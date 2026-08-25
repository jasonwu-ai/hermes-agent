"""Immutable decision ledger and exactly-once Kanban projector.

This module owns only the first connector in the verified pipeline:

* register exact specification bytes plus a frozen profile inventory;
* record one authenticated human decision against those exact bytes;
* atomically enqueue one immutable outbox record; and
* project that record to exactly one ordinary Kanban task.

It is deliberately not a scheduler or lifecycle state machine. Kanban remains
execution truth. The controller database retains decision truth and a replayable
receipt when the two durable stores cannot commit atomically.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from typing import Any, Callable, Iterator, Mapping, Optional

from hermes_cli.profiles import get_profile_dir
from hermes_cli.role_contract import RoleContractError, load_role_contract
from plugins.plugin_storage import plugin_data_dir


PLUGIN_NAME = "verified-pipeline"
SCHEMA_VERSION = 1
CONTROLLER_ID = "verified-pipeline/decision-outbox/v1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
PLANNER_PROFILE = "07-planner"
PLANNER_SKILL = "ordinary-planner-r3"
REVISION_PROFILE = "00-cos"
MANDATORY_IMPLEMENTATION_PROFILES = (
    "02-builder",
    "09-test",
    "06-integration",
    "08-release",
)
OPTIONAL_IMPLEMENTATION_PROFILES = ("10-validator",)
IMPLEMENTATION_PROFILES = (
    *MANDATORY_IMPLEMENTATION_PROFILES,
    *OPTIONAL_IMPLEMENTATION_PROFILES,
)
_KANBAN_STAGE_TOOLS = {
    "kanban_show", "kanban_comment", "kanban_attach", "kanban_attachments",
    "kanban_complete", "kanban_block", "kanban_heartbeat",
}
IMPLEMENTATION_ROLE_TOOL_CEILINGS = {
    "02-builder": _KANBAN_STAGE_TOOLS | {"read_file", "search_files", "write_file", "patch"},
    "09-test": _KANBAN_STAGE_TOOLS | {"read_file", "search_files", "write_file"},
    "06-integration": _KANBAN_STAGE_TOOLS | {"read_file", "search_files", "write_file", "patch"},
    "08-release": _KANBAN_STAGE_TOOLS | {"read_file", "search_files", "write_file"},
    "10-validator": _KANBAN_STAGE_TOOLS | {"read_file", "search_files"},
}
VALID_ACTIONS = frozenset({"approve", "request_changes"})
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^run_[0-9a-f]{24}$")


class PipelineControlError(RuntimeError):
    """Stable, non-secret controller error suitable for API responses."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ProjectionReceipt:
    idempotency_key: str
    decision_id: str
    status: str
    task_id: Optional[str]
    replayed: bool
    error_code: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _installed_implementation_contract(profile: str) -> dict[str, Any]:
    """Derive authority from the exact installed, hash-bound contract bytes."""
    try:
        contract = load_role_contract(get_profile_dir(profile), profile, required=True)
    except (FileNotFoundError, RoleContractError, ValueError) as exc:
        raise PipelineControlError(
            "IMPLEMENTATION_PROFILE_UNVERIFIABLE",
            f"{profile} installed role contract could not be verified",
        ) from exc
    if contract is None:  # pragma: no cover - required=True is fail-closed
        raise PipelineControlError(
            "IMPLEMENTATION_PROFILE_UNVERIFIABLE",
            f"{profile} installed role contract is missing",
        )
    return {
        "schema": contract.schema,
        "version": contract.version,
        "sha256": contract.sha256,
        "allowed_toolsets": list(contract.allowed_toolsets),
        "allowed_tools": list(contract.allowed_tools),
        "workspace_only": contract.workspace_only,
    }


def _default_db_path() -> Path:
    return plugin_data_dir(PLUGIN_NAME) / "pipeline-control.db"


def _default_workspace_root() -> Path:
    return plugin_data_dir(PLUGIN_NAME) / "workspaces"


def connect(db_path: Optional[str | os.PathLike[str]] = None) -> sqlite3.Connection:
    """Open the controller DB in explicit-transaction mode."""
    path = Path(db_path) if db_path is not None else _default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        path,
        timeout=30.0,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    for attempt in range(30):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 29:
                conn.close()
                raise
            time.sleep(min(0.01 * (attempt + 1), 0.1))
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _write_txn(conn: sqlite3.Connection) -> Iterator[None]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def init_db(db_path: Optional[str | os.PathLike[str]] = None) -> Path:
    """Create and verify the immutable controller schema."""
    path = Path(db_path) if db_path is not None else _default_db_path()
    conn = connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS pipeline_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                controller_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS intakes (
                run_id TEXT PRIMARY KEY,
                specification_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision > 0),
                artifact_bytes BLOB NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                decision_nonce TEXT NOT NULL UNIQUE,
                frozen_profiles_json TEXT NOT NULL,
                authority_ceiling_json TEXT NOT NULL,
                board TEXT,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'APPROVED', 'CHANGES_REQUESTED')),
                decision_id TEXT,
                UNIQUE (specification_id, revision)
            );

            CREATE TABLE IF NOT EXISTS decisions (
                decision_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL UNIQUE,
                request_sha256 TEXT NOT NULL,
                run_id TEXT NOT NULL UNIQUE REFERENCES intakes(run_id),
                action TEXT NOT NULL CHECK (action IN ('approve', 'request_changes')),
                actor TEXT NOT NULL,
                feedback TEXT,
                artifact_sha256 TEXT NOT NULL,
                decided_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbox (
                idempotency_key TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL UNIQUE REFERENCES decisions(decision_id),
                kind TEXT NOT NULL CHECK (kind IN ('planner_intake', 'specifier_revision')),
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'DELIVERED')),
                attempts INTEGER NOT NULL DEFAULT 0,
                task_id TEXT,
                delivered_at INTEGER,
                last_error_code TEXT
            );

            CREATE TRIGGER IF NOT EXISTS pipeline_identity_no_update
            BEFORE UPDATE ON pipeline_identity
            BEGIN SELECT RAISE(ABORT, 'pipeline identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS pipeline_identity_no_delete
            BEFORE DELETE ON pipeline_identity
            BEGIN SELECT RAISE(ABORT, 'pipeline identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS intakes_identity_no_update
            BEFORE UPDATE OF run_id, specification_id, revision, artifact_bytes,
                artifact_sha256, decision_nonce, frozen_profiles_json,
                authority_ceiling_json, board, created_at ON intakes
            BEGIN SELECT RAISE(ABORT, 'intake identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS intakes_no_delete
            BEFORE DELETE ON intakes
            BEGIN SELECT RAISE(ABORT, 'intakes are append-only'); END;

            CREATE TRIGGER IF NOT EXISTS decisions_no_update
            BEFORE UPDATE ON decisions
            BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;

            CREATE TRIGGER IF NOT EXISTS decisions_no_delete
            BEFORE DELETE ON decisions
            BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;

            CREATE TRIGGER IF NOT EXISTS outbox_payload_no_update
            BEFORE UPDATE OF idempotency_key, decision_id, kind, payload_json,
                created_at ON outbox
            BEGIN SELECT RAISE(ABORT, 'outbox identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS outbox_no_delete
            BEFORE DELETE ON outbox
            BEGIN SELECT RAISE(ABORT, 'outbox records are append-only'); END;
            """
        )
        with _write_txn(conn):
            conn.execute(
                "INSERT OR IGNORE INTO pipeline_identity "
                "(singleton, schema_version, controller_id, created_at) VALUES (1, ?, ?, ?)",
                (SCHEMA_VERSION, CONTROLLER_ID, _now()),
            )
        row = conn.execute(
            "SELECT schema_version, controller_id FROM pipeline_identity WHERE singleton = 1"
        ).fetchone()
        if row is None or row["schema_version"] != SCHEMA_VERSION or row["controller_id"] != CONTROLLER_ID:
            raise PipelineControlError(
                "PIPELINE_IDENTITY_MISMATCH",
                "controller database identity does not match this implementation",
            )
    finally:
        conn.close()
    return path


def _validate_frozen_profiles(value: Mapping[str, Mapping[str, Any]]) -> str:
    if not isinstance(value, Mapping) or not value:
        raise PipelineControlError("INVALID_PROFILE_INVENTORY", "frozen profile inventory is required")
    normalized: dict[str, dict[str, Any]] = {}
    for profile, receipt in value.items():
        name = str(profile).strip().lower()
        if not _ID_RE.fullmatch(name) or not isinstance(receipt, Mapping):
            raise PipelineControlError("INVALID_PROFILE_INVENTORY", "frozen profile inventory is malformed")
        digest = str(receipt.get("sha256") or "").strip().lower()
        schema = str(receipt.get("schema") or "").strip()
        version = str(receipt.get("version") or "").strip()
        if not _SHA256_RE.fullmatch(digest) or not schema or not version:
            raise PipelineControlError("INVALID_PROFILE_INVENTORY", "profile receipt is incomplete")
        normalized_receipt: dict[str, Any] = {
            "schema": schema,
            "version": version,
            "sha256": digest,
        }
        if name in IMPLEMENTATION_ROLE_TOOL_CEILINGS:
            allowed_toolsets = sorted(
                {str(item) for item in receipt.get("allowed_toolsets", [])}
            )
            allowed_tools = sorted({str(item) for item in receipt.get("allowed_tools", [])})
            if (
                not allowed_toolsets
                or not set(allowed_toolsets).issubset({"file", "kanban"})
                or not set(allowed_tools).issubset(IMPLEMENTATION_ROLE_TOOL_CEILINGS[name])
                or receipt.get("workspace_only") is not True
            ):
                raise PipelineControlError(
                    "IMPLEMENTATION_PROFILE_AUTHORITY_WIDENED",
                    f"{name} exceeds the verified implementation-role authority ceiling",
                )
            normalized_receipt.update(
                {
                    "allowed_toolsets": allowed_toolsets,
                    "allowed_tools": allowed_tools,
                    "workspace_only": True,
                }
            )
            if normalized_receipt != _installed_implementation_contract(name):
                raise PipelineControlError(
                    "IMPLEMENTATION_PROFILE_RECEIPT_MISMATCH",
                    f"{name} frozen authority does not match its exact installed contract bytes",
                )
        normalized[name] = normalized_receipt
    for required in (PLANNER_PROFILE,):
        if required not in normalized:
            raise PipelineControlError(
                "INVALID_PROFILE_INVENTORY",
                f"frozen profile inventory is missing {required}",
            )
    return _canonical_json(normalized)


def _validate_authority_ceiling(value: list[str] | tuple[str, ...]) -> str:
    normalized = sorted({str(item).strip() for item in value if str(item).strip()})
    allowed = {
        "plan",
        "revise_specification",
        "adversarial_review",
        "strategic_review",
    }
    if not normalized or not set(normalized).issubset(allowed):
        raise PipelineControlError(
            "INVALID_AUTHORITY_CEILING",
            "authority ceiling contains an unsupported verified-pipeline capability",
        )
    return _canonical_json(normalized)


def _intake_dict(row: sqlite3.Row, *, include_artifact: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "run_id": row["run_id"],
        "specification_id": row["specification_id"],
        "revision": row["revision"],
        "artifact_sha256": row["artifact_sha256"],
        "decision_nonce": row["decision_nonce"],
        "frozen_profiles": json.loads(row["frozen_profiles_json"]),
        "authority_ceiling": json.loads(row["authority_ceiling_json"]),
        "board": row["board"],
        "created_at": row["created_at"],
        "status": row["status"],
        "decision_id": row["decision_id"],
    }
    if include_artifact:
        result["artifact_bytes"] = bytes(row["artifact_bytes"])
    return result


def register_intake(
    *,
    specification_id: str,
    revision: int,
    artifact_bytes: bytes,
    frozen_profiles: Mapping[str, Mapping[str, Any]],
    authority_ceiling: list[str] | tuple[str, ...],
    board: Optional[str] = None,
    db_path: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    """Register exact review bytes and return their immutable decision binding."""
    specification_id = str(specification_id).strip()
    if not _ID_RE.fullmatch(specification_id):
        raise PipelineControlError("INVALID_SPECIFICATION_ID", "specification id is malformed")
    try:
        revision = int(revision)
    except (TypeError, ValueError) as exc:
        raise PipelineControlError("INVALID_REVISION", "revision must be a positive integer") from exc
    if revision <= 0:
        raise PipelineControlError("INVALID_REVISION", "revision must be a positive integer")
    if not isinstance(artifact_bytes, bytes) or not artifact_bytes:
        raise PipelineControlError("INVALID_ARTIFACT", "artifact must contain exact non-empty bytes")
    if len(artifact_bytes) > MAX_ARTIFACT_BYTES:
        raise PipelineControlError("INVALID_ARTIFACT", "artifact exceeds the controller size limit")
    try:
        artifact_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PipelineControlError("INVALID_ARTIFACT", "artifact must be strict UTF-8") from exc
    if "\x00" in artifact_bytes.decode("utf-8"):
        raise PipelineControlError("INVALID_ARTIFACT", "artifact must not contain NUL bytes")
    frozen_json = _validate_frozen_profiles(frozen_profiles)
    ceiling_json = _validate_authority_ceiling(authority_ceiling)
    board = str(board).strip() if board else None
    artifact_digest = _sha256(artifact_bytes)
    identity_basis = {
        "schema": CONTROLLER_ID,
        "specification_id": specification_id,
        "revision": revision,
        "artifact_sha256": artifact_digest,
        "frozen_profiles": json.loads(frozen_json),
        "authority_ceiling": json.loads(ceiling_json),
        "board": board,
    }
    run_id = "run_" + _sha256(_canonical_json(identity_basis).encode("utf-8"))[:24]
    init_db(db_path)
    conn = connect(db_path)
    try:
        existing = conn.execute("SELECT * FROM intakes WHERE run_id = ?", (run_id,)).fetchone()
        if existing is not None:
            return _intake_dict(existing, include_artifact=False)
        with _write_txn(conn):
            try:
                conn.execute(
                    """
                    INSERT INTO intakes (
                        run_id, specification_id, revision, artifact_bytes,
                        artifact_sha256, decision_nonce, frozen_profiles_json,
                        authority_ceiling_json, board, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        specification_id,
                        revision,
                        sqlite3.Binary(artifact_bytes),
                        artifact_digest,
                        secrets.token_urlsafe(24),
                        frozen_json,
                        ceiling_json,
                        board,
                        _now(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                row = conn.execute(
                    "SELECT run_id FROM intakes WHERE specification_id = ? AND revision = ?",
                    (specification_id, revision),
                ).fetchone()
                if row is not None:
                    if row["run_id"] != run_id:
                        raise PipelineControlError(
                            "REVISION_CONFLICT",
                            "this specification revision is already bound to different bytes",
                        ) from exc
                    replay = conn.execute(
                        "SELECT * FROM intakes WHERE run_id = ?", (run_id,)
                    ).fetchone()
                    assert replay is not None
                    return _intake_dict(replay, include_artifact=False)
                raise
        row = conn.execute("SELECT * FROM intakes WHERE run_id = ?", (run_id,)).fetchone()
        assert row is not None
        return _intake_dict(row, include_artifact=False)
    finally:
        conn.close()


def get_intake(
    run_id: str,
    *,
    include_artifact: bool = False,
    db_path: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    init_db(db_path)
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM intakes WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise PipelineControlError("INTAKE_NOT_FOUND", "pipeline intake was not found")
        return _intake_dict(row, include_artifact=include_artifact)
    finally:
        conn.close()


def record_decision(
    *,
    run_id: str,
    request_id: str,
    action: str,
    actor: str,
    decision_nonce: str,
    artifact_sha256: str,
    feedback: Optional[str] = None,
    db_path: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    """Atomically append one decision and one immutable outbox record."""
    request_id = str(request_id).strip()
    action = str(action).strip().lower()
    actor = str(actor).strip()
    feedback = str(feedback).strip() if feedback is not None else None
    if not _ID_RE.fullmatch(request_id):
        raise PipelineControlError("INVALID_REQUEST_ID", "request id is malformed")
    if action not in VALID_ACTIONS:
        raise PipelineControlError("INVALID_DECISION", "decision must be approve or request_changes")
    if not actor or len(actor) > 256:
        raise PipelineControlError("INVALID_ACTOR", "authenticated actor binding is missing")
    if action == "request_changes" and not feedback:
        raise PipelineControlError("FEEDBACK_REQUIRED", "request_changes requires feedback")
    if feedback and len(feedback.encode("utf-8")) > 64 * 1024:
        raise PipelineControlError("INVALID_FEEDBACK", "feedback exceeds the size limit")
    artifact_sha256 = str(artifact_sha256).strip().lower()
    request_basis = {
        "run_id": run_id,
        "request_id": request_id,
        "action": action,
        "actor": actor,
        "decision_nonce": decision_nonce,
        "artifact_sha256": artifact_sha256,
        "feedback": feedback,
    }
    request_sha = _sha256(_canonical_json(request_basis).encode("utf-8"))
    init_db(db_path)
    conn = connect(db_path)
    try:
        with _write_txn(conn):
            replay = conn.execute(
                "SELECT * FROM decisions WHERE request_id = ?", (request_id,)
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != request_sha:
                    raise PipelineControlError(
                        "REQUEST_ID_CONFLICT",
                        "request id was already used with different decision bytes",
                    )
                outbox = conn.execute(
                    "SELECT * FROM outbox WHERE decision_id = ?", (replay["decision_id"],)
                ).fetchone()
                assert outbox is not None
                return {
                    "decision_id": replay["decision_id"],
                    "idempotency_key": outbox["idempotency_key"],
                    "action": replay["action"],
                    "replayed": True,
                }

            intake = conn.execute("SELECT * FROM intakes WHERE run_id = ?", (run_id,)).fetchone()
            if intake is None:
                raise PipelineControlError("INTAKE_NOT_FOUND", "pipeline intake was not found")
            if intake["status"] != "PENDING":
                raise PipelineControlError("ALREADY_DECIDED", "pipeline intake already has a decision")
            if not secrets.compare_digest(str(decision_nonce), intake["decision_nonce"]):
                raise PipelineControlError("DECISION_BINDING_MISMATCH", "decision nonce does not match")
            if not _SHA256_RE.fullmatch(artifact_sha256) or not secrets.compare_digest(
                artifact_sha256, intake["artifact_sha256"]
            ):
                raise PipelineControlError(
                    "DECISION_BINDING_MISMATCH",
                    "decision artifact digest does not match the reviewed bytes",
                )

            decision_id = "decision_" + request_sha[:24]
            kind = "planner_intake" if action == "approve" else "specifier_revision"
            assignee = PLANNER_PROFILE if action == "approve" else REVISION_PROFILE
            required_authority = (
                "plan" if action == "approve" else "revise_specification"
            )
            frozen_profiles = json.loads(intake["frozen_profiles_json"])
            authority_ceiling = json.loads(intake["authority_ceiling_json"])
            if required_authority not in authority_ceiling or assignee not in frozen_profiles:
                raise PipelineControlError(
                    "DECISION_AUTHORITY_UNAVAILABLE",
                    f"{action} is not admitted by this intake's frozen authority",
                )
            idempotency_key = f"verified-pipeline:{decision_id}:{kind}"
            payload = {
                "schema": CONTROLLER_ID,
                "run_id": run_id,
                "decision_id": decision_id,
                "action": action,
                "specification_id": intake["specification_id"],
                "revision": intake["revision"],
                "artifact_sha256": intake["artifact_sha256"],
                "frozen_profiles": frozen_profiles,
                "authority_ceiling": authority_ceiling,
                "board": intake["board"],
                "assignee": assignee,
                "feedback": feedback,
            }
            now = _now()
            conn.execute(
                """
                INSERT INTO decisions (
                    decision_id, request_id, request_sha256, run_id, action,
                    actor, feedback, artifact_sha256, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    request_id,
                    request_sha,
                    run_id,
                    action,
                    actor,
                    feedback,
                    artifact_sha256,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO outbox (
                    idempotency_key, decision_id, kind, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (idempotency_key, decision_id, kind, _canonical_json(payload), now),
            )
            conn.execute(
                "UPDATE intakes SET status = ?, decision_id = ? WHERE run_id = ?",
                ("APPROVED" if action == "approve" else "CHANGES_REQUESTED", decision_id, run_id),
            )
        return {
            "decision_id": decision_id,
            "idempotency_key": idempotency_key,
            "action": action,
            "replayed": False,
        }
    finally:
        conn.close()


def _read_custodied_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise PipelineControlError(
            "ARTIFACT_CUSTODY_MISMATCH",
            "materialized specification is missing",
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PipelineControlError(
            "ARTIFACT_CUSTODY_MISMATCH",
            "materialized specification must be a regular file, not a symlink or device",
        )
    if metadata.st_mode & 0o022:
        raise PipelineControlError(
            "ARTIFACT_CUSTODY_MISMATCH",
            "materialized specification must not be group/world-writable",
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PipelineControlError(
            "ARTIFACT_CUSTODY_MISMATCH",
            "materialized specification could not be opened safely",
        ) from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise PipelineControlError(
                "ARTIFACT_CUSTODY_MISMATCH",
                "materialized specification changed type while opening",
            )
        if opened.st_mode & 0o022:
            raise PipelineControlError(
                "ARTIFACT_CUSTODY_MISMATCH",
                "materialized specification became group/world-writable while opening",
            )
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PipelineControlError(
                "ARTIFACT_CUSTODY_MISMATCH",
                "materialized specification changed while opening",
            )
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if len(raw) != opened.st_size:
        raise PipelineControlError(
            "ARTIFACT_CUSTODY_MISMATCH",
            "materialized specification changed while reading",
        )
    return raw


def _safe_workspace(
    *,
    workspace_root: Path,
    run_id: str,
    artifact_bytes: bytes,
    artifact_sha256: str,
) -> tuple[Path, Path]:
    if not _RUN_ID_RE.fullmatch(run_id):
        raise PipelineControlError("INVALID_RUN_ID", "stored run id is malformed")
    root = workspace_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace = root / run_id
    if workspace.is_symlink():
        raise PipelineControlError("WORKSPACE_ESCAPE", "workspace must not be a symlink")
    workspace.mkdir(mode=0o700, exist_ok=True)
    resolved = workspace.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PipelineControlError("WORKSPACE_ESCAPE", "workspace escaped the controlled root") from exc
    artifact_path = resolved / "specification.md"
    if artifact_path.exists() or artifact_path.is_symlink():
        existing = _read_custodied_file(artifact_path)
        if _sha256(existing) != artifact_sha256:
            raise PipelineControlError(
                "ARTIFACT_CUSTODY_MISMATCH",
                "materialized specification bytes do not match the decision",
            )
    else:
        tmp = resolved / f".specification.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(artifact_bytes)
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    os.link(tmp, artifact_path, follow_symlinks=False)
                except FileExistsError:
                    existing = _read_custodied_file(artifact_path)
                    if _sha256(existing) != artifact_sha256:
                        raise PipelineControlError(
                            "ARTIFACT_CUSTODY_MISMATCH",
                            "concurrent specification custody bytes do not match the decision",
                        )
            finally:
                if tmp.exists():
                    tmp.unlink()
        except BaseException:
            if tmp.exists():
                tmp.unlink()
            raise
    if _sha256(_read_custodied_file(artifact_path)) != artifact_sha256:
        raise PipelineControlError(
            "ARTIFACT_CUSTODY_MISMATCH",
            "artifact bytes changed during materialization",
        )
    return resolved, artifact_path


def _task_body(payload: Mapping[str, Any], artifact_path: Path) -> str:
    if payload["action"] == "approve":
        instruction = (
            "Produce a bounded implementation plan from the exact specification. "
            "Read `planner-request.json` and write only `plan.md` and `plan.json`. "
            "Complete only the current Planner card; the deterministic controller validates "
            "the exact terminal-run artifacts and writes `validation.md`. Do not create downstream tasks, "
            "dispatch workers, merge, deploy, or release."
        )
    else:
        instruction = (
            "Revise the specification using the exact reviewed bytes and human feedback. "
            "Do not approve, plan, create downstream tasks, dispatch workers, merge, deploy, or release."
        )
    feedback = payload.get("feedback") or "(none)"
    return (
        f"# Verified pipeline intake\n\n"
        f"{instruction}\n\n"
        f"- Run: `{payload['run_id']}`\n"
        f"- Decision: `{payload['decision_id']}`\n"
        f"- Specification: `{payload['specification_id']}` revision `{payload['revision']}`\n"
        f"- Exact artifact: `{artifact_path}`\n"
        f"- Artifact SHA-256: `{payload['artifact_sha256']}`\n"
        f"- Frozen profiles: `{_canonical_json(payload['frozen_profiles'])}`\n"
        f"- Authority ceiling: `{_canonical_json(payload['authority_ceiling'])}`\n"
        f"- Human feedback: {feedback}\n"
    )


def _mark_projection_error(
    db_path: Optional[str | os.PathLike[str]],
    idempotency_key: str,
    code: str,
) -> None:
    conn = connect(db_path)
    try:
        with _write_txn(conn):
            conn.execute(
                "UPDATE outbox SET attempts = attempts + 1, last_error_code = ? "
                "WHERE idempotency_key = ? AND status = 'PENDING'",
                (code, idempotency_key),
            )
    finally:
        conn.close()


def project_run(
    run_id: str,
    *,
    db_path: Optional[str | os.PathLike[str]] = None,
    kanban_db_path: Optional[str | os.PathLike[str]] = None,
    workspace_root: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    """Replay projection for a committed run without resubmitting its decision."""
    init_db(db_path)
    conn = connect(db_path)
    try:
        row = conn.execute(
            "SELECT o.idempotency_key FROM outbox o "
            "JOIN decisions d ON d.decision_id = o.decision_id WHERE d.run_id = ?",
            (run_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise PipelineControlError(
            "DECISION_NOT_FOUND",
            "pipeline intake has no committed decision to reconcile",
        )
    return project_outbox(
        row["idempotency_key"],
        db_path=db_path,
        kanban_db_path=kanban_db_path,
        workspace_root=workspace_root,
    )


def project_outbox(
    idempotency_key: str,
    *,
    db_path: Optional[str | os.PathLike[str]] = None,
    kanban_db_path: Optional[str | os.PathLike[str]] = None,
    workspace_root: Optional[str | os.PathLike[str]] = None,
    _after_task_created: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    """Project one immutable outbox record to exactly one Kanban task.

    If Kanban is unavailable, decision truth remains committed and the receipt
    remains PENDING. Replaying this function is the recovery path. The outer
    Kanban write transaction serializes lookup plus insertion, closing the
    public create_task helper's documented concurrent-idempotency race.
    """
    init_db(db_path)
    control = connect(db_path)
    try:
        row = control.execute(
            "SELECT * FROM outbox WHERE idempotency_key = ?", (idempotency_key,)
        ).fetchone()
        if row is None:
            raise PipelineControlError("OUTBOX_NOT_FOUND", "outbox record was not found")
        if row["status"] == "DELIVERED":
            return ProjectionReceipt(
                idempotency_key=idempotency_key,
                decision_id=row["decision_id"],
                status="DELIVERED",
                task_id=row["task_id"],
                replayed=True,
            ).as_dict()
        if row["kind"] not in {"planner_intake", "specifier_revision"}:
            raise PipelineControlError("UNKNOWN_OUTBOX_KIND", "outbox kind is not supported")
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise PipelineControlError("INVALID_OUTBOX_PAYLOAD", "outbox payload is malformed") from exc
        expected = {
            "planner_intake": ("approve", PLANNER_PROFILE),
            "specifier_revision": ("request_changes", REVISION_PROFILE),
        }[row["kind"]]
        if (
            payload.get("schema") != CONTROLLER_ID
            or payload.get("decision_id") != row["decision_id"]
            or payload.get("action") != expected[0]
            or payload.get("assignee") != expected[1]
        ):
            raise PipelineControlError(
                "OUTBOX_AUTHORITY_MISMATCH",
                "outbox payload does not match its bounded connector authority",
            )
        intake = control.execute(
            "SELECT artifact_bytes, artifact_sha256, frozen_profiles_json, "
            "authority_ceiling_json, board FROM intakes WHERE run_id = ?",
            (payload.get("run_id"),),
        ).fetchone()
        if intake is None:
            raise PipelineControlError("INTAKE_NOT_FOUND", "outbox intake was not found")
        artifact_bytes = bytes(intake["artifact_bytes"])
        if (
            _sha256(artifact_bytes) != intake["artifact_sha256"]
            or intake["artifact_sha256"] != payload.get("artifact_sha256")
            or json.loads(intake["frozen_profiles_json"]) != payload.get("frozen_profiles")
            or json.loads(intake["authority_ceiling_json"]) != payload.get("authority_ceiling")
            or intake["board"] != payload.get("board")
        ):
            raise PipelineControlError(
                "ARTIFACT_CUSTODY_MISMATCH",
                "canonical artifact bytes no longer match the decision receipt",
            )
        root = Path(workspace_root) if workspace_root is not None else _default_workspace_root()
        workspace, artifact_path = _safe_workspace(
            workspace_root=root,
            run_id=payload["run_id"],
            artifact_bytes=artifact_bytes,
            artifact_sha256=payload["artifact_sha256"],
        )
        if payload["action"] == "approve":
            from plugins.verified_pipeline import review

            review.prepare_initial_planner_workspace(
                workspace=workspace,
                artifact_path=artifact_path,
                payload=payload,
            )
    finally:
        control.close()

    try:
        from hermes_cli import kanban_db

        kanban_path = Path(kanban_db_path) if kanban_db_path is not None else None
        kanban_db.init_db(db_path=kanban_path, board=payload.get("board") if kanban_path is None else None)
        kconn = kanban_db.connect(
            db_path=kanban_path,
            board=payload.get("board") if kanban_path is None else None,
        )
        try:
            with kanban_db.write_txn(kconn):
                existing_rows = kconn.execute(
                    "SELECT id FROM tasks WHERE idempotency_key = ? ORDER BY created_at, id",
                    (idempotency_key,),
                ).fetchall()
                if len(existing_rows) > 1:
                    raise PipelineControlError(
                        "DUPLICATE_SUCCESSOR",
                        "more than one Kanban task already carries this outbox identity",
                    )
                if existing_rows:
                    task_id = existing_rows[0]["id"]
                else:
                    task_id = kanban_db.create_task(
                        kconn,
                        title=(
                            f"Plan {payload['specification_id']} r{payload['revision']}"
                            if payload["action"] == "approve"
                            else f"Revise {payload['specification_id']} r{payload['revision']}"
                        ),
                        body=_task_body(payload, artifact_path),
                        assignee=expected[1],
                        created_by="verified-pipeline-controller",
                        workspace_kind="dir",
                        workspace_path=str(workspace),
                        idempotency_key=idempotency_key,
                        max_runtime_seconds=3600,
                        max_retries=0,
                        skills=[PLANNER_SKILL],
                        require_role_contract=True,
                        expected_role_contract_sha256=payload["frozen_profiles"][expected[1]]["sha256"],
                    )
            if _after_task_created is not None:
                _after_task_created(task_id)
        finally:
            kconn.close()
    except PipelineControlError:
        raise
    except (OSError, sqlite3.Error) as exc:
        _mark_projection_error(db_path, idempotency_key, "KANBAN_UNAVAILABLE")
        return ProjectionReceipt(
            idempotency_key=idempotency_key,
            decision_id=row["decision_id"],
            status="PENDING",
            task_id=None,
            replayed=False,
            error_code="KANBAN_UNAVAILABLE",
        ).as_dict()
    except (ValueError, RuntimeError):
        _mark_projection_error(db_path, idempotency_key, "TASK_PROJECTION_FAILED")
        return ProjectionReceipt(
            idempotency_key=idempotency_key,
            decision_id=row["decision_id"],
            status="PENDING",
            task_id=None,
            replayed=False,
            error_code="TASK_PROJECTION_FAILED",
        ).as_dict()

    control = connect(db_path)
    try:
        with _write_txn(control):
            control.execute(
                "UPDATE outbox SET status = 'DELIVERED', task_id = ?, delivered_at = ?, "
                "attempts = attempts + 1, last_error_code = NULL "
                "WHERE idempotency_key = ? AND status = 'PENDING'",
                (task_id, _now(), idempotency_key),
            )
        delivered = control.execute(
            "SELECT status, task_id FROM outbox WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        assert delivered is not None
        return ProjectionReceipt(
            idempotency_key=idempotency_key,
            decision_id=row["decision_id"],
            status=delivered["status"],
            task_id=delivered["task_id"],
            replayed=False,
        ).as_dict()
    finally:
        control.close()
