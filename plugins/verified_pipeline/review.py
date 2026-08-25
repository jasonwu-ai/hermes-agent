"""Automatic Planner → DA → CEO review reconciliation for verified-pipeline.

This module extends the immutable decision connector without creating a second
execution lifecycle. Kanban remains task truth. The controller database stores
only immutable typed stage transitions and a replayable successor outbox.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Any, Callable, Mapping, Optional

from plugins.verified_pipeline import validators

REVIEW_CONTROLLER_ID = "verified-pipeline/automatic-plan-review/v1"
DA_PROFILE = "11-devils-advocate"
CEO_PROFILE = "01-ceo"
DA_SKILL = "premortem-r3"
CEO_SKILL = "ceo-decision-r3"
MAX_PLAN_REVISION = 3
REVIEW_KINDS = frozenset({"planner_revision", "da_review", "ceo_review"})
_WORKSPACE_RE = re.compile(r"^review_[0-9a-f]{24}$")


class ReviewCoordinationError(RuntimeError):
    """Stable fail-closed error for automatic review coordination."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _controller():
    from plugins.verified_pipeline import controller

    return controller


def _now() -> int:
    return _controller()._now()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_bytes(value: Any) -> bytes:
    return (_canonical(value) + "\n").encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _workspace_name(run_id: str, kind: str, revision: int) -> str:
    basis = f"{REVIEW_CONTROLLER_ID}\n{run_id}\n{kind}\n{revision}".encode("utf-8")
    return "review_" + _digest(basis)[:24]


def init_review_schema(db_path: Optional[str | os.PathLike[str]] = None) -> Path:
    controller = _controller()
    path = controller.init_db(db_path)
    conn = controller.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS review_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                controller_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS review_transitions (
                transition_key TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES intakes(run_id),
                source_task_id TEXT NOT NULL UNIQUE,
                stage TEXT NOT NULL CHECK (stage IN ('planner', 'da', 'ceo')),
                plan_revision INTEGER NOT NULL CHECK (plan_revision BETWEEN 1 AND 3),
                outcome TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS review_outbox (
                idempotency_key TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES intakes(run_id),
                kind TEXT NOT NULL
                    CHECK (kind IN ('planner_revision', 'da_review', 'ceo_review')),
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'DELIVERED')),
                attempts INTEGER NOT NULL DEFAULT 0,
                task_id TEXT,
                delivered_at INTEGER,
                last_error_code TEXT
            );

            CREATE TRIGGER IF NOT EXISTS review_identity_no_update
            BEFORE UPDATE ON review_identity
            BEGIN SELECT RAISE(ABORT, 'review identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS review_identity_no_delete
            BEFORE DELETE ON review_identity
            BEGIN SELECT RAISE(ABORT, 'review identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS review_transitions_no_update
            BEFORE UPDATE ON review_transitions
            BEGIN SELECT RAISE(ABORT, 'review transitions are immutable'); END;

            CREATE TRIGGER IF NOT EXISTS review_transitions_no_delete
            BEFORE DELETE ON review_transitions
            BEGIN SELECT RAISE(ABORT, 'review transitions are append-only'); END;

            CREATE TRIGGER IF NOT EXISTS review_outbox_payload_no_update
            BEFORE UPDATE OF idempotency_key, run_id, kind, payload_json, created_at
            ON review_outbox
            BEGIN SELECT RAISE(ABORT, 'review outbox identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS review_outbox_no_delete
            BEFORE DELETE ON review_outbox
            BEGIN SELECT RAISE(ABORT, 'review outbox is append-only'); END;
            """
        )
        with controller._write_txn(conn):
            conn.execute(
                "INSERT OR IGNORE INTO review_identity "
                "(singleton, controller_id, created_at) VALUES (1, ?, ?)",
                (REVIEW_CONTROLLER_ID, _now()),
            )
        identity = conn.execute(
            "SELECT controller_id FROM review_identity WHERE singleton = 1"
        ).fetchone()
        if identity is None or identity["controller_id"] != REVIEW_CONTROLLER_ID:
            raise ReviewCoordinationError(
                "REVIEW_IDENTITY_MISMATCH",
                "review database identity does not match this implementation",
            )
    finally:
        conn.close()
    return path


def _intake(run_id: str, db_path: Optional[str | os.PathLike[str]]) -> dict[str, Any]:
    controller = _controller()
    intake = controller.get_intake(run_id, include_artifact=True, db_path=db_path)
    required = {
        controller.PLANNER_PROFILE,
        DA_PROFILE,
        CEO_PROFILE,
    }
    missing = sorted(required - set(intake["frozen_profiles"]))
    if missing:
        raise ReviewCoordinationError(
            "REVIEW_PROFILE_INVENTORY_INCOMPLETE",
            f"review profile inventory is missing: {missing}",
        )
    required_authority = {"plan", "adversarial_review", "strategic_review"}
    missing_authority = sorted(required_authority - set(intake["authority_ceiling"]))
    if missing_authority:
        raise ReviewCoordinationError(
            "REVIEW_AUTHORITY_CEILING_INCOMPLETE",
            f"review authority ceiling is missing: {missing_authority}",
        )
    return intake


def _safe_file(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReviewCoordinationError("REVIEW_ARTIFACT_MISSING", f"{label} is missing") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            f"{label} must be a regular file, not a symlink or device",
        )
    if metadata.st_mode & 0o022:
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            f"{label} must not be group/world-writable",
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            f"{label} could not be opened safely",
        ) from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ReviewCoordinationError(
                "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
                f"{label} changed type while opening",
            )
        if opened.st_mode & 0o022:
            raise ReviewCoordinationError(
                "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
                f"{label} became group/world-writable while opening",
            )
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ReviewCoordinationError(
                "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
                f"{label} changed while opening",
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
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            f"{label} changed while reading",
        )
    return raw


def _write_exact(path: Path, raw: bytes, label: str) -> None:
    if path.exists() or path.is_symlink():
        if _safe_file(path, label) != raw:
            raise ReviewCoordinationError(
                "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
                f"existing {label} bytes do not match the authoritative request",
            )
        return
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # Install only if absent. Unlike os.replace(), this never swaps the
            # inode beneath a concurrent custody reader.
            os.link(tmp, path, follow_symlinks=False)
        except FileExistsError:
            pass
    finally:
        if tmp.exists():
            tmp.unlink()
    if _safe_file(path, label) != raw:
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            f"{label} bytes changed during materialization",
        )


def _workspace(
    workspace_root: Path,
    *,
    name: str,
    create: bool,
) -> Path:
    if not _WORKSPACE_RE.fullmatch(name):
        raise ReviewCoordinationError("REVIEW_WORKSPACE_INVALID", "review workspace identity is malformed")
    root = workspace_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / name
    if path.is_symlink():
        raise ReviewCoordinationError("REVIEW_WORKSPACE_DRIFT", "review workspace is a symlink")
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    if not path.exists():
        raise ReviewCoordinationError("REVIEW_WORKSPACE_MISSING", "review workspace is missing")
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ReviewCoordinationError("REVIEW_WORKSPACE_DRIFT", "review workspace escaped its root") from exc
    return resolved


def _initial_planner_request(
    *,
    run_id: str,
    intake: Mapping[str, Any],
    workspace: Path,
) -> dict[str, Any]:
    return {
        "schema": "planner-request/v1",
        "run_id": run_id,
        "specification_id": intake["specification_id"],
        "specification_sha256": intake["artifact_sha256"],
        "plan_revision": 1,
        "output_workspace": str(workspace),
        "prior_findings": "none",
    }


def prepare_initial_planner_workspace(
    *,
    workspace: Path,
    artifact_path: Path,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Project the task-local typed Planner request before initial task creation."""
    intake = {
        "specification_id": payload["specification_id"],
        "artifact_sha256": payload["artifact_sha256"],
    }
    request = _initial_planner_request(
        run_id=payload["run_id"],
        intake=intake,
        workspace=workspace,
    )
    validators.validate_plan_request(request)
    if _digest(_safe_file(artifact_path, "specification")) != request["specification_sha256"]:
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            "Planner request does not match specification bytes",
        )
    _write_exact(workspace / "planner-request.json", _canonical_bytes(request), "Planner request")
    return request


def _review_payload(
    *,
    run_id: str,
    kind: str,
    revision: int,
    source_task_id: str,
    request: Mapping[str, Any],
    frozen_profiles: Mapping[str, Any],
    extra: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    controller = _controller()
    assignee = {
        "planner_revision": controller.PLANNER_PROFILE,
        "da_review": DA_PROFILE,
        "ceo_review": CEO_PROFILE,
    }[kind]
    payload: dict[str, Any] = {
        "schema": REVIEW_CONTROLLER_ID,
        "run_id": run_id,
        "kind": kind,
        "source_task_id": source_task_id,
        "plan_revision": revision,
        "assignee": assignee,
        "workspace_name": _workspace_name(run_id, kind, revision),
        "frozen_profiles": frozen_profiles,
        "request": dict(request),
    }
    if extra:
        payload.update(extra)
    return payload


def _insert_review_outbox(
    conn: sqlite3.Connection,
    *,
    idempotency_key: str,
    payload: Mapping[str, Any],
) -> None:
    conn.execute(
        "INSERT INTO review_outbox "
        "(idempotency_key, run_id, kind, payload_json, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            idempotency_key,
            payload["run_id"],
            payload["kind"],
            _canonical(payload),
            _now(),
        ),
    )


def _insert_transition(
    conn: sqlite3.Connection,
    *,
    key: str,
    run_id: str,
    task_id: str,
    stage: str,
    revision: int,
    outcome: str,
    payload: Mapping[str, Any],
) -> None:
    conn.execute(
        "INSERT INTO review_transitions "
        "(transition_key, run_id, source_task_id, stage, plan_revision, outcome, "
        "payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (key, run_id, task_id, stage, revision, outcome, _canonical(payload), _now()),
    )


def _load_json_file(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _safe_file(path, label)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise validators.ArtifactValidationError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise validators.ArtifactValidationError(f"{label} must contain an object")
    return value, raw


def _planner_revision_request(
    *,
    run_id: str,
    intake: Mapping[str, Any],
    revision: int,
    workspace: Path,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "planner-request/v1",
        "run_id": run_id,
        "specification_id": intake["specification_id"],
        "specification_sha256": intake["artifact_sha256"],
        "plan_revision": revision,
        "output_workspace": str(workspace),
        "prior_findings": findings,
    }


def _finding(identifier: str, summary: str) -> dict[str, Any]:
    return {"id": identifier, "classification": "blocking", "summary": summary}


def _authoritative_stage_payload(
    *,
    run_id: str,
    task_id: str,
    kind: str,
    db_path: Optional[str | os.PathLike[str]],
) -> dict[str, Any]:
    controller = _controller()
    conn = controller.connect(db_path)
    try:
        if kind == "planner_intake":
            row = conn.execute(
                "SELECT payload_json FROM outbox WHERE task_id = ? AND kind = ? "
                "AND status = 'DELIVERED'",
                (task_id, kind),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT payload_json FROM review_outbox WHERE task_id = ? AND kind = ? "
                "AND status = 'DELIVERED'",
                (task_id, kind),
            ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ReviewCoordinationError(
            "REVIEW_REQUEST_NOT_FOUND",
            "terminal task has no delivered authoritative stage request",
        )
    payload = json.loads(row["payload_json"])
    if payload.get("run_id") != run_id:
        raise ReviewCoordinationError("REVIEW_REQUEST_DRIFT", "stage request run identity drifted")
    return payload


def _kanban_connection(
    kanban_db_path: Optional[str | os.PathLike[str]],
    board_name: Optional[str],
):
    from hermes_cli import kanban_db

    explicit_path = Path(kanban_db_path) if kanban_db_path else None
    return kanban_db.connect(
        db_path=explicit_path,
        board=board_name if explicit_path is None else None,
    )


def _verify_task(
    *,
    task_id: str,
    expected_assignee: str,
    expected_workspace: Path,
    allowed_statuses: set[str],
    kanban_db_path: Optional[str | os.PathLike[str]],
    board_name: Optional[str],
):
    from hermes_cli import kanban_db

    conn = _kanban_connection(kanban_db_path, board_name)
    try:
        task = kanban_db.get_task(conn, task_id)
    finally:
        conn.close()
    if task is None:
        raise ReviewCoordinationError("REVIEW_TASK_MISSING", "delivered review task is missing")
    if task.assignee != expected_assignee or task.status not in allowed_statuses:
        raise ReviewCoordinationError(
            "REVIEW_TASK_IDENTITY_MISMATCH",
            "terminal task does not match the admitted review stage",
        )
    if not task.workspace_path or Path(task.workspace_path).resolve() != expected_workspace:
        raise ReviewCoordinationError(
            "REVIEW_WORKSPACE_DRIFT",
            "task workspace drifted after review projection",
        )
    return task


def _verify_terminal_run(
    *,
    task_id: str,
    expected_assignee: str,
    expected_workspace: Path,
    expected_contract: Mapping[str, Any],
    terminal_status: str,
    kanban_db_path: Optional[str | os.PathLike[str]],
    board_name: Optional[str],
) -> dict[str, Any]:
    event_kind = "completed" if terminal_status == "done" else "blocked"
    expected_outcome = "completed" if terminal_status == "done" else "blocked"
    conn = _kanban_connection(kanban_db_path, board_name)
    try:
        events = conn.execute(
            "SELECT run_id, payload FROM task_events WHERE task_id = ? AND kind = ? "
            "ORDER BY id DESC LIMIT 2",
            (task_id, event_kind),
        ).fetchall()
        if len(events) != 1 or events[0]["run_id"] is None:
            raise ReviewCoordinationError(
                "REVIEW_RUN_RECEIPT_MISSING",
                "governance task has no unambiguous terminal run receipt",
            )
        run_id = int(events[0]["run_id"])
        run = conn.execute(
            "SELECT profile, status, outcome, ended_at, metadata FROM task_runs "
            "WHERE id = ? AND task_id = ?",
            (run_id, task_id),
        ).fetchone()
        admitted_events = conn.execute(
            "SELECT payload FROM task_events WHERE task_id = ? AND run_id = ? "
            "AND kind = 'role_contract_admitted' ORDER BY id",
            (task_id, run_id),
        ).fetchall()
        task_custody = conn.execute(
            "SELECT workspace_path, branch_name FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
    finally:
        conn.close()
    if (
        run is None
        or run["profile"] != expected_assignee
        or run["status"] != terminal_status
        or run["outcome"] != expected_outcome
        or run["ended_at"] is None
    ):
        raise ReviewCoordinationError(
            "REVIEW_RUN_IDENTITY_MISMATCH",
            "terminal run does not match the admitted governance stage",
        )
    try:
        metadata = json.loads(run["metadata"] or "{}")
        receipt = metadata["role_contract_admission"]
        admitted_receipt = json.loads(admitted_events[0]["payload"])
        basis = {
            "schema": receipt["schema"],
            "profile": receipt["profile"],
            "version": receipt["version"],
            "contract_sha256": receipt["contract_sha256"],
            "configured_toolsets": receipt["configured_toolsets"],
            "allowed_toolsets": receipt["allowed_toolsets"],
            "allowed_tools": receipt["allowed_tools"],
            "workspace_only": receipt["workspace_only"],
            "mandatory_toolsets": receipt["mandatory_toolsets"],
            "effective_toolsets": receipt["effective_toolsets"],
            "task_id": receipt["task_id"],
            "run_id": receipt["run_id"],
            "workspace_path": receipt["workspace_path"],
            "branch_name": receipt["branch_name"],
        }
        computed_receipt_id = hashlib.sha256(
            json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ReviewCoordinationError(
            "REVIEW_RUN_RECEIPT_INVALID",
            "terminal run admission receipt is missing or malformed",
        ) from exc
    expected_workspace_text = str(expected_workspace)
    if (
        len(admitted_events) != 1
        or admitted_receipt != receipt
        or receipt.get("receipt_id") != computed_receipt_id
        or receipt.get("task_id") != task_id
        or receipt.get("run_id") != run_id
        or receipt.get("profile") != expected_assignee
        or receipt.get("workspace_path") != expected_workspace_text
        or task_custody is None
        or receipt.get("workspace_path") != task_custody["workspace_path"]
        or receipt.get("branch_name") != task_custody["branch_name"]
        or receipt.get("schema") != expected_contract.get("schema")
        or receipt.get("version") != expected_contract.get("version")
        or receipt.get("contract_sha256") != expected_contract.get("sha256")
    ):
        raise ReviewCoordinationError(
            "REVIEW_RUN_RECEIPT_MISMATCH",
            "terminal run admission receipt does not match the frozen governance identity",
        )
    return receipt


def submit_planner_completion(
    *,
    run_id: str,
    task_id: str,
    kind: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: Optional[str | os.PathLike[str]],
    workspace_root: Path,
) -> dict[str, Any]:
    controller = _controller()
    intake = _intake(run_id, db_path)
    source = _authoritative_stage_payload(
        run_id=run_id,
        task_id=task_id,
        kind=kind,
        db_path=db_path,
    )
    revision = 1 if kind == "planner_intake" else int(source["plan_revision"])
    expected = (
        (workspace_root / run_id).resolve()
        if kind == "planner_intake"
        else _workspace(
            workspace_root,
            name=source["workspace_name"],
            create=False,
        )
    )
    task = _verify_task(
        task_id=task_id,
        expected_assignee=controller.PLANNER_PROFILE,
        expected_workspace=expected,
        allowed_statuses={"done"},
        kanban_db_path=kanban_db_path,
        board_name=intake["board"],
    )
    _verify_terminal_run(
        task_id=task_id,
        expected_assignee=controller.PLANNER_PROFILE,
        expected_workspace=expected,
        expected_contract=intake["frozen_profiles"][controller.PLANNER_PROFILE],
        terminal_status=task.status,
        kanban_db_path=kanban_db_path,
        board_name=intake["board"],
    )
    request = (
        _initial_planner_request(run_id=run_id, intake=intake, workspace=expected)
        if kind == "planner_intake"
        else source["request"]
    )
    request_bytes = _safe_file(expected / "planner-request.json", "Planner request")
    if request_bytes != _canonical_bytes(request):
        raise ReviewCoordinationError("REVIEW_REQUEST_DRIFT", "Planner request bytes drifted")
    specification = _safe_file(expected / "specification.md", "specification")
    if specification != intake["artifact_bytes"]:
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            "Planner specification bytes do not match the human-approved intake",
        )
    plan_md = _safe_file(expected / "plan.md", "plan.md")
    if not plan_md.strip():
        raise validators.ArtifactValidationError("plan.md must not be empty")
    findings: Optional[str] = None
    plan: Optional[dict[str, Any]] = None
    plan_raw = b""
    try:
        plan, plan_raw = _load_json_file(expected / "plan.json", "plan.json")
        validators.validate_plan(plan, request=request)
        expected_receipt = f"VALID: {_digest(_canonical_bytes(plan))}\n".encode("utf-8")
        _write_exact(expected / "validation.md", expected_receipt, "validation.md")
    except validators.ArtifactValidationError as exc:
        findings = str(exc)
    key = f"planner-completion:{task_id}"
    init_review_schema(db_path)
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            existing = conn.execute(
                "SELECT payload_json FROM review_transitions WHERE transition_key = ?",
                (key,),
            ).fetchone()
            if existing is not None:
                return json.loads(existing["payload_json"])
            if findings is not None:
                if revision >= MAX_PLAN_REVISION:
                    outcome = "PLANNER_INVALID_FINAL_ROUND"
                    result = {
                        "status": "JASON_DECISION_REQUIRED",
                        "run_id": run_id,
                        "plan_revision": revision,
                        "findings": findings,
                        "source_task_id": task_id,
                    }
                else:
                    next_revision = revision + 1
                    review_findings = [_finding("planner-structural", findings)]
                    workspace_name = _workspace_name(
                        run_id, "planner_revision", next_revision
                    )
                    request_workspace = _workspace(
                        workspace_root,
                        name=workspace_name,
                        create=True,
                    )
                    next_request = _planner_revision_request(
                        run_id=run_id,
                        intake=intake,
                        revision=next_revision,
                        workspace=request_workspace,
                        findings=review_findings,
                    )
                    payload = _review_payload(
                        run_id=run_id,
                        kind="planner_revision",
                        revision=next_revision,
                        source_task_id=task_id,
                        request=next_request,
                        frozen_profiles=intake["frozen_profiles"],
                        extra={
                            "findings": review_findings,
                            "previous_plan_md": plan_md.decode("utf-8"),
                            "previous_plan_json": plan_raw.decode("utf-8", errors="replace"),
                        },
                    )
                    _insert_review_outbox(
                        conn,
                        idempotency_key=(
                            f"verified-pipeline:{run_id}:planner-revision:{next_revision}"
                        ),
                        payload=payload,
                    )
                    outcome = "PLANNER_REVISION_QUEUED"
                    result = {
                        "status": outcome,
                        "run_id": run_id,
                        "plan_revision": revision,
                        "next_revision": next_revision,
                        "findings": review_findings,
                        "source_task_id": task_id,
                    }
            else:
                assert plan is not None
                workspace_name = _workspace_name(run_id, "da_review", revision)
                da_workspace = _workspace(
                    workspace_root,
                    name=workspace_name,
                    create=True,
                )
                da_request = {
                    "schema": validators.DA_REQUEST_SCHEMA,
                    "run_id": run_id,
                    "specification_id": intake["specification_id"],
                    "specification": specification.decode("utf-8"),
                    "specification_path": str(expected / "specification.md"),
                    "specification_sha256": intake["artifact_sha256"],
                    "plan_md": plan_md.decode("utf-8"),
                    "plan": plan,
                    "plan_sha256": _digest(_canonical_bytes(plan)),
                    "plan_revision": revision,
                    "review_round": revision,
                    "prior_findings": request["prior_findings"],
                    "risk_policy": dict(validators.DEFAULT_RISK_POLICY),
                    "minimum_standard": (
                        "PASS requires zero unresolved blockers and zero unresolved "
                        "severe findings with likelihood × impact >= 12."
                    ),
                    "output_workspace": str(da_workspace),
                }
                validators.validate_da_request(da_request)
                payload = _review_payload(
                    run_id=run_id,
                    kind="da_review",
                    revision=revision,
                    source_task_id=task_id,
                    request=da_request,
                    frozen_profiles=intake["frozen_profiles"],
                )
                _insert_review_outbox(
                    conn,
                    idempotency_key=f"verified-pipeline:{run_id}:da-review:{revision}",
                    payload=payload,
                )
                outcome = "DA_REVIEW_QUEUED"
                result = {
                    "status": outcome,
                    "run_id": run_id,
                    "plan_revision": revision,
                    "source_task_id": task_id,
                }
            _insert_transition(
                conn,
                key=key,
                run_id=run_id,
                task_id=task.id,
                stage="planner",
                revision=revision,
                outcome=outcome,
                payload=result,
            )
            return result
    finally:
        conn.close()


def submit_da_completion(
    *,
    run_id: str,
    task_id: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: Optional[str | os.PathLike[str]],
    workspace_root: Path,
) -> dict[str, Any]:
    controller = _controller()
    intake = _intake(run_id, db_path)
    source = _authoritative_stage_payload(
        run_id=run_id,
        task_id=task_id,
        kind="da_review",
        db_path=db_path,
    )
    revision = int(source["plan_revision"])
    workspace = _workspace(
        workspace_root,
        name=source["workspace_name"],
        create=False,
    )
    task = _verify_task(
        task_id=task_id,
        expected_assignee=DA_PROFILE,
        expected_workspace=workspace,
        allowed_statuses={"done", "blocked", "triage"},
        kanban_db_path=kanban_db_path,
        board_name=intake["board"],
    )
    _verify_terminal_run(
        task_id=task_id,
        expected_assignee=DA_PROFILE,
        expected_workspace=workspace,
        expected_contract=intake["frozen_profiles"][DA_PROFILE],
        terminal_status=task.status,
        kanban_db_path=kanban_db_path,
        board_name=intake["board"],
    )
    request = source["request"]
    validators.validate_da_request(request)
    if _safe_file(workspace / "da-request.json", "DA request") != _canonical_bytes(request):
        raise ReviewCoordinationError("REVIEW_REQUEST_DRIFT", "DA request bytes drifted")
    specification = _safe_file(Path(request["specification_path"]), "specification")
    if specification != intake["artifact_bytes"]:
        raise ReviewCoordinationError(
            "REVIEW_ARTIFACT_CUSTODY_MISMATCH",
            "DA specification bytes do not match the approved intake",
        )
    verdict, _ = _load_json_file(workspace / "verdict.json", "verdict.json")
    validators.validate_da_verdict(verdict, request=request)
    premortem = _safe_file(workspace / "premortem.md", "premortem.md")
    if not premortem.strip():
        raise validators.ArtifactValidationError("premortem.md must not be empty")
    if verdict["verdict"] == "PASS" and task.status != "done":
        raise ReviewCoordinationError(
            "REVIEW_TASK_IDENTITY_MISMATCH",
            "DA PASS requires a completed task",
        )
    key = f"da-completion:{task_id}"
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            existing = conn.execute(
                "SELECT payload_json FROM review_transitions WHERE transition_key = ?",
                (key,),
            ).fetchone()
            if existing is not None:
                return json.loads(existing["payload_json"])
            if verdict["verdict"] == "PASS":
                workspace_name = _workspace_name(run_id, "ceo_review", revision)
                ceo_workspace = _workspace(
                    workspace_root,
                    name=workspace_name,
                    create=True,
                )
                ceo_request = {
                    "schema": validators.CEO_REQUEST_SCHEMA,
                    "run_id": run_id,
                    "specification_id": intake["specification_id"],
                    "plan_revision": revision,
                    "specification": request["specification"],
                    "specification_path": request["specification_path"],
                    "specification_sha256": intake["artifact_sha256"],
                    "plan_md": request["plan_md"],
                    "plan": request["plan"],
                    "plan_sha256": request["plan_sha256"],
                    "premortem_md": premortem.decode("utf-8"),
                    "da_verdict": verdict,
                    "da_verdict_sha256": _digest(_canonical_bytes(verdict)),
                    "authority_scope": {
                        "exact_specification_only": True,
                        "stops_at": "CEO_APPROVED_PENDING_MATERIALIZATION",
                        "material_scope_or_risk_change_requires_jason": True,
                    },
                    "output_workspace": str(ceo_workspace),
                }
                validators.validate_ceo_request(ceo_request)
                payload = _review_payload(
                    run_id=run_id,
                    kind="ceo_review",
                    revision=revision,
                    source_task_id=task_id,
                    request=ceo_request,
                    frozen_profiles=intake["frozen_profiles"],
                )
                _insert_review_outbox(
                    conn,
                    idempotency_key=f"verified-pipeline:{run_id}:ceo-review:{revision}",
                    payload=payload,
                )
                outcome = "CEO_REVIEW_QUEUED"
                result = {
                    "status": outcome,
                    "run_id": run_id,
                    "plan_revision": revision,
                    "source_task_id": task_id,
                }
            elif revision >= MAX_PLAN_REVISION:
                outcome = "DA_REVISE_FINAL_ROUND"
                result = {
                    "status": "JASON_DECISION_REQUIRED",
                    "run_id": run_id,
                    "plan_revision": revision,
                    "findings": verdict["findings"],
                    "decision_question": verdict["decision_question"],
                    "source_task_id": task_id,
                }
            else:
                next_revision = revision + 1
                workspace_name = _workspace_name(
                    run_id, "planner_revision", next_revision
                )
                planner_workspace = _workspace(
                    workspace_root,
                    name=workspace_name,
                    create=True,
                )
                next_request = _planner_revision_request(
                    run_id=run_id,
                    intake=intake,
                    revision=next_revision,
                    workspace=planner_workspace,
                    findings=verdict["findings"],
                )
                payload = _review_payload(
                    run_id=run_id,
                    kind="planner_revision",
                    revision=next_revision,
                    source_task_id=task_id,
                    request=next_request,
                    frozen_profiles=intake["frozen_profiles"],
                    extra={
                        "findings": verdict["findings"],
                        "previous_plan_md": request["plan_md"],
                        "previous_plan_json": json.dumps(
                            request["plan"], indent=2, sort_keys=True
                        )
                        + "\n",
                    },
                )
                _insert_review_outbox(
                    conn,
                    idempotency_key=(
                        f"verified-pipeline:{run_id}:planner-revision:{next_revision}"
                    ),
                    payload=payload,
                )
                outcome = "PLANNER_REVISION_QUEUED"
                result = {
                    "status": outcome,
                    "run_id": run_id,
                    "plan_revision": revision,
                    "next_revision": next_revision,
                    "findings": verdict["findings"],
                    "source_task_id": task_id,
                }
            _insert_transition(
                conn,
                key=key,
                run_id=run_id,
                task_id=task_id,
                stage="da",
                revision=revision,
                outcome=outcome,
                payload=result,
            )
            return result
    finally:
        conn.close()


def _ceo_findings(changes: list[str]) -> list[dict[str, Any]]:
    return [
        _finding(f"ceo-change-{index + 1}", change)
        for index, change in enumerate(changes)
    ]


def submit_ceo_completion(
    *,
    run_id: str,
    task_id: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: Optional[str | os.PathLike[str]],
    workspace_root: Path,
) -> dict[str, Any]:
    controller = _controller()
    intake = _intake(run_id, db_path)
    source = _authoritative_stage_payload(
        run_id=run_id,
        task_id=task_id,
        kind="ceo_review",
        db_path=db_path,
    )
    revision = int(source["plan_revision"])
    workspace = _workspace(
        workspace_root,
        name=source["workspace_name"],
        create=False,
    )
    task = _verify_task(
        task_id=task_id,
        expected_assignee=CEO_PROFILE,
        expected_workspace=workspace,
        allowed_statuses={"done"},
        kanban_db_path=kanban_db_path,
        board_name=intake["board"],
    )
    _verify_terminal_run(
        task_id=task_id,
        expected_assignee=CEO_PROFILE,
        expected_workspace=workspace,
        expected_contract=intake["frozen_profiles"][CEO_PROFILE],
        terminal_status=task.status,
        kanban_db_path=kanban_db_path,
        board_name=intake["board"],
    )
    request = source["request"]
    validators.validate_ceo_request(request)
    if _safe_file(workspace / "ceo-request.json", "CEO request") != _canonical_bytes(request):
        raise ReviewCoordinationError("REVIEW_REQUEST_DRIFT", "CEO request bytes drifted")
    decision, _ = _load_json_file(workspace / "decision.json", "decision.json")
    validators.validate_ceo_decision(decision, request=request)
    decision_md = _safe_file(workspace / "decision.md", "decision.md")
    if not decision_md.strip():
        raise validators.ArtifactValidationError("decision.md must not be empty")
    key = f"ceo-completion:{task_id}"
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            existing = conn.execute(
                "SELECT payload_json FROM review_transitions WHERE transition_key = ?",
                (key,),
            ).fetchone()
            if existing is not None:
                return json.loads(existing["payload_json"])
            verdict = decision["decision"]
            if verdict == "APPROVE":
                outcome = "CEO_APPROVED"
                result = {
                    "status": "CEO_APPROVED_PENDING_MATERIALIZATION",
                    "run_id": run_id,
                    "plan_revision": revision,
                    "source_task_id": task_id,
                    "decision": decision,
                    "boundary": "No implementation DAG materialized",
                }
            elif verdict == "REJECT_WITH_CHANGES" and revision < MAX_PLAN_REVISION:
                next_revision = revision + 1
                findings = _ceo_findings(decision["required_changes"])
                workspace_name = _workspace_name(
                    run_id, "planner_revision", next_revision
                )
                planner_workspace = _workspace(
                    workspace_root,
                    name=workspace_name,
                    create=True,
                )
                next_request = _planner_revision_request(
                    run_id=run_id,
                    intake=intake,
                    revision=next_revision,
                    workspace=planner_workspace,
                    findings=findings,
                )
                payload = _review_payload(
                    run_id=run_id,
                    kind="planner_revision",
                    revision=next_revision,
                    source_task_id=task_id,
                    request=next_request,
                    frozen_profiles=intake["frozen_profiles"],
                    extra={
                        "findings": findings,
                        "previous_plan_md": request["plan_md"],
                        "previous_plan_json": json.dumps(
                            request["plan"], indent=2, sort_keys=True
                        )
                        + "\n",
                    },
                )
                _insert_review_outbox(
                    conn,
                    idempotency_key=(
                        f"verified-pipeline:{run_id}:planner-revision:{next_revision}"
                    ),
                    payload=payload,
                )
                outcome = "CEO_REJECT_WITH_CHANGES"
                result = {
                    "status": "PLANNER_REVISION_QUEUED",
                    "run_id": run_id,
                    "plan_revision": revision,
                    "next_revision": next_revision,
                    "findings": findings,
                    "source_task_id": task_id,
                }
            else:
                outcome = f"CEO_{verdict}"
                result = {
                    "status": "JASON_DECISION_REQUIRED",
                    "run_id": run_id,
                    "plan_revision": revision,
                    "source_task_id": task_id,
                    "decision": decision,
                    "boundary": "No implementation DAG materialized",
                }
            _insert_transition(
                conn,
                key=key,
                run_id=run_id,
                task_id=task_id,
                stage="ceo",
                revision=revision,
                outcome=outcome,
                payload=result,
            )
            return result
    finally:
        conn.close()


def _validate_review_payload(
    row: sqlite3.Row,
    *,
    intake: Mapping[str, Any],
    conn: sqlite3.Connection,
) -> dict[str, Any]:
    try:
        payload = json.loads(row["payload_json"])
    except json.JSONDecodeError as exc:
        raise ReviewCoordinationError(
            "REVIEW_OUTBOX_INVALID",
            "review outbox payload is malformed",
        ) from exc
    expected_assignee = {
        "planner_revision": _controller().PLANNER_PROFILE,
        "da_review": DA_PROFILE,
        "ceo_review": CEO_PROFILE,
    }.get(row["kind"])
    revision = payload.get("plan_revision")
    expected_name = (
        _workspace_name(payload.get("run_id", ""), row["kind"], revision)
        if type(revision) is int
        else None
    )
    if (
        row["kind"] not in REVIEW_KINDS
        or payload.get("schema") != REVIEW_CONTROLLER_ID
        or payload.get("run_id") != row["run_id"]
        or payload.get("kind") != row["kind"]
        or payload.get("assignee") != expected_assignee
        or payload.get("workspace_name") != expected_name
        or payload.get("frozen_profiles") != intake["frozen_profiles"]
        or not isinstance(payload.get("source_task_id"), str)
    ):
        raise ReviewCoordinationError(
            "REVIEW_OUTBOX_AUTHORITY_MISMATCH",
            "review outbox payload does not match bounded stage authority",
        )
    request = payload.get("request")
    if row["kind"] == "planner_revision":
        validators.validate_plan_request(request)
    elif row["kind"] == "da_review":
        validators.validate_da_request(request)
    else:
        validators.validate_ceo_request(request)
    transition = conn.execute(
        "SELECT stage, plan_revision, outcome, payload_json FROM review_transitions "
        "WHERE run_id = ? AND source_task_id = ?",
        (row["run_id"], payload["source_task_id"]),
    ).fetchone()
    if transition is None:
        raise ReviewCoordinationError(
            "REVIEW_OUTBOX_AUTHORITY_MISMATCH",
            "review successor has no immutable source transition",
        )
    transition_payload = json.loads(transition["payload_json"])
    if row["kind"] == "da_review":
        valid_source = (
            transition["stage"] == "planner"
            and transition["outcome"] == "DA_REVIEW_QUEUED"
            and transition["plan_revision"] == revision
        )
    elif row["kind"] == "ceo_review":
        valid_source = (
            transition["stage"] == "da"
            and transition["outcome"] == "CEO_REVIEW_QUEUED"
            and transition["plan_revision"] == revision
        )
    else:
        valid_source = (
            transition["outcome"]
            in {"PLANNER_REVISION_QUEUED", "CEO_REJECT_WITH_CHANGES"}
            and transition_payload.get("next_revision") == revision
            and transition["plan_revision"] == revision - 1
        )
    if not valid_source:
        raise ReviewCoordinationError(
            "REVIEW_OUTBOX_AUTHORITY_MISMATCH",
            "review successor is inconsistent with its immutable source transition",
        )
    return payload


def _prepare_review_workspace(
    *,
    payload: Mapping[str, Any],
    intake: Mapping[str, Any],
    workspace_root: Path,
) -> Path:
    workspace = _workspace(
        workspace_root,
        name=payload["workspace_name"],
        create=True,
    )
    kind = payload["kind"]
    request = payload["request"]
    if Path(request["output_workspace"]).resolve() != workspace:
        raise ReviewCoordinationError(
            "REVIEW_WORKSPACE_DRIFT",
            "task-bound request output workspace drifted from its outbox identity",
        )
    if kind == "planner_revision":
        _write_exact(
            workspace / "planner-request.json",
            _canonical_bytes(request),
            "Planner request",
        )
        _write_exact(
            workspace / "specification.md",
            intake["artifact_bytes"],
            "specification",
        )
        _write_exact(
            workspace / "review-findings.json",
            _canonical_bytes(payload["findings"]),
            "review findings",
        )
        _write_exact(
            workspace / "previous-plan.md",
            payload["previous_plan_md"].encode("utf-8"),
            "previous plan markdown",
        )
        _write_exact(
            workspace / "previous-plan.json",
            payload["previous_plan_json"].encode("utf-8"),
            "previous plan JSON",
        )
    elif kind == "da_review":
        _write_exact(
            workspace / "da-request.json",
            _canonical_bytes(request),
            "DA request",
        )
    else:
        _write_exact(
            workspace / "ceo-request.json",
            _canonical_bytes(request),
            "CEO request",
        )
    return workspace


def _task_body(payload: Mapping[str, Any]) -> str:
    kind = payload["kind"]
    if kind == "planner_revision":
        return (
            "# Bounded Planner correction\n\n"
            "Correct only the admitted review findings in task-local files. Do not "
            "create successors, implement, materialize a DAG, merge, deploy, or release.\n\n"
            "Read `planner-request.json`, `specification.md`, `review-findings.json`, "
            "`previous-plan.md`, and `previous-plan.json`. Write `plan.md` and `plan.json`, "
            "then complete only this card. The deterministic controller validates the exact "
            "terminal-run artifacts and writes `validation.md`.\n"
        )
    if kind == "da_review":
        return (
            "# Bounded Devil's Advocate review\n\n"
            "Review only the exact `da-request.json`. Write `premortem.md` and "
            "`verdict.json`. Do not create successors or implementation work. The deterministic "
            "controller validates the exact terminal-run verdict.\n\n"
            "On PASS complete this card. On REVISE block it with `kind='needs_input'`.\n"
        )
    return (
        "# Bounded CEO review\n\n"
        "Review only the exact `ceo-request.json`. Write `decision.md` and `decision.json`. "
        "Do not create successors, materialize a DAG, merge, deploy, or release. The deterministic "
        "controller validates the exact terminal-run decision.\n"
    )


def project_review_outbox(
    idempotency_key: str,
    *,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: Optional[str | os.PathLike[str]],
    workspace_root: Path,
    _after_task_created: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    controller = _controller()
    init_review_schema(db_path)
    conn = controller.connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM review_outbox WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if row is None:
            raise ReviewCoordinationError("REVIEW_OUTBOX_NOT_FOUND", "review outbox row was not found")
        if row["status"] == "DELIVERED":
            return {
                "idempotency_key": idempotency_key,
                "status": "DELIVERED",
                "task_id": row["task_id"],
                "replayed": True,
            }
        intake = _intake(row["run_id"], db_path)
        payload = _validate_review_payload(row, intake=intake, conn=conn)
        workspace = _prepare_review_workspace(
            payload=payload,
            intake=intake,
            workspace_root=workspace_root,
        )
    finally:
        conn.close()
    from hermes_cli import kanban_db

    kanban_path = Path(kanban_db_path) if kanban_db_path else None
    board_name = intake["board"] if kanban_path is None else None
    try:
        kanban_db.init_db(db_path=kanban_path, board=board_name)
        board = _kanban_connection(kanban_db_path, intake["board"])
        try:
            with kanban_db.write_txn(board):
                existing = board.execute(
                    "SELECT id FROM tasks WHERE idempotency_key = ? ORDER BY created_at, id",
                    (idempotency_key,),
                ).fetchall()
                if len(existing) > 1:
                    raise ReviewCoordinationError(
                        "DUPLICATE_REVIEW_SUCCESSOR",
                        "more than one task carries this review outbox identity",
                    )
                if existing:
                    task_id = existing[0]["id"]
                else:
                    title = {
                        "planner_revision": (
                            f"Revise plan for {intake['specification_id']} "
                            f"r{payload['plan_revision']}"
                        ),
                        "da_review": (
                            f"Premortem for {intake['specification_id']} "
                            f"r{payload['plan_revision']}"
                        ),
                        "ceo_review": (
                            f"CEO review for {intake['specification_id']} "
                            f"r{payload['plan_revision']}"
                        ),
                    }[payload["kind"]]
                    parents = (
                        [payload["source_task_id"]]
                        if payload["kind"] in {"da_review", "ceo_review"}
                        else []
                    )
                    task_id = kanban_db.create_task(
                        board,
                        title=title,
                        body=_task_body(payload),
                        assignee=payload["assignee"],
                        created_by="verified-pipeline-review-controller",
                        parents=parents,
                        workspace_kind="dir",
                        workspace_path=str(workspace),
                        tenant=f"verified:{payload['run_id']}",
                        idempotency_key=idempotency_key,
                        max_runtime_seconds=3600,
                        max_retries=0,
                        skills=[
                            {
                                "planner_revision": controller.PLANNER_SKILL,
                                "da_review": DA_SKILL,
                                "ceo_review": CEO_SKILL,
                            }[payload["kind"]]
                        ],
                        require_role_contract=True,
                        expected_role_contract_sha256=(
                            intake["frozen_profiles"][payload["assignee"]]["sha256"]
                        ),
                    )
            if _after_task_created is not None:
                _after_task_created(task_id)
        finally:
            board.close()
    except ReviewCoordinationError:
        raise
    except (OSError, sqlite3.Error):
        _mark_review_projection_error(db_path, idempotency_key, "KANBAN_UNAVAILABLE")
        return {
            "idempotency_key": idempotency_key,
            "status": "PENDING",
            "task_id": None,
            "replayed": False,
            "error_code": "KANBAN_UNAVAILABLE",
        }

    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            conn.execute(
                "UPDATE review_outbox SET status = 'DELIVERED', task_id = ?, "
                "delivered_at = ?, attempts = attempts + 1, last_error_code = NULL "
                "WHERE idempotency_key = ? AND status = 'PENDING'",
                (task_id, _now(), idempotency_key),
            )
    finally:
        conn.close()
    return {
        "idempotency_key": idempotency_key,
        "status": "DELIVERED",
        "task_id": task_id,
        "replayed": False,
    }


def _mark_review_projection_error(
    db_path: Optional[str | os.PathLike[str]],
    idempotency_key: str,
    code: str,
) -> None:
    controller = _controller()
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            conn.execute(
                "UPDATE review_outbox SET attempts = attempts + 1, last_error_code = ? "
                "WHERE idempotency_key = ? AND status = 'PENDING'",
                (code, idempotency_key),
            )
    finally:
        conn.close()


def _pending_review_keys(
    *,
    run_id: str,
    db_path: Optional[str | os.PathLike[str]],
) -> list[str]:
    controller = _controller()
    conn = controller.connect(db_path)
    try:
        return [
            row["idempotency_key"]
            for row in conn.execute(
                "SELECT idempotency_key FROM review_outbox "
                "WHERE run_id = ? AND status = 'PENDING' "
                "ORDER BY created_at, idempotency_key",
                (run_id,),
            )
        ]
    finally:
        conn.close()


def _delivered_stages(
    *,
    run_id: str,
    db_path: Optional[str | os.PathLike[str]],
) -> list[dict[str, Any]]:
    controller = _controller()
    conn = controller.connect(db_path)
    try:
        rows: list[dict[str, Any]] = []
        initial = conn.execute(
            "SELECT o.task_id, o.payload_json, o.created_at FROM outbox o "
            "JOIN decisions d ON d.decision_id = o.decision_id "
            "WHERE d.run_id = ? AND o.kind = 'planner_intake' "
            "AND o.status = 'DELIVERED' AND o.task_id IS NOT NULL",
            (run_id,),
        ).fetchall()
        for row in initial:
            rows.append(
                {
                    "kind": "planner_intake",
                    "task_id": row["task_id"],
                    "payload": json.loads(row["payload_json"]),
                    "created_at": row["created_at"],
                }
            )
        for row in conn.execute(
            "SELECT kind, task_id, payload_json, created_at FROM review_outbox "
            "WHERE run_id = ? AND status = 'DELIVERED' AND task_id IS NOT NULL",
            (run_id,),
        ):
            rows.append(
                {
                    "kind": row["kind"],
                    "task_id": row["task_id"],
                    "payload": json.loads(row["payload_json"]),
                    "created_at": row["created_at"],
                }
            )
        return sorted(rows, key=lambda item: (item["created_at"], item["task_id"]))
    finally:
        conn.close()


def reconcile_review_once(
    run_id: str,
    *,
    db_path: Optional[str | os.PathLike[str]] = None,
    kanban_db_path: Optional[str | os.PathLike[str]] = None,
    workspace_root: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    """Project pending work and admit terminal Planner/DA/CEO cards once."""
    controller = _controller()
    init_review_schema(db_path)
    intake = _intake(run_id, db_path)
    root = (
        Path(workspace_root)
        if workspace_root is not None
        else controller._default_workspace_root()
    )
    initial = controller.project_run(
        run_id,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
        workspace_root=root,
    )
    delivered: list[dict[str, Any]] = []
    if not initial["replayed"]:
        delivered.append(initial)
    for key in _pending_review_keys(run_id=run_id, db_path=db_path):
        receipt = project_review_outbox(
            key,
            db_path=db_path,
            kanban_db_path=kanban_db_path,
            workspace_root=root,
        )
        if receipt["status"] == "DELIVERED":
            delivered.append(receipt)
    advanced: list[dict[str, Any]] = []
    conn = controller.connect(db_path)
    try:
        completed = {
            row["source_task_id"]
            for row in conn.execute(
                "SELECT source_task_id FROM review_transitions WHERE run_id = ?",
                (run_id,),
            )
        }
    finally:
        conn.close()
    from hermes_cli import kanban_db

    for stage in _delivered_stages(run_id=run_id, db_path=db_path):
        if stage["task_id"] in completed or stage["kind"] == "specifier_revision":
            continue
        board = _kanban_connection(kanban_db_path, intake["board"])
        try:
            task = kanban_db.get_task(board, stage["task_id"])
        finally:
            board.close()
        if task is None:
            raise ReviewCoordinationError(
                "REVIEW_TASK_MISSING",
                "delivered stage references a missing task",
            )
        if stage["kind"] in {"planner_intake", "planner_revision"}:
            if task.status != "done":
                continue
            result = submit_planner_completion(
                run_id=run_id,
                task_id=task.id,
                kind=stage["kind"],
                db_path=db_path,
                kanban_db_path=kanban_db_path,
                workspace_root=root,
            )
        elif stage["kind"] == "da_review":
            if task.status not in {"done", "blocked", "triage"}:
                continue
            result = submit_da_completion(
                run_id=run_id,
                task_id=task.id,
                db_path=db_path,
                kanban_db_path=kanban_db_path,
                workspace_root=root,
            )
        else:
            if task.status != "done":
                continue
            result = submit_ceo_completion(
                run_id=run_id,
                task_id=task.id,
                db_path=db_path,
                kanban_db_path=kanban_db_path,
                workspace_root=root,
            )
        advanced.append(
            {
                "kind": stage["kind"],
                "task_id": task.id,
                "status": result["status"],
            }
        )
        completed.add(task.id)
    for key in _pending_review_keys(run_id=run_id, db_path=db_path):
        receipt = project_review_outbox(
            key,
            db_path=db_path,
            kanban_db_path=kanban_db_path,
            workspace_root=root,
        )
        if receipt["status"] == "DELIVERED":
            delivered.append(receipt)
    return {
        "run_id": run_id,
        "advanced": advanced,
        "delivered": delivered,
        "status": intake["status"],
    }
