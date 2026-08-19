"""Disabled-by-default exact merge actuator for verified-pipeline custody.

This module is an operational capability boundary.  It is intentionally not
imported by the plugin package, dashboard, reconciler, dispatcher, gateway, or
any service startup path.  The public entry point is usable only in a separate
trusted process with three startup pins:

* an exact enable token;
* the SHA-256 of the canonical one-shot actuation scope; and
* the SHA-256 of the fixed ``/usr/bin/gh`` executable.

The persisted custody and Kanban databases are adversarial.  Signed authority,
full execution completion, exact board state, and candidate scope are
revalidated at consumption.  A durable DISPATCHED event is committed before
calling GitHub.  If the process loses the result after dispatch, replay stops at
OUTCOME_UNKNOWN; it never retries the merge.  A successful local observation
is not a signed merge-result attestation and grants no deployment/live authority.

Arbitrary malicious Python in this same process is outside the security model;
production use requires the dedicated privileged process exposed by ``main``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
from typing import Any, Mapping, Protocol

from hermes_cli import kanban_db
from plugins.verified_pipeline import controller, execution, release

ACTUATOR_ID = "verified-pipeline/exact-github-merge-actuator/v1"
ADAPTER_RESULT_SCHEMA = "verified-pipeline/github-merge-observation/v1"
ENABLE_ENV = "HERMES_VERIFIED_PIPELINE_MERGE_ACTUATOR_ENABLE"
SCOPE_PIN_ENV = "HERMES_VERIFIED_PIPELINE_MERGE_ACTUATOR_SCOPE_SHA256"
GH_PIN_ENV = "HERMES_VERIFIED_PIPELINE_GH_SHA256"
ENABLE_TOKEN = "EXECUTE_ONE_EXACT_SIGNED_MERGE_V1"
GH_BINARY = Path("/usr/bin/gh")

_STARTUP_ENABLE = os.environ.get(ENABLE_ENV, "")
_STARTUP_SCOPE_SHA256 = os.environ.get(SCOPE_PIN_ENV, "")
_STARTUP_GH_SHA256 = os.environ.get(GH_PIN_ENV, "")


class MergeActuatorError(RuntimeError):
    """Stable fail-closed actuator error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class MergeAdapter(Protocol):
    def merge(self, scope: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _canonical(value: Any) -> str:
    return execution._canonical(value)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _regular_absolute_path(value: str | os.PathLike[str], *, code: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise MergeActuatorError(code, "actuator database path must be an absolute regular file")
    return path.resolve(strict=True)


def _scope_from_receipt(
    receipt: Mapping[str, Any],
    *,
    execution_key: str,
    board: str,
    control_db_path: Path,
    kanban_db_path: Path,
) -> dict[str, Any]:
    immutable_receipt = {key: value for key, value in receipt.items() if key != "replayed"}
    return {
        "schema": ACTUATOR_ID,
        "action": "MERGE",
        "execution_key": execution_key,
        "board": board,
        "control_db_path": str(control_db_path),
        "kanban_db_path": str(kanban_db_path),
        "merge_key": receipt["merge_key"],
        "merge_authorization_sha256": _digest(immutable_receipt),
        "repository": receipt["repository"],
        "base_ref": receipt["base_ref"],
        "head_sha": receipt["head_sha"],
        "pull_request": receipt["pull_request"],
        "merge_method": receipt["merge_method"],
    }


def _read_untrusted_scope(
    execution_key: str,
    *,
    board: str,
    control_db_path: Path,
    kanban_db_path: Path,
) -> dict[str, Any]:
    """Read only enough untrusted custody to compare with the startup scope pin."""
    try:
        conn = sqlite3.connect(f"file:{control_db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT payload_json FROM merge_authorization_receipts WHERE merge_key = ?",
            (f"{execution_key}:merge",),
        ).fetchone()
    except sqlite3.Error as exc:
        raise MergeActuatorError("MERGE_SCOPE_UNAVAILABLE", "merge scope could not be read") from exc
    finally:
        if "conn" in locals():
            conn.close()
    if row is None:
        raise MergeActuatorError("MERGE_AUTHORIZATION_REQUIRED", "merge authorization is missing")
    try:
        receipt = json.loads(row["payload_json"])
        required = {
            "merge_key",
            "repository",
            "base_ref",
            "head_sha",
            "pull_request",
            "merge_method",
        }
        if not isinstance(receipt, dict) or not required.issubset(receipt):
            raise ValueError
        return _scope_from_receipt(
            receipt,
            execution_key=execution_key,
            board=board,
            control_db_path=control_db_path,
            kanban_db_path=kanban_db_path,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MergeActuatorError("MERGE_SCOPE_INVALID", "merge scope is malformed") from exc


def _validate_startup_gate(scope: Mapping[str, Any]) -> None:
    if _STARTUP_ENABLE != ENABLE_TOKEN:
        raise MergeActuatorError("MERGE_ACTUATOR_DISABLED", "merge actuator is disabled at startup")
    if not re.fullmatch(r"[0-9a-f]{64}", _STARTUP_SCOPE_SHA256):
        raise MergeActuatorError("MERGE_SCOPE_PIN_REQUIRED", "exact startup scope pin is required")
    if _digest(scope) != _STARTUP_SCOPE_SHA256:
        raise MergeActuatorError("MERGE_SCOPE_PIN_MISMATCH", "requested merge differs from startup scope")
    if not re.fullmatch(r"[0-9a-f]{64}", _STARTUP_GH_SHA256):
        raise MergeActuatorError("GH_BINARY_PIN_REQUIRED", "GitHub adapter binary pin is required")
    if not GH_BINARY.is_file() or GH_BINARY.is_symlink():
        raise MergeActuatorError("GH_BINARY_INVALID", "fixed GitHub adapter binary is unavailable")
    if hashlib.sha256(GH_BINARY.read_bytes()).hexdigest() != _STARTUP_GH_SHA256:
        raise MergeActuatorError("GH_BINARY_PIN_MISMATCH", "GitHub adapter binary differs from startup pin")
    if not os.environ.get("GH_TOKEN"):
        raise MergeActuatorError("GH_TOKEN_REQUIRED", "dedicated GitHub credential is required")


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS merge_actuator_identity (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            actuator_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS merge_actuator_intents (
            consumption_key TEXT PRIMARY KEY,
            execution_key TEXT NOT NULL UNIQUE,
            scope_json TEXT NOT NULL,
            scope_sha256 TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS merge_actuator_events (
            event_key TEXT PRIMARY KEY,
            consumption_key TEXT NOT NULL REFERENCES merge_actuator_intents(consumption_key),
            kind TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(consumption_key, kind)
        );
        CREATE TRIGGER IF NOT EXISTS merge_actuator_identity_no_update
        BEFORE UPDATE ON merge_actuator_identity
        BEGIN SELECT RAISE(ABORT, 'merge actuator identity is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS merge_actuator_identity_no_delete
        BEFORE DELETE ON merge_actuator_identity
        BEGIN SELECT RAISE(ABORT, 'merge actuator identity is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS merge_actuator_intent_no_update
        BEFORE UPDATE ON merge_actuator_intents
        BEGIN SELECT RAISE(ABORT, 'merge actuator intent is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS merge_actuator_intent_no_delete
        BEFORE DELETE ON merge_actuator_intents
        BEGIN SELECT RAISE(ABORT, 'merge actuator intent is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS merge_actuator_event_no_update
        BEFORE UPDATE ON merge_actuator_events
        BEGIN SELECT RAISE(ABORT, 'merge actuator event is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS merge_actuator_event_no_delete
        BEFORE DELETE ON merge_actuator_events
        BEGIN SELECT RAISE(ABORT, 'merge actuator event is append-only'); END;
        """
    )
    with kanban_db.write_txn(conn):
        conn.execute(
            "INSERT OR IGNORE INTO merge_actuator_identity "
            "(singleton, actuator_id, created_at) VALUES (1, ?, ?)",
            (ACTUATOR_ID, int(time.time())),
        )
        row = conn.execute(
            "SELECT actuator_id FROM merge_actuator_identity WHERE singleton = 1"
        ).fetchone()
    if row is None or row["actuator_id"] != ACTUATOR_ID:
        raise MergeActuatorError("ACTUATOR_IDENTITY_MISMATCH", "actuator schema identity differs")


def _validated_scope(
    execution_key: str,
    *,
    board: str,
    control_db_path: Path,
    kanban_db_path: Path,
) -> dict[str, Any]:
    try:
        receipt = release._validated_merge_authorization(
            execution_key,
            board=board,
            db_path=control_db_path,
            kanban_db_path=kanban_db_path,
        )
    except release.ReleaseBoundaryError as exc:
        raise MergeActuatorError(
            "MERGE_AUTHORITY_INVALID", "signed merge authority or board completion is invalid"
        ) from exc
    return _scope_from_receipt(
        receipt,
        execution_key=execution_key,
        board=board,
        control_db_path=control_db_path,
        kanban_db_path=kanban_db_path,
    )


def _locked_completion_revalidation(
    execution_key: str,
    *,
    board: str,
    control_db_path: Path,
    board_conn: sqlite3.Connection,
) -> None:
    """Revalidate exact board completion without opening another board writer."""
    try:
        execution._validated_completion_receipt_on_board_connection(
            execution_key,
            board=board,
            authority_verifier=release._pinned_verifier(
                release.EXECUTION_POLICY_KEY, control_db_path
            ),
            db_path=control_db_path,
            board_conn=board_conn,
            require_existing=True,
        )
    except (execution.ExecutionError, release.ReleaseBoundaryError) as exc:
        raise MergeActuatorError(
            "MERGE_AUTHORITY_INVALID", "locked board completion revalidation failed"
        ) from exc


def _refresh_exact_scope(
    execution_key: str,
    *,
    board: str,
    control_db_path: Path,
    kanban_db_path: Path,
    expected_scope: Mapping[str, Any],
) -> dict[str, Any]:
    scope = _validated_scope(
        execution_key,
        board=board,
        control_db_path=control_db_path,
        kanban_db_path=kanban_db_path,
    )
    if _canonical(scope) != _canonical(expected_scope):
        raise MergeActuatorError("MERGE_SCOPE_DRIFT", "validated merge scope changed")
    return scope


def _event(conn: sqlite3.Connection, consumption_key: str, kind: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT payload_json FROM merge_actuator_events WHERE consumption_key = ? AND kind = ?",
        (consumption_key, kind),
    ).fetchone()
    return None if row is None else json.loads(row["payload_json"])


def _insert_event(
    conn: sqlite3.Connection,
    *,
    consumption_key: str,
    kind: str,
    payload: Mapping[str, Any],
) -> bool:
    canonical = _canonical(payload)
    try:
        conn.execute(
            "INSERT INTO merge_actuator_events "
            "(event_key, consumption_key, kind, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (f"{consumption_key}:{kind.lower()}", consumption_key, kind, canonical, int(time.time())),
        )
        return True
    except sqlite3.IntegrityError:
        existing = _event(conn, consumption_key, kind)
        if existing is not None and _canonical(existing) == canonical:
            return False
        raise MergeActuatorError("ACTUATOR_EVENT_CONFLICT", "actuator event conflicts with custody")


def _admit_intent(
    conn: sqlite3.Connection,
    *,
    execution_key: str,
    scope: Mapping[str, Any],
) -> str:
    consumption_key = f"{execution_key}:merge-actuation"
    canonical = _canonical(scope)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    row = conn.execute(
        "SELECT execution_key, scope_json, scope_sha256 FROM merge_actuator_intents "
        "WHERE consumption_key = ?",
        (consumption_key,),
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO merge_actuator_intents "
            "(consumption_key, execution_key, scope_json, scope_sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (consumption_key, execution_key, canonical, digest, int(time.time())),
        )
    elif (
        row["execution_key"] != execution_key
        or row["scope_json"] != canonical
        or row["scope_sha256"] != digest
    ):
        raise MergeActuatorError("MERGE_INTENT_CONFLICT", "existing merge intent has different scope")
    return consumption_key


def _validate_adapter_result(result: Mapping[str, Any], scope: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema": ADAPTER_RESULT_SCHEMA,
        "repository": scope["repository"],
        "base_ref": scope["base_ref"],
        "head_sha": scope["head_sha"],
        "pull_request": scope["pull_request"],
        "merge_method": scope["merge_method"],
        "result": "MERGED",
    }
    if not isinstance(result, Mapping) or set(result) != {*expected, "merge_commit_sha"}:
        raise MergeActuatorError("ADAPTER_RESULT_INVALID", "merge adapter returned an invalid result")
    if any(result[key] != value for key, value in expected.items()):
        raise MergeActuatorError("ADAPTER_SCOPE_MISMATCH", "merge adapter result differs from exact scope")
    if not release._is_sha(result["merge_commit_sha"]):
        raise MergeActuatorError("ADAPTER_RESULT_INVALID", "merge adapter returned an invalid commit")
    return dict(result)


def _consume_exact_merge(
    execution_key: str,
    *,
    board: str,
    db_path: str | os.PathLike[str],
    kanban_db_path: str | os.PathLike[str],
    expected_scope: Mapping[str, Any],
    adapter: MergeAdapter,
) -> dict[str, Any]:
    """Private core used by the dedicated process and disposable tests."""
    control_path = _regular_absolute_path(db_path, code="CONTROL_DB_PATH_INVALID")
    board_path = _regular_absolute_path(kanban_db_path, code="KANBAN_DB_PATH_INVALID")
    scope = _refresh_exact_scope(
        execution_key,
        board=board,
        control_db_path=control_path,
        kanban_db_path=board_path,
        expected_scope=expected_scope,
    )
    conn = kanban_db.connect(db_path=board_path)
    try:
        _init_schema(conn)
        consumption_key = f"{execution_key}:merge-actuation"
        with kanban_db.write_txn(conn):
            _locked_completion_revalidation(
                execution_key,
                board=board,
                control_db_path=control_path,
                board_conn=conn,
            )
            consumption_key = _admit_intent(conn, execution_key=execution_key, scope=scope)
            succeeded = _event(conn, consumption_key, "SUCCEEDED")
            if succeeded is not None:
                return {**succeeded, "replayed": True}
            if _event(conn, consumption_key, "DISPATCHED") is not None:
                raise MergeActuatorError(
                    "MERGE_OUTCOME_UNKNOWN",
                    "merge was dispatched without a durable success observation; do not retry",
                )

        scope = _refresh_exact_scope(
            execution_key,
            board=board,
            control_db_path=control_path,
            kanban_db_path=board_path,
            expected_scope=expected_scope,
        )
        with kanban_db.write_txn(conn):
            _locked_completion_revalidation(
                execution_key,
                board=board,
                control_db_path=control_path,
                board_conn=conn,
            )
            created = _insert_event(
                conn,
                consumption_key=consumption_key,
                kind="DISPATCHED",
                payload={
                    "schema": ACTUATOR_ID,
                    "consumption_key": consumption_key,
                    "scope_sha256": _digest(scope),
                    "status": "DISPATCHED_OUTCOME_UNKNOWN_UNTIL_OBSERVED",
                },
            )
        if not created:
            raise MergeActuatorError(
                "MERGE_OUTCOME_UNKNOWN", "another process already dispatched this exact merge"
            )

        scope = _refresh_exact_scope(
            execution_key,
            board=board,
            control_db_path=control_path,
            kanban_db_path=board_path,
            expected_scope=expected_scope,
        )
        try:
            with kanban_db.write_txn(conn):
                _locked_completion_revalidation(
                    execution_key,
                    board=board,
                    control_db_path=control_path,
                    board_conn=conn,
                )
                observed = _validate_adapter_result(adapter.merge(scope), scope)
                receipt = {
                    "schema": ACTUATOR_ID,
                    "consumption_key": consumption_key,
                    "execution_key": execution_key,
                    "scope_sha256": _digest(scope),
                    "merge_commit_sha": observed["merge_commit_sha"],
                    "status": "MERGE_OBSERVED_PENDING_SIGNED_RESULT_ATTESTATION",
                    "boundary": "local observation only; no deployment or live authority",
                }
                _insert_event(
                    conn,
                    consumption_key=consumption_key,
                    kind="SUCCEEDED",
                    payload=receipt,
                )
                return {**receipt, "replayed": False}
        except MergeActuatorError:
            raise
        except Exception as exc:
            raise MergeActuatorError(
                "MERGE_OUTCOME_UNKNOWN",
                "adapter returned no durably admitted result; do not retry automatically",
            ) from exc
    finally:
        conn.close()


class GitHubCLIAdapter:
    """Fixed-binary conditional GitHub merge adapter."""

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        env = {
            "GH_TOKEN": os.environ["GH_TOKEN"],
            "GH_HOST": "github.com",
            "NO_COLOR": "1",
            "LC_ALL": "C.UTF-8",
        }
        try:
            return subprocess.run(
                [str(GH_BINARY), *args],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise MergeActuatorError("GITHUB_ADAPTER_FAILED", "GitHub adapter failed") from exc

    def _view(self, scope: Mapping[str, Any]) -> dict[str, Any]:
        completed = self._run(
            [
                "pr",
                "view",
                str(scope["pull_request"]),
                "--repo",
                scope["repository"],
                "--json",
                "number,state,headRefOid,baseRefName,mergeCommit",
            ]
        )
        try:
            value = json.loads(completed.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise MergeActuatorError("GITHUB_RESPONSE_INVALID", "GitHub returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise MergeActuatorError("GITHUB_RESPONSE_INVALID", "GitHub returned invalid PR state")
        return value

    def merge(self, scope: Mapping[str, Any]) -> Mapping[str, Any]:
        before = self._view(scope)
        if (
            before.get("number") != scope["pull_request"]
            or before.get("state") != "OPEN"
            or before.get("headRefOid") != scope["head_sha"]
            or before.get("baseRefName") != scope["base_ref"]
            or before.get("mergeCommit") is not None
        ):
            raise MergeActuatorError("GITHUB_PR_SCOPE_MISMATCH", "GitHub PR differs from authority")
        repository = scope["repository"]
        if not isinstance(repository, str) or re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
        ) is None:
            raise MergeActuatorError("GITHUB_REPOSITORY_INVALID", "repository is not owner/name")
        merged = self._run(
            [
                "api",
                "--method",
                "PUT",
                f"repos/{repository}/pulls/{scope['pull_request']}/merge",
                "--raw-field",
                f"sha={scope['head_sha']}",
                "--raw-field",
                f"merge_method={scope['merge_method']}",
            ]
        )
        try:
            merge_response = json.loads(merged.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise MergeActuatorError(
                "GITHUB_RESPONSE_INVALID", "GitHub merge endpoint returned invalid JSON"
            ) from exc
        response_sha = merge_response.get("sha") if isinstance(merge_response, dict) else None
        if (
            not isinstance(merge_response, dict)
            or merge_response.get("merged") is not True
            or not release._is_sha(response_sha)
        ):
            raise MergeActuatorError("GITHUB_MERGE_NOT_OBSERVED", "GitHub did not confirm a merge")
        after = self._view(scope)
        merge_commit = after.get("mergeCommit")
        merge_oid = merge_commit.get("oid") if isinstance(merge_commit, dict) else None
        if (
            after.get("number") != scope["pull_request"]
            or after.get("state") != "MERGED"
            or after.get("headRefOid") != scope["head_sha"]
            or after.get("baseRefName") != scope["base_ref"]
            or not release._is_sha(merge_oid)
            or merge_oid != response_sha
        ):
            raise MergeActuatorError("GITHUB_MERGE_NOT_OBSERVED", "exact merge result was not observed")
        return {
            "schema": ADAPTER_RESULT_SCHEMA,
            "repository": scope["repository"],
            "base_ref": scope["base_ref"],
            "head_sha": scope["head_sha"],
            "pull_request": scope["pull_request"],
            "merge_method": scope["merge_method"],
            "merge_commit_sha": merge_oid,
            "result": "MERGED",
        }


def consume_exact_merge(
    execution_key: str,
    *,
    board: str,
    db_path: str | os.PathLike[str],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Consume one externally pinned signed merge authorization."""
    control_path = _regular_absolute_path(db_path, code="CONTROL_DB_PATH_INVALID")
    board_path = _regular_absolute_path(kanban_db_path, code="KANBAN_DB_PATH_INVALID")
    untrusted_scope = _read_untrusted_scope(
        execution_key,
        board=board,
        control_db_path=control_path,
        kanban_db_path=board_path,
    )
    _validate_startup_gate(untrusted_scope)
    return _consume_exact_merge(
        execution_key,
        board=board,
        db_path=control_path,
        kanban_db_path=board_path,
        expected_scope=untrusted_scope,
        adapter=GitHubCLIAdapter(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consume one exact signed GitHub merge authority")
    parser.add_argument("--execution-key", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--control-db", required=True)
    parser.add_argument("--kanban-db", required=True)
    args = parser.parse_args(argv)
    try:
        result = consume_exact_merge(
            args.execution_key,
            board=args.board,
            db_path=args.control_db,
            kanban_db_path=args.kanban_db,
        )
    except MergeActuatorError as exc:
        print(_canonical({"error": exc.code, "message": exc.message}), file=sys.stderr)
        return 2
    print(_canonical(result))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a separate process
    raise SystemExit(main())
