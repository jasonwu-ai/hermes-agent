"""Explicit bounded execution authorization for materialized plan DAGs.

Nothing in this module is wired into startup, review reconciliation, dashboard
routes, or dispatch loops.  A trusted caller must record an authorization and
then explicitly project it.  Projection only arms the already-materialized
Kanban DAG; normal Kanban dependency gating owns subsequent execution.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Callable, Mapping, Optional

from plugins.verified_pipeline import controller, materializer

EXECUTION_CONTROLLER_ID = "verified-pipeline/bounded-execution-controller/v1"
AUTHORIZATION_SCHEMA = "verified-pipeline/execution-authorization/v1"
EXECUTION_DECISION = "AUTHORIZE_BOUNDED_EXECUTION"
COMPLETION_STATUS = "IMPLEMENTATION_COMPLETE_PENDING_RELEASE_REVIEW"
AUTHORIZED_BOUNDARY = (
    "bounded execution authorized; no merge, deploy, or release authority"
)


class ExecutionError(RuntimeError):
    """Stable fail-closed error raised by the execution boundary."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256((_canonical(value) + "\n").encode("utf-8")).hexdigest()


def init_execution_schema(
    db_path: Optional[str | os.PathLike[str]] = None,
) -> Path:
    path = materializer.init_materialization_schema(db_path)
    conn = controller.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS execution_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                controller_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_outbox (
                idempotency_key TEXT PRIMARY KEY,
                materialization_key TEXT NOT NULL UNIQUE
                    REFERENCES materialization_outbox(idempotency_key),
                run_id TEXT NOT NULL UNIQUE REFERENCES intakes(run_id),
                source_task_id TEXT NOT NULL UNIQUE,
                board TEXT NOT NULL,
                plan_sha256 TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'ARMED')),
                attempts INTEGER NOT NULL DEFAULT 0,
                armed_at INTEGER,
                last_error_code TEXT
            );

            CREATE TABLE IF NOT EXISTS execution_completion_receipts (
                execution_key TEXT PRIMARY KEY
                    REFERENCES execution_outbox(idempotency_key),
                run_id TEXT NOT NULL UNIQUE REFERENCES intakes(run_id),
                plan_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS execution_identity_no_update
            BEFORE UPDATE ON execution_identity
            BEGIN SELECT RAISE(ABORT, 'execution identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS execution_identity_no_delete
            BEFORE DELETE ON execution_identity
            BEGIN SELECT RAISE(ABORT, 'execution identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS execution_outbox_payload_no_update
            BEFORE UPDATE OF idempotency_key, materialization_key, run_id,
                source_task_id, board, plan_sha256, authorization_sha256,
                payload_json, created_at
            ON execution_outbox
            BEGIN SELECT RAISE(ABORT, 'execution authorization is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS execution_outbox_no_delete
            BEFORE DELETE ON execution_outbox
            BEGIN SELECT RAISE(ABORT, 'execution outbox is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS execution_completion_no_update
            BEFORE UPDATE ON execution_completion_receipts
            BEGIN SELECT RAISE(ABORT, 'execution completion is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS execution_completion_no_delete
            BEFORE DELETE ON execution_completion_receipts
            BEGIN SELECT RAISE(ABORT, 'execution completion is append-only'); END;
            """
        )
        with controller._write_txn(conn):
            conn.execute(
                "INSERT OR IGNORE INTO execution_identity "
                "(singleton, controller_id, created_at) VALUES (1, ?, ?)",
                (EXECUTION_CONTROLLER_ID, controller._now()),
            )
        identity = conn.execute(
            "SELECT controller_id FROM execution_identity WHERE singleton = 1"
        ).fetchone()
        if identity is None or identity["controller_id"] != EXECUTION_CONTROLLER_ID:
            raise ExecutionError(
                "EXECUTION_IDENTITY_MISMATCH",
                "execution database identity does not match this implementation",
            )
    finally:
        conn.close()
    return path


def _load_materialization(
    materialization_key: str,
    *,
    db_path: Optional[str | os.PathLike[str]],
) -> tuple[sqlite3.Row, dict[str, Any], dict[str, str]]:
    conn = controller.connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM materialization_outbox WHERE idempotency_key = ?",
            (materialization_key,),
        ).fetchone()
        if row is None or row["status"] != "DELIVERED":
            raise ExecutionError(
                "MATERIALIZATION_NOT_DELIVERED",
                "exact materialization receipt is not delivered",
            )
        try:
            payload = json.loads(row["payload_json"])
            task_map = json.loads(row["task_map_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ExecutionError(
                "MATERIALIZATION_RECEIPT_INVALID",
                "materialization receipt is malformed",
            ) from exc
        live = materializer._approved_payload(
            run_id=row["run_id"],
            source_task_id=row["source_task_id"],
            db_path=db_path,
        )
        if (
            payload != live
            or row["plan_sha256"] != live["plan_sha256"]
            or set(task_map) != {task["id"] for task in payload["plan"]["tasks"]}
            or not all(isinstance(value, str) and value for value in task_map.values())
            or len(set(task_map.values())) != len(task_map)
        ):
            raise ExecutionError(
                "MATERIALIZATION_RECEIPT_INVALID",
                "materialization receipt no longer matches approval custody",
            )
        return row, payload, task_map
    finally:
        conn.close()


def _validate_authorization(
    authorization: Mapping[str, Any],
    *,
    materialization_key: str,
    payload: Mapping[str, Any],
) -> dict[str, str]:
    expected_keys = {
        "schema",
        "run_id",
        "materialization_key",
        "decision",
        "authorized_by",
        "authority_ref",
    }
    if set(authorization) != expected_keys:
        raise ExecutionError(
            "EXECUTION_AUTHORIZATION_INVALID",
            "authorization has missing or unknown fields",
        )
    normalized = dict(authorization)
    if (
        normalized["schema"] != AUTHORIZATION_SCHEMA
        or normalized["run_id"] != payload["run_id"]
        or normalized["materialization_key"] != materialization_key
        or normalized["decision"] != EXECUTION_DECISION
        or not isinstance(normalized["authorized_by"], str)
        or not normalized["authorized_by"].strip()
        or not isinstance(normalized["authority_ref"], str)
        or not normalized["authority_ref"].strip()
    ):
        raise ExecutionError(
            "EXECUTION_AUTHORIZATION_INVALID",
            "authorization identity or decision is invalid",
        )
    return normalized


def record_execution_authorization(
    *,
    materialization_key: str,
    authorization: Mapping[str, Any],
    db_path: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    """Commit one immutable authorization for an exact delivered graph."""
    init_execution_schema(db_path)
    row, payload, task_map = _load_materialization(
        materialization_key, db_path=db_path
    )
    normalized = _validate_authorization(
        authorization, materialization_key=materialization_key, payload=payload
    )
    execution_key = (
        f"verified-pipeline:{payload['run_id']}:execution:r{payload['plan_revision']}"
    )
    intent = {
        "schema": EXECUTION_CONTROLLER_ID,
        "execution_key": execution_key,
        "materialization_key": materialization_key,
        "run_id": payload["run_id"],
        "source_task_id": payload["source_task_id"],
        "board": payload["board"],
        "plan_sha256": payload["plan_sha256"],
        "task_map": task_map,
        "authorization": normalized,
        "boundary": "bounded execution only; no merge, deploy, or release authority",
    }
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            existing = conn.execute(
                "SELECT * FROM execution_outbox WHERE idempotency_key = ?",
                (execution_key,),
            ).fetchone()
            if existing is not None:
                if existing["payload_json"] != _canonical(intent):
                    raise ExecutionError(
                        "EXECUTION_AUTHORIZATION_DRIFT",
                        "existing execution authorization has different immutable bytes",
                    )
                return {
                    "idempotency_key": execution_key,
                    "status": existing["status"],
                    "replayed": True,
                }
            conn.execute(
                "INSERT INTO execution_outbox "
                "(idempotency_key, materialization_key, run_id, source_task_id, "
                "board, plan_sha256, authorization_sha256, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    execution_key,
                    materialization_key,
                    row["run_id"],
                    row["source_task_id"],
                    row["board"],
                    row["plan_sha256"],
                    _digest(normalized),
                    _canonical(intent),
                    controller._now(),
                ),
            )
        return {"idempotency_key": execution_key, "status": "PENDING", "replayed": False}
    finally:
        conn.close()


def _load_execution(
    execution_key: str,
    *,
    db_path: Optional[str | os.PathLike[str]],
) -> tuple[sqlite3.Row, dict[str, Any], dict[str, Any]]:
    conn = controller.connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM execution_outbox WHERE idempotency_key = ?",
            (execution_key,),
        ).fetchone()
        if row is None:
            raise ExecutionError(
                "EXECUTION_AUTHORIZATION_NOT_FOUND", "execution authorization was not found"
            )
        try:
            intent = json.loads(row["payload_json"])
        except json.JSONDecodeError as exc:
            raise ExecutionError(
                "EXECUTION_AUTHORIZATION_INVALID", "execution payload is malformed"
            ) from exc
        materialization, payload, task_map = _load_materialization(
            row["materialization_key"], db_path=db_path
        )
        expected = {
            "schema": EXECUTION_CONTROLLER_ID,
            "execution_key": execution_key,
            "materialization_key": row["materialization_key"],
            "run_id": payload["run_id"],
            "source_task_id": payload["source_task_id"],
            "board": payload["board"],
            "plan_sha256": payload["plan_sha256"],
            "task_map": task_map,
            "authorization": intent.get("authorization"),
            "boundary": "bounded execution only; no merge, deploy, or release authority",
        }
        normalized = _validate_authorization(
            intent.get("authorization", {}),
            materialization_key=row["materialization_key"],
            payload=payload,
        )
        if (
            intent != expected
            or row["authorization_sha256"] != _digest(normalized)
            or row["run_id"] != materialization["run_id"]
            or row["source_task_id"] != materialization["source_task_id"]
            or row["board"] != materialization["board"]
            or row["plan_sha256"] != materialization["plan_sha256"]
        ):
            raise ExecutionError(
                "EXECUTION_AUTHORIZATION_DRIFT",
                "execution authorization no longer matches materialization custody",
            )
        return row, intent, payload
    finally:
        conn.close()


def _expected_armed_status(task: Mapping[str, Any]) -> str:
    return "todo" if task["dependencies"] else "ready"


def _authorized_task_body(payload: Mapping[str, Any], task: Mapping[str, Any]) -> str:
    inert = materializer._task_body(payload, task)
    expected = (
        f"**Boundary: {materializer.INERT_BOUNDARY}. "
        "Do not execute, dispatch, merge, deploy, or release.**"
    )
    authorized = (
        f"**Boundary: {AUTHORIZED_BOUNDARY}. Execute only this approved task and "
        "its acceptance criteria.**"
    )
    if expected not in inert:
        raise ExecutionError(
            "EXECUTION_TASK_TEMPLATE_DRIFT", "materialized task boundary template drifted"
        )
    return inert.replace(
        "# Verified implementation task (INERT)",
        "# Verified implementation task (EXECUTION AUTHORIZED)",
        1,
    ).replace(expected, authorized, 1)


def _validate_arm_events(
    conn: sqlite3.Connection,
    *,
    execution_key: str,
    task_ids: list[str],
    expected_count: int = 1,
) -> None:
    for task_id in task_ids:
        events = conn.execute(
            "SELECT payload FROM task_events WHERE task_id = ? AND kind = 'unblocked' "
            "ORDER BY id",
            (task_id,),
        ).fetchall()
        matching = []
        for event in events:
            try:
                event_payload = json.loads(event["payload"] or "{}")
            except json.JSONDecodeError:
                continue
            if (
                event_payload.get("authority") == EXECUTION_CONTROLLER_ID
                and event_payload.get("execution_key") == execution_key
            ):
                matching.append(event_payload)
        if len(matching) != expected_count:
            raise ExecutionError(
                "EXECUTION_ARM_RECEIPT_DRIFT",
                "task execution authorization event count is inconsistent",
            )


def _validate_bound_graph(
    conn: sqlite3.Connection,
    *,
    intent: Mapping[str, Any],
    payload: Mapping[str, Any],
    allowed_statuses: set[str],
    authorized: bool,
) -> None:
    task_map = intent["task_map"]
    for task in materializer._topological_tasks(payload["plan"]):
        expected_key = materializer._task_key(payload, task["id"])
        rows = conn.execute(
            "SELECT * FROM tasks WHERE idempotency_key = ? ORDER BY created_at, id",
            (expected_key,),
        ).fetchall()
        if len(rows) != 1 or rows[0]["id"] != task_map[task["id"]]:
            raise ExecutionError(
                "EXECUTION_TASK_IDENTITY_DRIFT", "bound implementation task identity drifted"
            )
        row = rows[0]
        expected_body = (
            _authorized_task_body(payload, task)
            if authorized
            else materializer._task_body(payload, task)
        )
        if (
            row["idempotency_key"] != expected_key
            or row["title"] != task["title"]
            or row["body"] != expected_body
            or row["workspace_kind"] != task["workspace"]
            or row["created_by"] != "verified-pipeline-materializer"
            or row["status"] not in allowed_statuses
            or row["tenant"] != f"verified:{payload['run_id']}"
            or row["assignee"] != task["assignee"]
            or row["expected_role_contract_sha256"]
            != payload["frozen_profiles"][task["assignee"]]["sha256"]
            or row["max_retries"] != 0
            or row["max_runtime_seconds"] != 3600
        ):
            raise ExecutionError(
                "EXECUTION_TASK_DRIFT", "bound implementation task has drifted"
            )
        actual_parents = sorted(
            edge["parent_id"]
            for edge in conn.execute(
                "SELECT parent_id FROM task_links WHERE child_id = ?", (row["id"],)
            ).fetchall()
        )
        expected_parents = sorted(task_map[parent] for parent in task["dependencies"])
        if actual_parents != expected_parents:
            raise ExecutionError(
                "EXECUTION_DEPENDENCY_DRIFT", "bound dependency graph has drifted"
            )


def arm_execution(
    execution_key: str,
    *,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
    _after_graph_armed: Optional[Callable[[], None]] = None,
) -> dict[str, Any]:
    """Atomically arm the exact blocked graph under native parent gating."""
    init_execution_schema(db_path)
    row, intent, payload = _load_execution(execution_key, db_path=db_path)
    if board != row["board"] or board != intent["board"]:
        raise ExecutionError(
            "EXECUTION_BOARD_MISMATCH", "requested board does not match execution authority"
        )
    already_armed = row["status"] == "ARMED"

    from hermes_cli import kanban_db

    board_conn = kanban_db.connect(db_path=Path(kanban_db_path))
    graph_already_armed = False
    try:
        with kanban_db.write_txn(board_conn):
            ordered_tasks = materializer._topological_tasks(payload["plan"])
            observed = {
                task["id"]: board_conn.execute(
                    "SELECT status FROM tasks WHERE id = ?",
                    (intent["task_map"][task["id"]],),
                ).fetchone()
                for task in ordered_tasks
            }
            if any(row is None for row in observed.values()):
                raise ExecutionError(
                    "EXECUTION_TASK_IDENTITY_DRIFT", "bound implementation task is missing"
                )
            all_blocked = all(row["status"] == "blocked" for row in observed.values())
            graph_already_armed = already_armed or not all_blocked
            execution_statuses = {
                "todo", "ready", "running", "review", "done", "blocked", "triage"
            }
            task_ids = [intent["task_map"][task["id"]] for task in ordered_tasks]
            if graph_already_armed:
                _validate_arm_events(
                    board_conn,
                    execution_key=execution_key,
                    task_ids=task_ids,
                )
            else:
                _validate_arm_events(
                    board_conn,
                    execution_key=execution_key,
                    task_ids=task_ids,
                    expected_count=0,
                )
            _validate_bound_graph(
                board_conn,
                intent=intent,
                payload=payload,
                allowed_statuses=execution_statuses if graph_already_armed else {"blocked"},
                authorized=graph_already_armed,
            )
            for task in ordered_tasks:
                task_id = intent["task_map"][task["id"]]
                expected = _expected_armed_status(task)
                current = board_conn.execute(
                    "SELECT status FROM tasks WHERE id = ?", (task_id,)
                ).fetchone()
                assert current is not None
                if graph_already_armed:
                    continue
                changed = board_conn.execute(
                    "UPDATE tasks SET status = ?, body = ?, current_run_id = NULL, "
                    "consecutive_failures = 0, last_failure_error = NULL "
                    "WHERE id = ? AND status = 'blocked'",
                    (expected, _authorized_task_body(payload, task), task_id),
                )
                if changed.rowcount != 1:
                    raise ExecutionError(
                        "EXECUTION_STATUS_DRIFT", "task could not be atomically armed"
                    )
                kanban_db._append_event(
                    board_conn,
                    task_id,
                    "unblocked",
                    {
                        "status": expected,
                        "authority": EXECUTION_CONTROLLER_ID,
                        "execution_key": execution_key,
                    },
                )
        if _after_graph_armed is not None:
            _after_graph_armed()
    finally:
        board_conn.close()

    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            conn.execute(
                "UPDATE execution_outbox SET status = 'ARMED', armed_at = ?, "
                "attempts = attempts + 1, last_error_code = NULL "
                "WHERE idempotency_key = ? AND status = 'PENDING'",
                (controller._now(), execution_key),
            )
        final = conn.execute(
            "SELECT status FROM execution_outbox WHERE idempotency_key = ?",
            (execution_key,),
        ).fetchone()
        assert final is not None
        return {
            "idempotency_key": execution_key,
            "status": final["status"],
            "task_map": intent["task_map"],
            "replayed": already_armed or graph_already_armed,
        }
    finally:
        conn.close()


def record_execution_completion(
    execution_key: str,
    *,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Append a release-inert receipt only after every bound task is done."""
    init_execution_schema(db_path)
    row, intent, payload = _load_execution(execution_key, db_path=db_path)
    if row["status"] != "ARMED":
        raise ExecutionError("EXECUTION_NOT_ARMED", "execution graph is not armed")
    if board != row["board"]:
        raise ExecutionError(
            "EXECUTION_BOARD_MISMATCH", "requested board does not match execution authority"
        )

    from hermes_cli import kanban_db

    board_conn = kanban_db.connect(db_path=Path(kanban_db_path))
    try:
        with kanban_db.write_txn(board_conn):
            _validate_bound_graph(
                board_conn,
                intent=intent,
                payload=payload,
                allowed_statuses={"done"},
                authorized=True,
            )
            task_results: dict[str, dict[str, Any]] = {}
            for task in payload["plan"]["tasks"]:
                task_id = intent["task_map"][task["id"]]
                task_row = board_conn.execute(
                    "SELECT status, result, completed_at FROM tasks WHERE id = ?",
                    (task_id,),
                ).fetchone()
                assert task_row is not None
                task_results[task["id"]] = {
                    "task_id": task_id,
                    "status": task_row["status"],
                    "result": task_row["result"],
                    "completed_at": task_row["completed_at"],
                }
    finally:
        board_conn.close()

    receipt = {
        "schema": EXECUTION_CONTROLLER_ID,
        "execution_key": execution_key,
        "run_id": row["run_id"],
        "plan_sha256": row["plan_sha256"],
        "status": COMPLETION_STATUS,
        "final_task_id": intent["task_map"][payload["plan"]["final_task_id"]],
        "task_results": task_results,
        "boundary": "release review required; no merge, deploy, or release authority",
    }
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            existing = conn.execute(
                "SELECT payload_json FROM execution_completion_receipts "
                "WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if existing is not None:
                if existing["payload_json"] != _canonical(receipt):
                    raise ExecutionError(
                        "EXECUTION_COMPLETION_DRIFT",
                        "existing completion receipt has different immutable bytes",
                    )
                return {**receipt, "replayed": True}
            conn.execute(
                "INSERT INTO execution_completion_receipts "
                "(execution_key, run_id, plan_sha256, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    execution_key,
                    row["run_id"],
                    row["plan_sha256"],
                    _canonical(receipt),
                    controller._now(),
                ),
            )
        return {**receipt, "replayed": False}
    finally:
        conn.close()
