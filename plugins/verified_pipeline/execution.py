"""Explicit bounded execution authorization for materialized plan DAGs.

Nothing in this module is wired into startup, review reconciliation, dashboard
routes, or dispatch loops.  A trusted caller must record an authorization and
then explicitly project it.  Projection only arms the already-materialized
Kanban DAG; normal Kanban dependency gating owns subsequent execution.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from typing import Any, Callable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from plugins.verified_pipeline import controller, materializer

EXECUTION_CONTROLLER_ID = "verified-pipeline/bounded-execution-controller/v1"
AUTHORIZATION_SCHEMA = "verified-pipeline/authenticated-execution-decision/v1"
EXECUTION_DECISION = "AUTHORIZE_BOUNDED_EXECUTION"
COMPLETION_STATUS = "TASK_GRAPH_COMPLETE_PENDING_RELEASE_REVIEW"
ARMING_STATUS = "ARMING"
ARMED_STATUS = "ARMED"
AUTHORIZED_BOUNDARY = (
    "bounded execution authorized; no merge, deploy, or release authority"
)
BOARD_ARM_RECEIPT_SCHEMA = "verified-pipeline/board-arm-receipt/v1"


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


def _signed_bytes(value: Mapping[str, Any]) -> bytes:
    return (_canonical(value) + "\n").encode("utf-8")


def _authority_public_key(verifier: Mapping[str, Any]) -> Ed25519PublicKey:
    if not isinstance(verifier, Mapping) or set(verifier) != {
        "issuer",
        "key_id",
        "public_key_b64",
    }:
        raise ExecutionError(
            "EXECUTION_AUTHORITY_VERIFIER_INVALID",
            "authority verifier has missing or unknown fields",
        )
    if not all(
        isinstance(verifier[field], str) and verifier[field]
        for field in ("issuer", "key_id", "public_key_b64")
    ):
        raise ExecutionError(
            "EXECUTION_AUTHORITY_VERIFIER_INVALID", "authority verifier is malformed"
        )
    try:
        raw = base64.b64decode(verifier["public_key_b64"], validate=True)
        key = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise ExecutionError(
            "EXECUTION_AUTHORITY_VERIFIER_INVALID", "authority verifier key is invalid"
        ) from exc
    if base64.b64encode(raw).decode("ascii") != verifier["public_key_b64"]:
        raise ExecutionError(
            "EXECUTION_AUTHORITY_VERIFIER_INVALID", "authority verifier key is non-canonical"
        )
    return key


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

            CREATE TABLE IF NOT EXISTS execution_authority_receipts (
                authority_key TEXT PRIMARY KEY,
                materialization_key TEXT NOT NULL UNIQUE
                    REFERENCES materialization_outbox(idempotency_key),
                run_id TEXT NOT NULL UNIQUE REFERENCES intakes(run_id),
                payload_json TEXT NOT NULL,
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

            CREATE TABLE IF NOT EXISTS execution_arm_state (
                execution_key TEXT PRIMARY KEY
                    REFERENCES execution_outbox(idempotency_key),
                state TEXT NOT NULL CHECK (state IN ('PENDING', 'ARMING', 'ARMED')),
                prepared_at INTEGER,
                armed_at INTEGER
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

            CREATE TRIGGER IF NOT EXISTS execution_authority_no_update
            BEFORE UPDATE ON execution_authority_receipts
            BEGIN SELECT RAISE(ABORT, 'execution authority receipt is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS execution_authority_no_delete
            BEFORE DELETE ON execution_authority_receipts
            BEGIN SELECT RAISE(ABORT, 'execution authority receipt is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS execution_outbox_payload_no_update
            BEFORE UPDATE OF idempotency_key, materialization_key, run_id,
                source_task_id, board, plan_sha256, authorization_sha256,
                payload_json, created_at
            ON execution_outbox
            BEGIN SELECT RAISE(ABORT, 'execution authorization is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS execution_outbox_no_delete
            BEFORE DELETE ON execution_outbox
            BEGIN SELECT RAISE(ABORT, 'execution outbox is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS execution_arm_state_identity_no_update
            BEFORE UPDATE OF execution_key ON execution_arm_state
            BEGIN SELECT RAISE(ABORT, 'execution arm state identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS execution_arm_state_no_delete
            BEFORE DELETE ON execution_arm_state
            BEGIN SELECT RAISE(ABORT, 'execution arm state is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS execution_arm_state_transition_guard
            BEFORE UPDATE OF state ON execution_arm_state
            WHEN NOT (
                (OLD.state = 'PENDING' AND NEW.state = 'ARMING') OR
                (OLD.state = 'ARMING' AND NEW.state = 'ARMED') OR
                OLD.state = NEW.state
            )
            BEGIN SELECT RAISE(ABORT, 'invalid execution arm state transition'); END;

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
            conn.execute(
                "INSERT OR IGNORE INTO execution_arm_state "
                "(execution_key, state, prepared_at, armed_at) "
                "SELECT idempotency_key, status, NULL, armed_at FROM execution_outbox"
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


def _load_authorization_receipt(
    authority_key: str,
    *,
    materialization_key: str,
    payload: Mapping[str, Any],
    authority_verifier: Mapping[str, Any],
    db_path: Optional[str | os.PathLike[str]],
) -> dict[str, Any]:
    """Consume, but never create, one authenticated immutable decision receipt."""
    conn = controller.connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM execution_authority_receipts WHERE authority_key = ?",
            (authority_key,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ExecutionError(
            "AUTHENTICATED_EXECUTION_AUTHORITY_REQUIRED",
            "authenticated execution authority receipt was not found",
        )
    try:
        authorization = json.loads(row["payload_json"])
    except json.JSONDecodeError as exc:
        raise ExecutionError(
            "EXECUTION_AUTHORIZATION_INVALID", "authority receipt is malformed"
        ) from exc
    expected_keys = {
        "schema",
        "authority_key",
        "run_id",
        "materialization_key",
        "decision",
        "principal",
        "authentication_context_sha256",
        "issuer",
        "key_id",
        "signature_b64",
    }
    if set(authorization) != expected_keys:
        raise ExecutionError(
            "EXECUTION_AUTHORIZATION_INVALID",
            "authority receipt has missing or unknown fields",
        )
    normalized = dict(authorization)
    auth_context = normalized["authentication_context_sha256"]
    unsigned = {key: value for key, value in normalized.items() if key != "signature_b64"}
    public_key = _authority_public_key(authority_verifier)
    if (
        normalized["schema"] != AUTHORIZATION_SCHEMA
        or normalized["authority_key"] != authority_key
        or normalized["run_id"] != payload["run_id"]
        or normalized["materialization_key"] != materialization_key
        or normalized["decision"] != EXECUTION_DECISION
        or normalized["principal"] != "owner"
        or not isinstance(auth_context, str)
        or re.fullmatch(r"[0-9a-f]{64}", auth_context) is None
        or normalized["issuer"] != authority_verifier.get("issuer")
        or normalized["key_id"] != authority_verifier.get("key_id")
        or row["materialization_key"] != materialization_key
        or row["run_id"] != payload["run_id"]
        or row["payload_json"] != _canonical(normalized)
    ):
        raise ExecutionError(
            "EXECUTION_AUTHORIZATION_INVALID",
            "authenticated authority receipt identity or decision is invalid",
        )
    try:
        signature = base64.b64decode(normalized["signature_b64"], validate=True)
        if base64.b64encode(signature).decode("ascii") != normalized["signature_b64"]:
            raise ValueError("non-canonical signature")
        public_key.verify(signature, _signed_bytes(unsigned))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ExecutionError(
            "EXECUTION_AUTHORIZATION_SIGNATURE_INVALID",
            "authority receipt signature is invalid",
        ) from exc
    return normalized


def record_execution_authorization(
    *,
    materialization_key: str,
    authority_key: str,
    authority_verifier: Mapping[str, Any],
    db_path: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    """Consume an authenticated receipt and commit authorization for one graph."""
    init_execution_schema(db_path)
    row, payload, task_map = _load_materialization(
        materialization_key, db_path=db_path
    )
    normalized = _load_authorization_receipt(
        authority_key,
        materialization_key=materialization_key,
        payload=payload,
        authority_verifier=authority_verifier,
        db_path=db_path,
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
                arm_state = conn.execute(
                    "SELECT state FROM execution_arm_state WHERE execution_key = ?",
                    (execution_key,),
                ).fetchone()
                if arm_state is None:
                    raise ExecutionError(
                        "EXECUTION_STATE_INVALID", "execution arm state is missing"
                    )
                return {
                    "idempotency_key": execution_key,
                    "status": arm_state["state"],
                    "replayed": True,
                }
            try:
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
                conn.execute(
                    "INSERT INTO execution_arm_state (execution_key, state) "
                    "VALUES (?, 'PENDING')",
                    (execution_key,),
                )
            except sqlite3.IntegrityError as exc:
                raise ExecutionError(
                    "EXECUTION_AUTHORIZATION_CONFLICT",
                    "execution authorization conflicts with existing immutable custody",
                ) from exc
        return {"idempotency_key": execution_key, "status": "PENDING", "replayed": False}
    finally:
        conn.close()


def _load_execution(
    execution_key: str,
    *,
    authority_verifier: Mapping[str, Any],
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
        authority_key = intent.get("authorization", {}).get("authority_key")
        if not isinstance(authority_key, str):
            raise ExecutionError(
                "EXECUTION_AUTHORIZATION_INVALID", "authority receipt identity is missing"
            )
        normalized = _load_authorization_receipt(
            authority_key,
            materialization_key=row["materialization_key"],
            payload=payload,
            authority_verifier=authority_verifier,
            db_path=db_path,
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
    authorized_body = inert.replace(
        "# Verified implementation task (INERT)",
        "# Verified implementation task (EXECUTION AUTHORIZED)",
        1,
    ).replace(expected, authorized, 1)
    return (
        authorized_body
        + "\n## Completion evidence\n\n"
        + "Before completing, declare at least one concrete task-workspace output "
        + "through `kanban_complete(artifacts=[...])`. Completion is rejected unless "
        + "durable custody binds exact artifact SHA-256 bytes to this terminal run.\n"
    )


def _init_execution_board_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS verified_execution_arm_receipts (
            execution_key TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS verified_execution_arm_receipt_no_update
        BEFORE UPDATE ON verified_execution_arm_receipts
        BEGIN SELECT RAISE(ABORT, 'execution arm receipt is immutable'); END;

        CREATE TRIGGER IF NOT EXISTS verified_execution_arm_receipt_no_delete
        BEFORE DELETE ON verified_execution_arm_receipts
        BEGIN SELECT RAISE(ABORT, 'execution arm receipt is append-only'); END;
        """
    )


def _board_arm_receipt(
    *, intent: Mapping[str, Any], payload: Mapping[str, Any]
) -> dict[str, Any]:
    task_map = intent["task_map"]
    tasks = []
    for task in materializer._topological_tasks(payload["plan"]):
        task_contract = {
            "task_id": task_map[task["id"]],
            "semantic_key": materializer._task_key(payload, task["id"]),
            "title": task["title"],
            "authorized_body": _authorized_task_body(payload, task),
            "assignee": task["assignee"],
            "tenant": f"verified:{payload['run_id']}",
            "created_by": "verified-pipeline-materializer",
            "workspace_kind": task["workspace"],
            "max_retries": 0,
            "max_runtime_seconds": 3600,
            "role_contract_sha256": payload["frozen_profiles"][task["assignee"]][
                "sha256"
            ],
            "initial_status": _expected_armed_status(task),
            "parent_task_ids": sorted(
                task_map[parent] for parent in task["dependencies"]
            ),
        }
        tasks.append(
            {
                "plan_task_id": task["id"],
                "task_id": task_contract["task_id"],
                "semantic_key": task_contract["semantic_key"],
                "initial_status": task_contract["initial_status"],
                "authorized_body_sha256": hashlib.sha256(
                    task_contract["authorized_body"].encode("utf-8")
                ).hexdigest(),
                "parent_task_ids": task_contract["parent_task_ids"],
                "role_contract_sha256": task_contract["role_contract_sha256"],
                "task_contract_sha256": _digest(task_contract),
            }
        )
    return {
        "schema": BOARD_ARM_RECEIPT_SCHEMA,
        "execution_key": intent["execution_key"],
        "materialization_key": intent["materialization_key"],
        "run_id": intent["run_id"],
        "source_task_id": intent["source_task_id"],
        "board": intent["board"],
        "plan_sha256": intent["plan_sha256"],
        "authorization_sha256": _digest(intent["authorization"]),
        "tasks": tasks,
        "boundary": "bounded execution only; no merge, deploy, or release authority",
    }


def _validate_board_arm_receipt(
    conn: sqlite3.Connection,
    *,
    intent: Mapping[str, Any],
    payload: Mapping[str, Any],
    expected_count: int = 1,
) -> None:
    rows = conn.execute(
        "SELECT payload_json FROM verified_execution_arm_receipts "
        "WHERE execution_key = ?",
        (intent["execution_key"],),
    ).fetchall()
    if len(rows) != expected_count or (
        expected_count == 1
        and rows[0]["payload_json"] != _canonical(_board_arm_receipt(intent=intent, payload=payload))
    ):
        raise ExecutionError(
            "EXECUTION_BOARD_RECEIPT_DRIFT",
            "immutable board-side execution receipt is missing or inconsistent",
        )


def _validate_arm_events(
    conn: sqlite3.Connection,
    *,
    execution_key: str,
    expected_statuses: Mapping[str, str],
    expected_count: int = 1,
) -> None:
    for task_id, expected_status in expected_statuses.items():
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
        expected_payload = {
            "status": expected_status,
            "authority": EXECUTION_CONTROLLER_ID,
            "execution_key": execution_key,
        }
        if len(matching) != expected_count or (
            expected_count == 1 and matching[0] != expected_payload
        ):
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
    authority_verifier: Mapping[str, Any],
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
    _after_graph_armed: Optional[Callable[[], None]] = None,
) -> dict[str, Any]:
    """Recoverably arm the graph: control PREPARE, board COMMIT, control ACK."""
    init_execution_schema(db_path)
    row, intent, payload = _load_execution(
        execution_key, authority_verifier=authority_verifier, db_path=db_path
    )
    if board != row["board"] or board != intent["board"]:
        raise ExecutionError(
            "EXECUTION_BOARD_MISMATCH", "requested board does not match execution authority"
        )
    if row["status"] not in {"PENDING", ARMING_STATUS, ARMED_STATUS}:
        raise ExecutionError(
            "EXECUTION_STATE_INVALID", "execution is not in an armable control state"
        )
    control_conn = controller.connect(db_path)
    try:
        with controller._write_txn(control_conn):
            control_conn.execute(
                "UPDATE execution_arm_state SET state = ?, prepared_at = COALESCE(prepared_at, ?) "
                "WHERE execution_key = ? AND state = 'PENDING'",
                (ARMING_STATUS, controller._now(), execution_key),
            )
            control_status = control_conn.execute(
                "SELECT state FROM execution_arm_state WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if control_status is None or control_status["state"] not in {
                ARMING_STATUS,
                ARMED_STATUS,
            }:
                raise ExecutionError(
                    "EXECUTION_STATE_INVALID",
                    "execution could not enter the recoverable arming state",
                )
            already_armed = control_status["state"] == ARMED_STATUS
    finally:
        control_conn.close()

    from hermes_cli import kanban_db

    board_conn = kanban_db.connect(db_path=Path(kanban_db_path))
    _init_execution_board_schema(board_conn)
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
            expected_statuses = {
                intent["task_map"][task["id"]]: _expected_armed_status(task)
                for task in ordered_tasks
            }
            if graph_already_armed:
                _validate_board_arm_receipt(
                    board_conn, intent=intent, payload=payload
                )
                _validate_arm_events(
                    board_conn,
                    execution_key=execution_key,
                    expected_statuses=expected_statuses,
                )
            else:
                _validate_board_arm_receipt(
                    board_conn, intent=intent, payload=payload, expected_count=0
                )
                _validate_arm_events(
                    board_conn,
                    execution_key=execution_key,
                    expected_statuses=expected_statuses,
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
            if not graph_already_armed:
                board_conn.execute(
                    "INSERT INTO verified_execution_arm_receipts "
                    "(execution_key, payload_json, created_at) VALUES (?, ?, ?)",
                    (
                        execution_key,
                        _canonical(_board_arm_receipt(intent=intent, payload=payload)),
                        controller._now(),
                    ),
                )
        if _after_graph_armed is not None:
            _after_graph_armed()
    finally:
        board_conn.close()

    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            armed_at = controller._now()
            conn.execute(
                "UPDATE execution_arm_state SET state = 'ARMED', "
                "armed_at = COALESCE(armed_at, ?) "
                "WHERE execution_key = ? AND state IN ('ARMING', 'ARMED')",
                (armed_at, execution_key),
            )
            conn.execute(
                "UPDATE execution_outbox SET status = 'ARMED', armed_at = ?, "
                "attempts = attempts + 1, last_error_code = NULL "
                "WHERE idempotency_key = ? AND status = 'PENDING'",
                (armed_at, execution_key),
            )
        final = conn.execute(
            "SELECT o.status, s.state FROM execution_outbox AS o "
            "JOIN execution_arm_state AS s ON s.execution_key = o.idempotency_key "
            "WHERE o.idempotency_key = ?",
            (execution_key,),
        ).fetchone()
        if final is None or final["status"] != ARMED_STATUS or final["state"] != ARMED_STATUS:
            raise ExecutionError(
                "EXECUTION_STATE_INVALID", "execution arming acknowledgement did not converge"
            )
        return {
            "idempotency_key": execution_key,
            "status": final["state"],
            "task_map": intent["task_map"],
            "replayed": already_armed or graph_already_armed,
        }
    finally:
        conn.close()


MAX_IMPLEMENTATION_ARTIFACT_BYTES = 25 * 1024 * 1024

_SAFE_GIT_CONFIG = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "credential.helper=",
    "-c", "core.sshCommand=/bin/false",
    "-c", "core.attributesFile=/dev/null",
    "-c", "core.excludesFile=/dev/null",
)


def _safe_git(
    workspace: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run non-network Git inspection without ambient credentials or executable hooks."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    return subprocess.run(
        ["/usr/bin/git", *_SAFE_GIT_CONFIG, "-C", str(workspace), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=check,
        env=env,
    )


def _sha256_regular_file(path: Path) -> tuple[str, int]:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise ExecutionError("EXECUTION_ARTIFACT_MISSING", "captured artifact is missing") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ExecutionError(
            "EXECUTION_ARTIFACT_UNSAFE", "captured artifact is not a regular file"
        )
    if before.st_size > MAX_IMPLEMENTATION_ARTIFACT_BYTES:
        raise ExecutionError(
            "EXECUTION_ARTIFACT_TOO_LARGE",
            "captured artifact exceeds the 25 MiB implementation-stage limit",
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ExecutionError("EXECUTION_ARTIFACT_DRIFT", "captured artifact cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ExecutionError("EXECUTION_ARTIFACT_DRIFT", "captured artifact changed while opening")
        if opened.st_size > MAX_IMPLEMENTATION_ARTIFACT_BYTES:
            raise ExecutionError(
                "EXECUTION_ARTIFACT_TOO_LARGE",
                "captured artifact exceeds the 25 MiB implementation-stage limit",
            )
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    if size != opened.st_size:
        raise ExecutionError("EXECUTION_ARTIFACT_DRIFT", "captured artifact changed while reading")
    return digest.hexdigest(), size


def _implementation_stage_receipt(
    board_conn: sqlite3.Connection,
    *,
    task_id: str,
    expected_profile: str,
    expected_contract: Mapping[str, Any],
) -> dict[str, Any]:
    events = board_conn.execute(
        "SELECT run_id, payload FROM task_events WHERE task_id = ? AND kind = 'completed' "
        "ORDER BY id DESC LIMIT 2",
        (task_id,),
    ).fetchall()
    if len(events) != 1 or events[0]["run_id"] is None:
        raise ExecutionError(
            "EXECUTION_STAGE_RECEIPT_MISSING",
            "implementation task has no unambiguous terminal run receipt",
        )
    run_id = int(events[0]["run_id"])
    run = board_conn.execute(
        "SELECT profile, status, outcome, ended_at, metadata FROM task_runs "
        "WHERE id = ? AND task_id = ?",
        (run_id, task_id),
    ).fetchone()
    admitted = board_conn.execute(
        "SELECT payload FROM task_events WHERE task_id = ? AND run_id = ? "
        "AND kind = 'role_contract_admitted' ORDER BY id",
        (task_id, run_id),
    ).fetchall()
    if (
        run is None
        or run["profile"] != expected_profile
        or run["status"] != "done"
        or run["outcome"] != "completed"
        or run["ended_at"] is None
        or len(admitted) != 1
    ):
        raise ExecutionError(
            "EXECUTION_STAGE_RUN_MISMATCH",
            "implementation terminal run does not match admitted stage identity",
        )
    try:
        metadata = json.loads(run["metadata"] or "{}")
        admission = metadata["role_contract_admission"]
        admitted_receipt = json.loads(admitted[0]["payload"])
        admission_basis = {
            key: admission[key]
            for key in (
                "schema",
                "profile",
                "version",
                "contract_sha256",
                "configured_toolsets",
                "allowed_toolsets",
                "allowed_tools",
                "workspace_only",
                "mandatory_toolsets",
                "effective_toolsets",
                "task_id",
                "run_id",
                "workspace_path",
                "branch_name",
            )
        }
        computed_admission_id = hashlib.sha256(
            json.dumps(admission_basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        completed_payload = json.loads(events[0]["payload"] or "{}")
        artifact_paths = completed_payload.get("artifacts") or []
        source_commit = metadata.get("source_commit")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ExecutionError(
            "EXECUTION_STAGE_RECEIPT_INVALID",
            "implementation stage receipt is missing or malformed",
        ) from exc
    if (
        admission != admitted_receipt
        or admission.get("receipt_id") != computed_admission_id
        or admission.get("task_id") != task_id
        or admission.get("run_id") != run_id
        or admission.get("profile") != expected_profile
        or admission.get("schema") != expected_contract.get("schema")
        or admission.get("version") != expected_contract.get("version")
        or admission.get("contract_sha256") != expected_contract.get("sha256")
        or (
            expected_profile in controller.IMPLEMENTATION_PROFILES
            and (
                sorted(admission.get("allowed_toolsets") or [])
                != sorted(expected_contract.get("allowed_toolsets") or [])
                or sorted(admission.get("allowed_tools") or [])
                != sorted(expected_contract.get("allowed_tools") or [])
                or admission.get("workspace_only") is not expected_contract.get("workspace_only")
            )
        )
    ):
        raise ExecutionError(
            "EXECUTION_STAGE_RECEIPT_MISMATCH",
            "implementation stage receipt does not match the frozen admitted run",
        )

    task_workspace = board_conn.execute(
        "SELECT workspace_path, branch_name FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()
    admitted_workspace = str(admission.get("workspace_path") or "").strip()
    current_workspace = str(task_workspace["workspace_path"] or "").strip() if task_workspace else ""
    try:
        same_workspace = (
            bool(admitted_workspace)
            and bool(current_workspace)
            and Path(admitted_workspace).resolve() == Path(current_workspace).resolve()
        )
    except OSError:
        same_workspace = False
    if (
        not same_workspace
        or admission.get("branch_name") != (task_workspace["branch_name"] if task_workspace else None)
    ):
        raise ExecutionError(
            "EXECUTION_STAGE_CUSTODY_DRIFT",
            "task workspace or branch changed after role-contract admission",
        )

    # Ordinary Hermes attachments remain the durable evidence path for
    # non-code outputs. Git-backed stages instead bind to an exact commit.
    if not isinstance(artifact_paths, list) or not all(
        isinstance(path, str) and path.strip() for path in artifact_paths
    ):
        raise ExecutionError(
            "EXECUTION_STAGE_RECEIPT_INVALID",
            "completion artifact paths are malformed",
        )
    artifacts: list[dict[str, Any]] = []
    for stored_path in artifact_paths:
        rows = board_conn.execute(
            "SELECT filename, stored_path, size, sha256 FROM task_attachments "
            "WHERE task_id = ? AND stored_path = ? AND uploaded_by = 'kanban_complete' "
            "ORDER BY id DESC LIMIT 2",
            (task_id, stored_path),
        ).fetchall()
        if len(rows) != 1:
            raise ExecutionError(
                "EXECUTION_ARTIFACT_MISSING",
                "completion artifact has no unambiguous durable attachment row",
            )
        attachment = rows[0]
        observed_sha, observed_size = _sha256_regular_file(Path(attachment["stored_path"]))
        if (
            attachment["size"] != observed_size
            or attachment["sha256"] != observed_sha
        ):
            raise ExecutionError(
                "EXECUTION_ARTIFACT_DRIFT",
                "completion artifact bytes or metadata drifted",
            )
        artifacts.append(
            {
                "filename": attachment["filename"],
                "size": observed_size,
                "sha256": observed_sha,
                "source_run_id": run_id,
                "artifact_role": "kanban-attachment",
            }
        )

    normalized_source_commit: Optional[dict[str, Any]] = None
    if source_commit is not None:
        _assert_source_evidence_supported(expected_profile)
        if not isinstance(source_commit, dict):
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_INVALID",
                "source commit receipt must be an object",
            )
        commit_sha = str(source_commit.get("commit_sha") or "").lower()
        repository = _canonical_repository_identity(
            str(source_commit.get("repository") or "").strip()
        )
        if (
            source_commit.get("schema") != "git-source/v1"
            or not repository
            or re.fullmatch(r"[0-9a-f]{40}", commit_sha) is None
        ):
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_INVALID",
                "source commit receipt is missing an exact repository and 40-hex commit",
            )
        normalized_source_commit = {
            "schema": "git-source/v1",
            "repository": repository,
            "commit_sha": commit_sha,
        }
        for optional_key in ("tree_sha", "pull_request_url"):
            value = source_commit.get(optional_key)
            if isinstance(value, str) and value.strip():
                normalized_source_commit[optional_key] = value.strip()
        declared_branch = str(source_commit.get("branch") or "").strip()
        if not declared_branch:
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_INVALID",
                "source commit receipt must name the exact checked-out branch",
            )
        normalized_source_commit["branch"] = declared_branch

        workspace_row = board_conn.execute(
            "SELECT workspace_path, branch_name FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        workspace_path = (
            Path(workspace_row["workspace_path"]).resolve()
            if workspace_row is not None and workspace_row["workspace_path"]
            else None
        )
        if workspace_path is None or not workspace_path.is_dir():
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_MISSING",
                "source commit receipt has no durable task worktree",
            )
        try:
            _safe_git(workspace_path, "cat-file", "-e", f"{commit_sha}^{{commit}}")
            observed_tree = _safe_git(
                workspace_path, "show", "-s", "--format=%T", commit_sha
            ).stdout.strip()
            observed_head = _safe_git(workspace_path, "rev-parse", "HEAD").stdout.strip().lower()
            observed_branch = _safe_git(
                workspace_path, "branch", "--show-current"
            ).stdout.strip()
            tracked_status = _safe_git(
                workspace_path, "status", "--porcelain", "--untracked-files=no"
            ).stdout.strip()
            remote = _safe_git(
                workspace_path, "config", "--get", "remote.origin.url", check=False
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_DRIFT",
                "exact source commit is not present in the task worktree",
            ) from exc
        workspace_uri = _canonical_repository_identity(workspace_path.as_uri())
        remote_identity = _canonical_repository_identity(remote)
        expected_branch = str(workspace_row["branch_name"] or "").strip()
        if observed_head != commit_sha:
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_DRIFT",
                "declared source commit is not the task worktree's exact HEAD",
            )
        if not observed_branch or declared_branch != observed_branch:
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_MISMATCH",
                "declared source branch does not match the checked-out task branch",
            )
        if expected_branch and observed_branch != expected_branch:
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_MISMATCH",
                "checked-out source branch does not match the dispatcher-assigned branch",
            )
        if tracked_status:
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_DIRTY",
                "task worktree index or tracked files differ from the declared HEAD",
            )
        if repository not in {workspace_uri, remote_identity}:
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_MISMATCH",
                "source repository does not match the task worktree or its origin",
            )
        declared_tree = normalized_source_commit.get("tree_sha")
        if declared_tree is not None and declared_tree.lower() != observed_tree.lower():
            raise ExecutionError(
                "EXECUTION_SOURCE_RECEIPT_DRIFT",
                "declared source tree does not match the exact commit",
            )
        normalized_source_commit["tree_sha"] = observed_tree

    if not artifacts and normalized_source_commit is None:
        raise ExecutionError(
            "EXECUTION_STAGE_RECEIPT_MISSING",
            "implementation stage produced neither a durable artifact nor an exact Git commit",
        )
    return {
        "task_id": task_id,
        "run_id": run_id,
        "profile": expected_profile,
        "role_contract_sha256": admission["contract_sha256"],
        "admission_receipt_id": admission["receipt_id"],
        "artifacts": artifacts,
        "source_commit": normalized_source_commit,
    }


def _implementation_role(profile: str) -> str:
    return re.sub(r"^\d+-", "", profile).lower()


def _assert_source_evidence_supported(profile: str) -> None:
    raise ExecutionError(
        "EXECUTION_EXECUTABLE_EVIDENCE_UNSUPPORTED",
        "source-commit evidence requires a separately admitted sandboxed execution capability",
    )


def _canonical_repository_identity(value: str) -> str:
    text = value.strip()
    patterns = (
        r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
        r"ssh://git@github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
        r"git@github\.com:([^/]+/[^/]+?)(?:\.git)?$",
        r"([^/\s]+/[^/\s]+)",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).removesuffix(".git").lower()
    return text


def _validate_source_lineage(
    board_conn: sqlite3.Connection,
    *,
    plan: Mapping[str, Any],
    task_results: Mapping[str, Mapping[str, Any]],
) -> Optional[dict[str, Any]]:
    """Bind Git-backed stages and return the source candidate at the final task."""
    effective_sources: dict[str, Optional[dict[str, Any]]] = {}
    for task in materializer._topological_tasks(plan):
        child_receipt = task_results[task["id"]]["stage_receipt"]
        child_source = child_receipt["source_commit"]
        parent_sources = [
            effective_sources[parent]
            for parent in task["dependencies"]
            if effective_sources[parent] is not None
        ]
        if not parent_sources:
            effective_sources[task["id"]] = child_source
            continue
        role = _implementation_role(task["assignee"])
        parent_identities = {
            (source["repository"], source["commit_sha"]) for source in parent_sources
        }
        if child_source is None:
            if role != "release" or len(parent_identities) != 1:
                raise ExecutionError(
                    "EXECUTION_SOURCE_LINEAGE_MISSING",
                    "Git-backed predecessor requires one exact successor source receipt",
                )
            effective_sources[task["id"]] = parent_sources[0]
            continue
        repositories = {source["repository"] for source in parent_sources}
        repositories.add(child_source["repository"])
        if len(repositories) != 1:
            raise ExecutionError(
                "EXECUTION_SOURCE_LINEAGE_MISMATCH",
                "source repository identity diverges across dependent stages",
            )
        if role == "test":
            parent_commits = {source["commit_sha"] for source in parent_sources}
            if len(parent_commits) != 1 or child_source["commit_sha"] not in parent_commits:
                raise ExecutionError(
                    "EXECUTION_SOURCE_LINEAGE_MISMATCH",
                    "Test must attest the exact unchanged predecessor commit",
                )
            effective_sources[task["id"]] = child_source
            continue
        task_row = board_conn.execute(
            "SELECT workspace_path FROM tasks WHERE id = ?",
            (child_receipt["task_id"],),
        ).fetchone()
        child_workspace = (
            Path(task_row["workspace_path"]).resolve()
            if task_row is not None and task_row["workspace_path"]
            else None
        )
        if child_workspace is None:
            raise ExecutionError(
                "EXECUTION_SOURCE_LINEAGE_MISSING",
                "source lineage has no successor worktree",
            )
        for parent_source in parent_sources:
            try:
                result = _safe_git(
                    child_workspace,
                    "merge-base",
                    "--is-ancestor",
                    parent_source["commit_sha"],
                    child_source["commit_sha"],
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ExecutionError(
                    "EXECUTION_SOURCE_LINEAGE_DRIFT",
                    "source ancestry could not be verified",
                ) from exc
            if result.returncode != 0:
                raise ExecutionError(
                    "EXECUTION_SOURCE_LINEAGE_MISMATCH",
                    "successor source does not descend from every Git-backed predecessor",
                )
        effective_sources[task["id"]] = child_source
    return effective_sources.get(plan["final_task_id"])


def _validated_completion_receipt_on_board_connection(
    execution_key: str,
    *,
    board: str,
    authority_verifier: Mapping[str, Any],
    db_path: Optional[str | os.PathLike[str]],
    board_conn: sqlite3.Connection,
    require_existing: bool = False,
) -> dict[str, Any]:
    """Reconstruct exact completion using an already transaction-bound board."""
    row, intent, payload = _load_execution(
        execution_key, authority_verifier=authority_verifier, db_path=db_path
    )
    state_conn = controller.connect(db_path)
    try:
        arm_state = state_conn.execute(
            "SELECT state FROM execution_arm_state WHERE execution_key = ?",
            (execution_key,),
        ).fetchone()
    finally:
        state_conn.close()
    if (
        row["status"] != ARMED_STATUS
        or arm_state is None
        or arm_state["state"] != ARMED_STATUS
    ):
        raise ExecutionError("EXECUTION_NOT_ARMED", "execution graph is not armed")
    if board != row["board"]:
        raise ExecutionError(
            "EXECUTION_BOARD_MISMATCH", "requested board does not match execution authority"
        )

    _validate_board_arm_receipt(board_conn, intent=intent, payload=payload)
    _validate_arm_events(
        board_conn,
        execution_key=execution_key,
        expected_statuses={
            intent["task_map"][task["id"]]: _expected_armed_status(task)
            for task in materializer._topological_tasks(payload["plan"])
        },
    )
    _validate_bound_graph(
        board_conn,
        intent=intent,
        payload=payload,
        allowed_statuses={"done"},
        authorized=True,
    )
    task_results: dict[str, dict[str, Any]] = {}
    for task in materializer._topological_tasks(payload["plan"]):
        task_id = intent["task_map"][task["id"]]
        task_row = board_conn.execute(
            "SELECT status, result, completed_at FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        assert task_row is not None
        stage_receipt = _implementation_stage_receipt(
            board_conn,
            task_id=task_id,
            expected_profile=task["assignee"],
            expected_contract=payload["frozen_profiles"][task["assignee"]],
        )
        task_results[task["id"]] = {
            "task_id": task_id,
            "status": task_row["status"],
            "result": task_row["result"],
            "completed_at": task_row["completed_at"],
            "stage_receipt": stage_receipt,
        }
    source_candidate = _validate_source_lineage(
        board_conn,
        plan=payload["plan"],
        task_results=task_results,
    )
    receipt = {
        "schema": EXECUTION_CONTROLLER_ID,
        "execution_key": execution_key,
        "run_id": row["run_id"],
        "plan_sha256": row["plan_sha256"],
        "status": COMPLETION_STATUS,
        "final_task_id": intent["task_map"][payload["plan"]["final_task_id"]],
        "task_results": task_results,
        "source_candidate": source_candidate,
        "boundary": "release review required; no merge, deploy, or release authority",
    }
    if require_existing:
        receipt_conn = controller.connect(db_path)
        try:
            existing = receipt_conn.execute(
                "SELECT payload_json FROM execution_completion_receipts "
                "WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
        finally:
            receipt_conn.close()
        if existing is None or existing["payload_json"] != _canonical(receipt):
            raise ExecutionError(
                "EXECUTION_COMPLETION_DRIFT",
                "stored completion receipt does not match the locked board",
            )
    return receipt


def record_execution_completion(
    execution_key: str,
    *,
    board: str,
    authority_verifier: Mapping[str, Any],
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Append a release-inert receipt only after every bound task is done."""
    init_execution_schema(db_path)
    from hermes_cli import kanban_db

    board_conn = kanban_db.connect(db_path=Path(kanban_db_path))
    _init_execution_board_schema(board_conn)
    try:
        with kanban_db.write_txn(board_conn):
            receipt = _validated_completion_receipt_on_board_connection(
                execution_key,
                board=board,
                authority_verifier=authority_verifier,
                db_path=db_path,
                board_conn=board_conn,
            )
    finally:
        board_conn.close()
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
                    receipt["run_id"],
                    receipt["plan_sha256"],
                    _canonical(receipt),
                    controller._now(),
                ),
            )
        return {**receipt, "replayed": False}
    finally:
        conn.close()
