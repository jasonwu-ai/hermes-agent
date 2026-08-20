"""Explicit CEO-approved plan to inert Kanban DAG materialization.

This module is intentionally not wired into review reconciliation or any live
surface.  Callers must first record an immutable intent and then explicitly
project it into a named, caller-supplied Kanban database.  Every projected task
is blocked; a later execution controller owns any authorization to unblock it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable, Mapping, Optional

from plugins.verified_pipeline import controller, review, validators

MATERIALIZER_ID = "verified-pipeline/inert-plan-materializer/v1"
INERT_BOUNDARY = "inert pending execution authorization"


class MaterializationError(RuntimeError):
    """Stable fail-closed error raised by the materialization boundary."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256((_canonical(value) + "\n").encode("utf-8")).hexdigest()


def init_materialization_schema(
    db_path: Optional[str | os.PathLike[str]] = None,
) -> Path:
    path = review.init_review_schema(db_path)
    conn = controller.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS materialization_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                materializer_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS materialization_outbox (
                idempotency_key TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE REFERENCES intakes(run_id),
                source_task_id TEXT NOT NULL UNIQUE,
                board TEXT NOT NULL,
                specification_id TEXT NOT NULL,
                plan_revision INTEGER NOT NULL CHECK (plan_revision BETWEEN 1 AND 3),
                plan_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'DELIVERED')),
                attempts INTEGER NOT NULL DEFAULT 0,
                task_map_json TEXT NOT NULL DEFAULT '{}',
                delivered_at INTEGER,
                last_error_code TEXT
            );

            CREATE TRIGGER IF NOT EXISTS materialization_identity_no_update
            BEFORE UPDATE ON materialization_identity
            BEGIN SELECT RAISE(ABORT, 'materialization identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS materialization_identity_no_delete
            BEFORE DELETE ON materialization_identity
            BEGIN SELECT RAISE(ABORT, 'materialization identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS materialization_outbox_payload_no_update
            BEFORE UPDATE OF idempotency_key, run_id, source_task_id, board,
                specification_id, plan_revision, plan_sha256, payload_json, created_at
            ON materialization_outbox
            BEGIN SELECT RAISE(ABORT, 'materialization intent is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS materialization_outbox_no_delete
            BEFORE DELETE ON materialization_outbox
            BEGIN SELECT RAISE(ABORT, 'materialization outbox is append-only'); END;
            """
        )
        with controller._write_txn(conn):
            conn.execute(
                "INSERT OR IGNORE INTO materialization_identity "
                "(singleton, materializer_id, created_at) VALUES (1, ?, ?)",
                (MATERIALIZER_ID, controller._now()),
            )
        identity = conn.execute(
            "SELECT materializer_id FROM materialization_identity WHERE singleton = 1"
        ).fetchone()
        if identity is None or identity["materializer_id"] != MATERIALIZER_ID:
            raise MaterializationError(
                "MATERIALIZER_IDENTITY_MISMATCH",
                "materialization database identity does not match this implementation",
            )
    finally:
        conn.close()
    return path


def _one(rows: list[sqlite3.Row], code: str, message: str) -> sqlite3.Row:
    if len(rows) != 1:
        raise MaterializationError(code, message)
    return rows[0]


def _approved_payload(
    *,
    run_id: str,
    source_task_id: str,
    db_path: Optional[str | os.PathLike[str]],
) -> dict[str, Any]:
    """Reconstruct and revalidate the complete immutable approval chain."""
    intake = controller.get_intake(run_id, include_artifact=True, db_path=db_path)
    conn = controller.connect(db_path)
    try:
        transition = _one(
            conn.execute(
                "SELECT * FROM review_transitions WHERE run_id = ? "
                "AND source_task_id = ? AND stage = 'ceo'",
                (run_id, source_task_id),
            ).fetchall(),
            "CEO_APPROVAL_NOT_FOUND",
            "exact CEO task has no immutable terminal transition",
        )
        if transition["outcome"] != "CEO_APPROVED":
            raise MaterializationError(
                "CEO_APPROVAL_REQUIRED", "terminal CEO outcome is not approved"
            )
        try:
            terminal = json.loads(transition["payload_json"])
        except json.JSONDecodeError as exc:
            raise MaterializationError(
                "CEO_APPROVAL_INVALID", "CEO transition payload is malformed"
            ) from exc
        if (
            terminal.get("status") != "CEO_APPROVED_PENDING_MATERIALIZATION"
            or terminal.get("run_id") != run_id
            or terminal.get("source_task_id") != source_task_id
            or terminal.get("plan_revision") != transition["plan_revision"]
        ):
            raise MaterializationError(
                "CEO_APPROVAL_INVALID", "CEO transition identity is inconsistent"
            )

        ceo_row = _one(
            conn.execute(
                "SELECT * FROM review_outbox WHERE run_id = ? AND kind = 'ceo_review' "
                "AND task_id = ? AND status = 'DELIVERED'",
                (run_id, source_task_id),
            ).fetchall(),
            "CEO_REQUEST_NOT_FOUND",
            "exact delivered CEO request was not found",
        )
        try:
            ceo_payload = json.loads(ceo_row["payload_json"])
            ceo_request = ceo_payload["request"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise MaterializationError(
                "CEO_REQUEST_INVALID", "CEO request payload is malformed"
            ) from exc
        if (
            ceo_payload.get("schema") != review.REVIEW_CONTROLLER_ID
            or ceo_payload.get("run_id") != run_id
            or ceo_payload.get("kind") != "ceo_review"
            or ceo_payload.get("assignee") != review.CEO_PROFILE
            or ceo_payload.get("plan_revision") != transition["plan_revision"]
            or ceo_payload.get("frozen_profiles") != intake["frozen_profiles"]
        ):
            raise MaterializationError(
                "CEO_REQUEST_INVALID", "CEO request authority binding is inconsistent"
            )
        validators.validate_ceo_request(ceo_request)
        decision = terminal.get("decision")
        validators.validate_ceo_decision(decision, request=ceo_request)
        if decision["decision"] != "APPROVE":
            raise MaterializationError(
                "CEO_APPROVAL_REQUIRED", "CEO decision is not APPROVE"
            )

        da_task_id = ceo_payload.get("source_task_id")
        da_row = _one(
            conn.execute(
                "SELECT * FROM review_outbox WHERE run_id = ? AND kind = 'da_review' "
                "AND task_id = ? AND status = 'DELIVERED'",
                (run_id, da_task_id),
            ).fetchall(),
            "DA_REQUEST_NOT_FOUND",
            "task-bound delivered DA request was not found",
        )
        try:
            da_payload = json.loads(da_row["payload_json"])
            da_request = da_payload["request"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise MaterializationError(
                "DA_REQUEST_INVALID", "DA request payload is malformed"
            ) from exc
        validators.validate_da_request(da_request)
        plan = ceo_request["plan"]
        if (
            da_request["plan"] != plan
            or da_request["plan_sha256"] != ceo_request["plan_sha256"]
            or ceo_request["run_id"] != run_id
            or da_request["run_id"] != run_id
        ):
            raise MaterializationError(
                "PLAN_CUSTODY_MISMATCH", "DA and CEO plan custody does not match"
            )
        plan_request = {
            "schema": "planner-request/v1",
            "run_id": run_id,
            "specification_id": da_request["specification_id"],
            "specification_sha256": da_request["specification_sha256"],
            "plan_revision": da_request["plan_revision"],
            "output_workspace": str(Path(da_request["specification_path"]).parent),
            "prior_findings": da_request["prior_findings"],
        }
        validators.validate_plan(plan, request=plan_request)
        plan_sha = _digest(plan)
        if plan_sha != ceo_request["plan_sha256"]:
            raise MaterializationError(
                "PLAN_CUSTODY_MISMATCH", "approved plan digest is inconsistent"
            )
        frozen = intake["frozen_profiles"]
        missing = sorted({task["assignee"] for task in plan["tasks"]} - set(frozen))
        if missing:
            raise MaterializationError(
                "IMPLEMENTATION_PROFILE_NOT_FROZEN",
                f"implementation profiles are not frozen: {missing}",
            )
        for task in plan["tasks"]:
            digest = frozen[task["assignee"]].get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise MaterializationError(
                    "IMPLEMENTATION_PROFILE_NOT_FROZEN",
                    f"implementation profile digest is invalid: {task['assignee']}",
                )
        if intake["specification_id"] != plan["specification_id"]:
            raise MaterializationError(
                "PLAN_CUSTODY_MISMATCH", "plan specification identity drifted"
            )
        return {
            "schema": MATERIALIZER_ID,
            "run_id": run_id,
            "source_task_id": source_task_id,
            "source_da_task_id": da_task_id,
            # An explicit Kanban DB path carries no board slug in the intake;
            # Kanban's canonical logical identity for that case is ``default``.
            "board": intake["board"] or "default",
            "specification_id": plan["specification_id"],
            "plan_revision": plan["plan_revision"],
            "plan_sha256": plan_sha,
            "plan": plan,
            "frozen_profiles": frozen,
            "boundary": INERT_BOUNDARY,
        }
    except validators.ArtifactValidationError as exc:
        raise MaterializationError(
            "APPROVED_PLAN_INVALID", f"approved artifact validation failed: {exc}"
        ) from exc
    finally:
        conn.close()


def record_materialization_intent(
    *,
    run_id: str,
    source_task_id: str,
    db_path: Optional[str | os.PathLike[str]] = None,
) -> dict[str, Any]:
    """Commit one immutable materialization intent for an exact CEO task."""
    init_materialization_schema(db_path)
    payload = _approved_payload(
        run_id=run_id, source_task_id=source_task_id, db_path=db_path
    )
    key = f"verified-pipeline:{run_id}:materialization:r{payload['plan_revision']}"
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            existing = conn.execute(
                "SELECT * FROM materialization_outbox WHERE idempotency_key = ?",
                (key,),
            ).fetchone()
            if existing is not None:
                if existing["payload_json"] != _canonical(payload):
                    raise MaterializationError(
                        "MATERIALIZATION_INTENT_DRIFT",
                        "existing materialization intent has different immutable bytes",
                    )
                return {
                    "idempotency_key": key,
                    "status": existing["status"],
                    "replayed": True,
                }
            conn.execute(
                "INSERT INTO materialization_outbox "
                "(idempotency_key, run_id, source_task_id, board, specification_id, "
                "plan_revision, plan_sha256, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    key,
                    run_id,
                    source_task_id,
                    payload["board"],
                    payload["specification_id"],
                    payload["plan_revision"],
                    payload["plan_sha256"],
                    _canonical(payload),
                    controller._now(),
                ),
            )
        return {"idempotency_key": key, "status": "PENDING", "replayed": False}
    finally:
        conn.close()


def _topological_tasks(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    tasks = list(plan["tasks"])
    pending = {task["id"]: task for task in tasks}
    order = {task["id"]: index for index, task in enumerate(tasks)}
    emitted: set[str] = set()
    result: list[dict[str, Any]] = []
    while pending:
        ready = [
            task
            for task in pending.values()
            if set(task["dependencies"]) <= emitted
        ]
        if not ready:
            raise MaterializationError(
                "PLAN_DEPENDENCY_DRIFT", "plan dependencies are not a DAG"
            )
        for task in sorted(ready, key=lambda item: order[item["id"]]):
            result.append(task)
            emitted.add(task["id"])
            del pending[task["id"]]
    return result


def _task_key(payload: Mapping[str, Any], plan_task_id: str) -> str:
    return (
        f"verified-pipeline:{payload['run_id']}:implementation:"
        f"r{payload['plan_revision']}:{plan_task_id}"
    )


def _task_body(payload: Mapping[str, Any], task: Mapping[str, Any]) -> str:
    criteria = "\n".join(f"- [ ] {item}" for item in task["acceptance_criteria"])
    dependencies = ", ".join(task["dependencies"]) or "none"
    return (
        "# Verified implementation task (INERT)\n\n"
        f"**Boundary: {INERT_BOUNDARY}. Do not execute, dispatch, merge, deploy, or release.**\n\n"
        f"- Run: `{payload['run_id']}`\n"
        f"- Specification: `{payload['specification_id']}`\n"
        f"- Approved plan revision: `{payload['plan_revision']}`\n"
        f"- Approved plan SHA-256: `{payload['plan_sha256']}`\n"
        f"- Plan task: `{task['id']}`\n"
        f"- Plan dependencies: `{dependencies}`\n\n"
        f"## Goal\n\n{task['goal']}\n\n"
        f"## Deliverable\n\n{task['deliverable']}\n\n"
        f"## Acceptance criteria\n\n{criteria}\n"
    )


def _validate_existing_task(
    conn: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    payload: Mapping[str, Any],
    task: Mapping[str, Any],
    parent_ids: list[str],
) -> None:
    expected_key = _task_key(payload, task["id"])
    if (
        row["idempotency_key"] != expected_key
        or row["title"] != task["title"]
        or row["assignee"] != task["assignee"]
        or row["status"] != "blocked"
        or row["workspace_kind"] != task["workspace"]
        or row["tenant"] != f"verified:{payload['run_id']}"
        or row["expected_role_contract_sha256"]
        != payload["frozen_profiles"][task["assignee"]]["sha256"]
        or INERT_BOUNDARY not in row["body"]
    ):
        raise MaterializationError(
            "MATERIALIZED_TASK_DRIFT", "existing materialized task has drifted"
        )
    actual_parents = [
        item["parent_id"]
        for item in conn.execute(
            "SELECT parent_id FROM task_links WHERE child_id = ? ORDER BY parent_id",
            (row["id"],),
        ).fetchall()
    ]
    if actual_parents != sorted(parent_ids):
        raise MaterializationError(
            "PLAN_DEPENDENCY_DRIFT", "materialized dependency edges have drifted"
        )


def project_materialization(
    idempotency_key: str,
    *,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
    _after_graph_created: Optional[Callable[[Mapping[str, str]], None]] = None,
) -> dict[str, Any]:
    """Project an immutable intent to one fully blocked, exactly-once DAG."""
    init_materialization_schema(db_path)
    conn = controller.connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM materialization_outbox WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if row is None:
            raise MaterializationError(
                "MATERIALIZATION_INTENT_NOT_FOUND", "materialization intent was not found"
            )
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError as exc:
            raise MaterializationError(
                "MATERIALIZATION_INTENT_INVALID", "materialization payload is malformed"
            ) from exc
        live = _approved_payload(
            run_id=row["run_id"],
            source_task_id=row["source_task_id"],
            db_path=db_path,
        )
        if payload != live or row["plan_sha256"] != live["plan_sha256"]:
            raise MaterializationError(
                "MATERIALIZATION_INTENT_DRIFT",
                "materialization intent no longer matches approval custody",
            )
        if board != row["board"] or board != payload["board"]:
            raise MaterializationError(
                "MATERIALIZATION_BOARD_MISMATCH",
                "requested board does not match the approved intake board",
            )
        already_delivered = row["status"] == "DELIVERED"
    finally:
        conn.close()

    from hermes_cli import kanban_db

    path = Path(kanban_db_path)
    kanban_db.init_db(db_path=path)
    board_conn = kanban_db.connect(db_path=path)
    task_map: dict[str, str] = {}
    try:
        with kanban_db.write_txn(board_conn):
            for task in _topological_tasks(payload["plan"]):
                key = _task_key(payload, task["id"])
                rows = board_conn.execute(
                    "SELECT * FROM tasks WHERE idempotency_key = ? ORDER BY created_at, id",
                    (key,),
                ).fetchall()
                if len(rows) > 1:
                    raise MaterializationError(
                        "DUPLICATE_MATERIALIZED_TASK",
                        "more than one task carries a materialization identity",
                    )
                parent_ids = [task_map[parent] for parent in task["dependencies"]]
                if rows:
                    task_id = rows[0]["id"]
                    _validate_existing_task(
                        board_conn,
                        row=rows[0],
                        payload=payload,
                        task=task,
                        parent_ids=parent_ids,
                    )
                else:
                    task_id = kanban_db.create_task(
                        board_conn,
                        title=task["title"],
                        body=_task_body(payload, task),
                        assignee=task["assignee"],
                        created_by="verified-pipeline-materializer",
                        workspace_kind=task["workspace"],
                        tenant=f"verified:{payload['run_id']}",
                        parents=parent_ids,
                        idempotency_key=key,
                        max_runtime_seconds=3600,
                        max_retries=0,
                        require_role_contract=True,
                        expected_role_contract_sha256=payload["frozen_profiles"][
                            task["assignee"]
                        ]["sha256"],
                        initial_status="blocked",
                    )
                    created = board_conn.execute(
                        "SELECT * FROM tasks WHERE id = ?", (task_id,)
                    ).fetchone()
                    assert created is not None
                    _validate_existing_task(
                        board_conn,
                        row=created,
                        payload=payload,
                        task=task,
                        parent_ids=parent_ids,
                    )
                task_map[task["id"]] = task_id
        if _after_graph_created is not None:
            _after_graph_created(dict(task_map))
    finally:
        board_conn.close()

    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            conn.execute(
                "UPDATE materialization_outbox SET status = 'DELIVERED', "
                "task_map_json = ?, delivered_at = ?, attempts = attempts + 1, "
                "last_error_code = NULL WHERE idempotency_key = ? AND status = 'PENDING'",
                (_canonical(task_map), controller._now(), idempotency_key),
            )
        delivered = conn.execute(
            "SELECT status, task_map_json FROM materialization_outbox "
            "WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        assert delivered is not None
        final_map = json.loads(delivered["task_map_json"])
        if final_map != task_map:
            raise MaterializationError(
                "MATERIALIZATION_RECEIPT_DRIFT", "delivered task mapping is inconsistent"
            )
        return {
            "idempotency_key": idempotency_key,
            "status": delivered["status"],
            "task_map": final_map,
            "replayed": already_delivered,
        }
    finally:
        conn.close()
