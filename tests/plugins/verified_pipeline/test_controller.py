from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from hermes_cli import kanban_db
from plugins.verified_pipeline import controller


FROZEN = {
    controller.REVISION_PROFILE: {
        "schema": "hermes-role-contract/v2",
        "version": "1.0.0",
        "sha256": "a" * 64,
    },
    controller.PLANNER_PROFILE: {
        "schema": "hermes-role-contract/v2",
        "version": "1.0.0",
        "sha256": "b" * 64,
    },
}
ARTIFACT = b"# Exact specification\n\nBuild the bounded thing.\n"


def _register(tmp_path, *, specification_id="spec-alpha", revision=1):
    control_db = tmp_path / "control.db"
    intake = controller.register_intake(
        specification_id=specification_id,
        revision=revision,
        artifact_bytes=ARTIFACT,
        frozen_profiles=FROZEN,
        authority_ceiling=["plan", "revise_specification"],
        db_path=control_db,
    )
    return control_db, intake


def test_intake_rejects_unsafe_implementation_contract(tmp_path):
    unsafe = {
        **FROZEN,
        "02-builder": {
            "schema": "hermes-role-contract/v2",
            "version": "1.0.0",
            "sha256": "c" * 64,
            "allowed_toolsets": ["terminal"],
            "allowed_tools": ["terminal"],
            "workspace_only": False,
        },
    }
    with pytest.raises(controller.PipelineControlError) as exc:
        controller.register_intake(
            specification_id="unsafe-contract",
            revision=1,
            artifact_bytes=ARTIFACT,
            frozen_profiles=unsafe,
            authority_ceiling=["plan"],
            db_path=tmp_path / "control.db",
        )
    assert exc.value.code == "IMPLEMENTATION_PROFILE_AUTHORITY_WIDENED"


def test_intake_rejects_forged_narrow_authority_for_wider_hash_bound_contract(
    tmp_path, monkeypatch
):
    supplied = {
        **FROZEN,
        "02-builder": {
            "schema": "hermes-role-contract/v2",
            "version": "1.0.0",
            "sha256": "c" * 64,
            "allowed_toolsets": ["file", "kanban"],
            "allowed_tools": ["read_file"],
            "workspace_only": True,
        },
    }
    monkeypatch.setattr(
        controller,
        "_installed_implementation_contract",
        lambda _profile: {
            "schema": "hermes-role-contract/v2",
            "version": "1.0.0",
            "sha256": "c" * 64,
            "allowed_toolsets": ["file", "kanban", "terminal"],
            "allowed_tools": ["read_file", "terminal"],
            "workspace_only": False,
        },
    )
    with pytest.raises(controller.PipelineControlError) as exc:
        controller.register_intake(
            specification_id="forged-narrow-contract",
            revision=1,
            artifact_bytes=ARTIFACT,
            frozen_profiles=supplied,
            authority_ceiling=["plan"],
            db_path=tmp_path / "control.db",
        )
    assert exc.value.code == "IMPLEMENTATION_PROFILE_RECEIPT_MISMATCH"


def test_intake_derives_authority_from_exact_installed_contract(
    tmp_path, monkeypatch
):
    home = tmp_path / ".hermes"
    profile = home / "profiles" / "02-builder"
    profile.mkdir(parents=True)
    raw = b"""---
schema: hermes-role-contract/v2
profile: 02-builder
version: 1.0.0
allowed_toolsets:
  - file
  - kanban
allowed_tools:
  - read_file
  - kanban_show
workspace_only: true
---
# Exact Builder contract
Only the exact admitted file and Kanban tools are available.
"""
    profile.joinpath("ROLE_CONTRACT.md").write_bytes(raw)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    frozen = {
        **FROZEN,
        "02-builder": {
            "schema": "hermes-role-contract/v2",
            "version": "1.0.0",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "allowed_toolsets": ["file", "kanban"],
            "allowed_tools": ["kanban_show", "read_file"],
            "workspace_only": True,
        },
    }
    intake = controller.register_intake(
        specification_id="exact-installed-contract",
        revision=1,
        artifact_bytes=ARTIFACT,
        frozen_profiles=frozen,
        authority_ceiling=["plan"],
        db_path=tmp_path / "control.db",
    )
    assert intake["frozen_profiles"]["02-builder"] == frozen["02-builder"]


def _decide(control_db, intake, *, action="approve", request_id="request-1", feedback=None):
    return controller.record_decision(
        run_id=intake["run_id"],
        request_id=request_id,
        action=action,
        actor="dashboard-session:test",
        decision_nonce=intake["decision_nonce"],
        artifact_sha256=intake["artifact_sha256"],
        feedback=feedback,
        db_path=control_db,
    )


def _tasks(kanban_path):
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        return conn.execute("SELECT * FROM tasks ORDER BY created_at, id").fetchall()
    finally:
        conn.close()


def test_approve_projects_exactly_one_bounded_planner_task_and_replays(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    kanban_path = tmp_path / "kanban.db"
    workspaces = tmp_path / "workspaces"

    first = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    replay = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )

    assert first["status"] == "DELIVERED"
    assert replay == {**first, "replayed": True}
    rows = _tasks(kanban_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["assignee"] == controller.PLANNER_PROFILE
    assert row["status"] == "ready"
    assert row["require_role_contract"] == 1
    assert row["expected_role_contract_sha256"] == FROZEN[controller.PLANNER_PROFILE]["sha256"]
    assert row["max_retries"] == 0
    assert json.loads(row["skills"]) == [controller.PLANNER_SKILL]
    assert row["idempotency_key"] == decision["idempotency_key"]
    assert "Do not create downstream tasks" in row["body"]
    artifact_path = workspaces / intake["run_id"] / "specification.md"
    assert artifact_path.read_bytes() == ARTIFACT
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == intake["artifact_sha256"]


def test_request_changes_projects_one_cos_revision_task_with_feedback(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(
        control_db,
        intake,
        action="request_changes",
        request_id="request-changes-1",
        feedback="Clarify the rollback boundary.",
    )
    kanban_path = tmp_path / "kanban.db"

    receipt = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=tmp_path / "workspaces",
    )

    assert receipt["status"] == "DELIVERED"
    rows = _tasks(kanban_path)
    assert len(rows) == 1
    assert rows[0]["assignee"] == controller.REVISION_PROFILE
    assert "Clarify the rollback boundary." in rows[0]["body"]
    assert "Do not approve, plan, create downstream tasks" in rows[0]["body"]


def test_duplicate_decision_request_is_stable_and_conflict_fails_closed(tmp_path):
    control_db, intake = _register(tmp_path)
    first = _decide(control_db, intake)
    replay = _decide(control_db, intake)
    assert replay == {**first, "replayed": True}

    with pytest.raises(controller.PipelineControlError) as exc:
        controller.record_decision(
            run_id=intake["run_id"],
            request_id="request-1",
            action="request_changes",
            actor="dashboard-session:test",
            decision_nonce=intake["decision_nonce"],
            artifact_sha256=intake["artifact_sha256"],
            feedback="Different bytes under the same request id",
            db_path=control_db,
        )
    assert exc.value.code == "REQUEST_ID_CONFLICT"


def test_concurrent_intake_registration_is_replay_stable(tmp_path):
    control_db = tmp_path / "control.db"

    def register(_):
        return controller.register_intake(
            specification_id="spec-concurrent",
            revision=1,
            artifact_bytes=ARTIFACT,
            frozen_profiles=FROZEN,
            authority_ceiling=["plan"],
            db_path=control_db,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(register, range(24)))

    assert len({item["run_id"] for item in results}) == 1
    conn = controller.connect(control_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM intakes").fetchone()[0] == 1
    finally:
        conn.close()


def test_concurrent_projection_creates_exactly_one_task(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    kanban_path = tmp_path / "kanban.db"
    workspaces = tmp_path / "workspaces"

    def project(_):
        return controller.project_outbox(
            decision["idempotency_key"],
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(project, range(24)))

    assert {item["status"] for item in receipts} == {"DELIVERED"}
    assert len({item["task_id"] for item in receipts}) == 1
    assert len(_tasks(kanban_path)) == 1


def test_concurrent_specification_custody_installs_without_overwrite(tmp_path):
    root = tmp_path / "workspaces"
    digest = hashlib.sha256(ARTIFACT).hexdigest()

    def publish(_):
        return controller._safe_workspace(
            workspace_root=root,
            run_id="run_0123456789abcdef01234567",
            artifact_bytes=ARTIFACT,
            artifact_sha256=digest,
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(publish, range(24)))

    artifact_paths = {artifact for _, artifact in results}
    assert len(artifact_paths) == 1
    artifact_path = artifact_paths.pop()
    assert artifact_path.read_bytes() == ARTIFACT
    assert artifact_path.stat().st_nlink == 1
    assert not list(artifact_path.parent.glob(".specification.*.tmp"))


def test_programming_error_is_not_hidden_as_replayable_outage(tmp_path, monkeypatch):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)

    def broken_create(*args, **kwargs):
        raise TypeError("simulated programmer error")

    monkeypatch.setattr(kanban_db, "create_task", broken_create)
    with pytest.raises(TypeError, match="simulated programmer error"):
        controller.project_outbox(
            decision["idempotency_key"],
            db_path=control_db,
            kanban_db_path=tmp_path / "kanban.db",
            workspace_root=tmp_path / "workspaces",
        )

    conn = controller.connect(control_db)
    try:
        row = conn.execute(
            "SELECT status, attempts, last_error_code FROM outbox WHERE idempotency_key = ?",
            (decision["idempotency_key"],),
        ).fetchone()
    finally:
        conn.close()
    assert dict(row) == {"status": "PENDING", "attempts": 0, "last_error_code": None}


def test_kanban_outage_keeps_decision_pending_then_replay_delivers_once(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    unavailable = tmp_path / "is-a-directory"
    unavailable.mkdir()

    pending = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        kanban_db_path=unavailable,
        workspace_root=tmp_path / "workspaces",
    )
    assert pending["status"] == "PENDING"
    assert pending["error_code"] == "KANBAN_UNAVAILABLE"

    kanban_path = tmp_path / "kanban.db"
    delivered = controller.project_run(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=tmp_path / "workspaces",
    )
    assert delivered["status"] == "DELIVERED"
    assert len(_tasks(kanban_path)) == 1


def test_crash_after_task_creation_before_receipt_replays_without_duplicate(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    kanban_path = tmp_path / "kanban.db"

    def crash(_task_id):
        raise RuntimeError("simulated process death before delivery receipt")

    pending = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=tmp_path / "workspaces",
        _after_task_created=crash,
    )
    assert pending["status"] == "PENDING"
    assert len(_tasks(kanban_path)) == 1
    original_task_id = _tasks(kanban_path)[0]["id"]
    kconn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(kconn):
            kconn.execute("UPDATE tasks SET status = 'archived' WHERE id = ?", (original_task_id,))
    finally:
        kconn.close()

    delivered = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=tmp_path / "workspaces",
    )
    assert delivered["status"] == "DELIVERED"
    assert delivered["task_id"] == original_task_id
    assert len(_tasks(kanban_path)) == 1


def test_mutation_and_deletion_of_identity_decision_and_outbox_payload_are_rejected(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    conn = controller.connect(control_db)
    try:
        statements = [
            "UPDATE pipeline_identity SET controller_id = 'evil' WHERE singleton = 1",
            "DELETE FROM pipeline_identity WHERE singleton = 1",
            f"UPDATE intakes SET artifact_sha256 = '{'f' * 64}' WHERE run_id = '{intake['run_id']}'",
            f"DELETE FROM intakes WHERE run_id = '{intake['run_id']}'",
            f"UPDATE decisions SET actor = 'evil' WHERE decision_id = '{decision['decision_id']}'",
            f"DELETE FROM decisions WHERE decision_id = '{decision['decision_id']}'",
            f"UPDATE outbox SET kind = 'specifier_revision' WHERE idempotency_key = '{decision['idempotency_key']}'",
            f"DELETE FROM outbox WHERE idempotency_key = '{decision['idempotency_key']}'",
        ]
        for statement in statements:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(statement)
    finally:
        conn.close()


def test_revision_cannot_be_rebound_to_different_bytes(tmp_path):
    control_db, _ = _register(tmp_path)
    with pytest.raises(controller.PipelineControlError) as exc:
        controller.register_intake(
            specification_id="spec-alpha",
            revision=1,
            artifact_bytes=b"different bytes",
            frozen_profiles=FROZEN,
            authority_ceiling=["plan"],
            db_path=control_db,
        )
    assert exc.value.code == "REVISION_CONFLICT"


def test_wrong_digest_nonce_and_path_like_specification_id_fail_closed(tmp_path):
    control_db, intake = _register(tmp_path)
    with pytest.raises(controller.PipelineControlError) as digest_exc:
        controller.record_decision(
            run_id=intake["run_id"], request_id="wrong-digest", action="approve",
            actor="dashboard-session:test", decision_nonce=intake["decision_nonce"],
            artifact_sha256="f" * 64, db_path=control_db,
        )
    assert digest_exc.value.code == "DECISION_BINDING_MISMATCH"

    with pytest.raises(controller.PipelineControlError) as nonce_exc:
        controller.record_decision(
            run_id=intake["run_id"], request_id="wrong-nonce", action="approve",
            actor="dashboard-session:test", decision_nonce="not-the-nonce",
            artifact_sha256=intake["artifact_sha256"], db_path=control_db,
        )
    assert nonce_exc.value.code == "DECISION_BINDING_MISMATCH"

    with pytest.raises(controller.PipelineControlError) as path_exc:
        controller.register_intake(
            specification_id="../../escape",
            revision=1,
            artifact_bytes=ARTIFACT,
            frozen_profiles=FROZEN,
            authority_ceiling=["plan"],
            db_path=tmp_path / "other.db",
        )
    assert path_exc.value.code == "INVALID_SPECIFICATION_ID"


def test_projector_revalidates_authority_even_if_storage_trigger_is_bypassed(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    conn = controller.connect(control_db)
    try:
        conn.execute("DROP TRIGGER outbox_payload_no_update")
        row = conn.execute(
            "SELECT payload_json FROM outbox WHERE idempotency_key = ?",
            (decision["idempotency_key"],),
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["assignee"] = "99-unbounded"
        conn.execute(
            "UPDATE outbox SET payload_json = ? WHERE idempotency_key = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), decision["idempotency_key"]),
        )
    finally:
        conn.close()

    with pytest.raises(controller.PipelineControlError) as exc:
        controller.project_outbox(
            decision["idempotency_key"],
            db_path=control_db,
            kanban_db_path=tmp_path / "kanban.db",
            workspace_root=tmp_path / "workspaces",
        )
    assert exc.value.code == "OUTBOX_AUTHORITY_MISMATCH"
    assert not (tmp_path / "kanban.db").exists()


def test_symlinked_artifact_is_rejected_even_when_target_bytes_match(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / intake["run_id"]
    workspace.mkdir(parents=True)
    outside = tmp_path / "outside-spec.md"
    outside.write_bytes(ARTIFACT)
    (workspace / "specification.md").symlink_to(outside)

    with pytest.raises(controller.PipelineControlError) as exc:
        controller.project_outbox(
            decision["idempotency_key"],
            db_path=control_db,
            kanban_db_path=tmp_path / "kanban.db",
            workspace_root=workspace_root,
        )
    assert exc.value.code == "ARTIFACT_CUSTODY_MISMATCH"
    assert not (tmp_path / "kanban.db").exists()


def test_preexisting_workspace_bytes_must_match_canonical_artifact(tmp_path):
    control_db, intake = _register(tmp_path)
    decision = _decide(control_db, intake)
    workspace = tmp_path / "workspaces" / intake["run_id"]
    workspace.mkdir(parents=True)
    (workspace / "specification.md").write_bytes(b"tampered")

    with pytest.raises(controller.PipelineControlError) as exc:
        controller.project_outbox(
            decision["idempotency_key"],
            db_path=control_db,
            kanban_db_path=tmp_path / "kanban.db",
            workspace_root=tmp_path / "workspaces",
        )
    assert exc.value.code == "ARTIFACT_CUSTODY_MISMATCH"
    assert not (tmp_path / "kanban.db").exists()


def test_custodied_file_rejects_inode_swap_between_lstat_and_open(tmp_path, monkeypatch):
    artifact = tmp_path / "specification.md"
    replacement = tmp_path / "replacement.md"
    artifact.write_bytes(ARTIFACT)
    replacement.write_bytes(b"replacement")
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if Path(path) == artifact and not swapped:
            swapped = True
            os.replace(replacement, artifact)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(controller.os, "open", swapping_open)
    with pytest.raises(controller.PipelineControlError) as exc:
        controller._read_custodied_file(artifact)
    assert exc.value.code == "ARTIFACT_CUSTODY_MISMATCH"
