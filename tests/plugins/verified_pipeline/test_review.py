from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_cli import kanban_db
from plugins.verified_pipeline import controller, execution, materializer, review, validators


FROZEN = {
    profile: {
        "schema": "hermes-role-contract/v2",
        "version": "1.0.0",
        "sha256": digest * 64,
    }
    for profile, digest in (
        (controller.REVISION_PROFILE, "a"),
        (controller.PLANNER_PROFILE, "b"),
        (review.DA_PROFILE, "c"),
        (review.CEO_PROFILE, "d"),
        ("02-researcher", "e"),
        ("09-test", "f"),
    )
}
ARTIFACT = b"# Exact specification\n\nBuild one bounded, reviewed plan.\n"
AUTHORITY_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
AUTHORITY_VERIFIER = {
    "issuer": "verified-pipeline-test-auth-adapter",
    "key_id": "test-ed25519-1",
    "public_key_b64": base64.b64encode(
        AUTHORITY_PRIVATE_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii"),
}


def _setup(tmp_path: Path, *, frozen=FROZEN, authority=None):
    control_db = tmp_path / "control.db"
    kanban_db_path = tmp_path / "kanban.db"
    workspaces = tmp_path / "workspaces"
    if authority is None:
        authority = [
            "plan",
            "revise_specification",
            "adversarial_review",
            "strategic_review",
        ]
    intake = controller.register_intake(
        specification_id="spec-review",
        revision=1,
        artifact_bytes=ARTIFACT,
        frozen_profiles=frozen,
        authority_ceiling=authority,
        db_path=control_db,
    )
    decision = controller.record_decision(
        run_id=intake["run_id"],
        request_id="review-decision-1",
        action="approve",
        actor="dashboard-session:test",
        decision_nonce=intake["decision_nonce"],
        artifact_sha256=intake["artifact_sha256"],
        db_path=control_db,
    )
    receipt = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        kanban_db_path=kanban_db_path,
        workspace_root=workspaces,
    )
    assert receipt["status"] == "DELIVERED"
    return control_db, kanban_db_path, workspaces, intake, receipt["task_id"]


def _task(kanban_path: Path, task_id: str):
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        return kanban_db.get_task(conn, task_id)
    finally:
        conn.close()


def _tasks(kanban_path: Path):
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        return conn.execute("SELECT * FROM tasks ORDER BY created_at, id").fetchall()
    finally:
        conn.close()


def _latest_task(kanban_path: Path, assignee: str):
    rows = [row for row in _tasks(kanban_path) if row["assignee"] == assignee]
    assert rows
    request_name = {
        controller.PLANNER_PROFILE: "planner-request.json",
        review.DA_PROFILE: "da-request.json",
        review.CEO_PROFILE: "ceo-request.json",
    }[assignee]

    def revision(row) -> int:
        request_path = Path(row["workspace_path"]) / request_name
        return json.loads(request_path.read_text(encoding="utf-8"))["plan_revision"]

    return max(rows, key=lambda row: (revision(row), row["id"]))


def _complete(kanban_path: Path, task_id: str) -> None:
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        assert kanban_db.complete_task(
            conn,
            task_id,
            result="task-local review artifacts complete",
            fire_lifecycle_hook=False,
        )
    finally:
        conn.close()


def _block(kanban_path: Path, task_id: str) -> None:
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        assert kanban_db.block_task(
            conn,
            task_id,
            reason="typed DA verdict requires bounded revision",
            kind="needs_input",
        )
    finally:
        conn.close()


def _plan(request: dict, *, dispositions: list[dict] | None = None) -> dict:
    if dispositions is None:
        prior = request["prior_findings"]
        dispositions = [] if prior == "none" else [
            {
                "finding_id": finding["id"],
                "disposition": "Corrected in this bounded revision.",
            }
            for finding in prior
        ]
    return {
        "schema": validators.PLAN_SCHEMA,
        "specification_id": request["specification_id"],
        "specification_sha256": request["specification_sha256"],
        "plan_revision": request["plan_revision"],
        "title": "Bounded implementation plan",
        "summary": "Produce and verify one implementation artifact.",
        "tasks": [
            {
                "id": "build",
                "title": "Build bounded artifact",
                "assignee": "02-researcher",
                "goal": "Implement only the accepted specification.",
                "dependencies": [],
                "deliverable": "A reviewable implementation artifact.",
                "acceptance_criteria": ["Exact specification behavior is verified."],
                "workspace": "worktree",
            },
            {
                "id": "verify",
                "title": "Verify bounded artifact",
                "assignee": "09-test",
                "goal": "Verify only the accepted specification and produced artifact.",
                "dependencies": ["build"],
                "deliverable": "A reproducible qualification receipt.",
                "acceptance_criteria": ["The exact implementation artifact passes qualification."],
                "workspace": "scratch",
            },
        ],
        "final_task_id": "verify",
        "review_dispositions": dispositions,
    }


def _write_plan(workspace: Path) -> dict:
    request = json.loads((workspace / "planner-request.json").read_text(encoding="utf-8"))
    plan = _plan(request)
    (workspace / "plan.md").write_text("# Plan\n\nOne bounded build task.\n", encoding="utf-8")
    (workspace / "plan.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(review._canonical_bytes(plan)).hexdigest()
    (workspace / "validation.md").write_text(f"VALID: {digest}\n", encoding="utf-8")
    return plan


def _da_finding(revision: int) -> dict:
    return {
        "id": f"risk-{revision}",
        "affected_task": "build",
        "affected_criterion": "Exact specification behavior is verified.",
        "causal_sequence": "A missing rollback check permits unsafe continuation.",
        "hidden_assumption": "Rollback is assumed rather than tested.",
        "early_warning": "Rollback test is absent.",
        "likelihood": 4,
        "impact": 4,
        "mitigation": "Add and verify the rollback gate.",
        "classification": "blocking",
        "exceeds_minimum_standard": False,
        "resolved": False,
        "lineage": "newly_discoverable",
        "prior_finding_id": None,
        "novelty_justification": (
            "This failure becomes visible only in the current corrected plan."
            if revision > 1
            else None
        ),
        "confidence": 5,
        "materiality_basis": "safety_invariant",
    }


def _write_da(workspace: Path, *, verdict: str) -> dict:
    request = json.loads((workspace / "da-request.json").read_text(encoding="utf-8"))
    revision = request["plan_revision"]
    findings = [] if verdict == "PASS" else [_da_finding(revision)]
    payload = {
        "schema": validators.DA_VERDICT_SCHEMA,
        "specification_id": request["specification_id"],
        "plan_revision": revision,
        "review_round": revision,
        "verdict": verdict,
        "findings": findings,
        "score": 100 if verdict == "PASS" else 65,
        "most_likely_failure": "An omitted verification gate allows drift.",
        "most_dangerous_failure": "Unreviewed authority reaches execution.",
        "cross_cutting_assumption": "Every transition is task-bound and replay-safe.",
        "escalate_to_jason": verdict == "REVISE" and revision == 3,
        "decision_question": (
            "Should this final-round unresolved risk be accepted?"
            if verdict == "REVISE" and revision == 3
            else None
        ),
    }
    (workspace / "premortem.md").write_text(
        "# Premortem\n\nBounded causal review.\n", encoding="utf-8"
    )
    (workspace / "verdict.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _write_ceo(workspace: Path, decision: str = "APPROVE") -> dict:
    request = json.loads((workspace / "ceo-request.json").read_text(encoding="utf-8"))
    payload = {
        "schema": validators.CEO_DECISION_SCHEMA,
        "specification_id": request["specification_id"],
        "plan_revision": request["plan_revision"],
        "decision": decision,
        "rationale": "The bounded reviewed plan satisfies the exact specification.",
        "required_changes": (
            ["Add an explicit rollback acceptance criterion."]
            if decision == "REJECT_WITH_CHANGES"
            else []
        ),
        "decision_question": (
            "Should the material scope change be accepted?"
            if decision == "NEEDS_JASON_DECISION"
            else None
        ),
        "material_scope_or_risk_change": decision == "NEEDS_JASON_DECISION",
    }
    (workspace / "decision.md").write_text(
        "# CEO decision\n\nBounded strategic review.\n", encoding="utf-8"
    )
    (workspace / "decision.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _advance_planner(control_db, kanban_path, workspaces, intake, task_id):
    workspace = Path(_task(kanban_path, task_id).workspace_path)
    _write_plan(workspace)
    _complete(kanban_path, task_id)
    return review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )


def test_straight_through_review_stops_after_ceo_approval_and_replays(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    first = _advance_planner(
        control_db, kanban_path, workspaces, intake, planner_id
    )
    assert first["advanced"][0]["status"] == "DA_REVIEW_QUEUED"
    da = _latest_task(kanban_path, review.DA_PROFILE)
    assert da["expected_role_contract_sha256"] == FROZEN[review.DA_PROFILE]["sha256"]

    _write_da(Path(da["workspace_path"]), verdict="PASS")
    _complete(kanban_path, da["id"])
    second = review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    assert second["advanced"][0]["status"] == "CEO_REVIEW_QUEUED"
    ceo = _latest_task(kanban_path, review.CEO_PROFILE)
    assert ceo["expected_role_contract_sha256"] == FROZEN[review.CEO_PROFILE]["sha256"]

    _write_ceo(Path(ceo["workspace_path"]), decision="APPROVE")
    _complete(kanban_path, ceo["id"])
    final = review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    assert final["advanced"][0]["status"] == "CEO_APPROVED_PENDING_MATERIALIZATION"
    assert sorted(row["assignee"] for row in _tasks(kanban_path)) == sorted(
        [
            controller.PLANNER_PROFILE,
            review.DA_PROFILE,
            review.CEO_PROFILE,
        ]
    )

    replay = review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    assert replay["advanced"] == []
    assert replay["delivered"] == []
    assert len(_tasks(kanban_path)) == 3


def test_da_revise_projects_one_bounded_planner_correction(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    _advance_planner(control_db, kanban_path, workspaces, intake, planner_id)
    da = _latest_task(kanban_path, review.DA_PROFILE)
    verdict = _write_da(Path(da["workspace_path"]), verdict="REVISE")
    _block(kanban_path, da["id"])

    result = review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    assert result["advanced"][0]["status"] == "PLANNER_REVISION_QUEUED"
    correction = _latest_task(kanban_path, controller.PLANNER_PROFILE)
    assert correction["id"] != planner_id
    assert correction["expected_role_contract_sha256"] == FROZEN[
        controller.PLANNER_PROFILE
    ]["sha256"]
    correction_workspace = Path(correction["workspace_path"])
    request = json.loads(
        (correction_workspace / "planner-request.json").read_text(encoding="utf-8")
    )
    assert request["plan_revision"] == 2
    assert request["prior_findings"] == verdict["findings"]
    assert (correction_workspace / "specification.md").read_bytes() == ARTIFACT
    assert len(_tasks(kanban_path)) == 3


def test_final_round_da_revise_stops_for_jason_without_successor(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    current_planner = planner_id
    for revision in (1, 2, 3):
        _advance_planner(
            control_db, kanban_path, workspaces, intake, current_planner
        )
        da = _latest_task(kanban_path, review.DA_PROFILE)
        assert json.loads(
            (Path(da["workspace_path"]) / "da-request.json").read_text(encoding="utf-8")
        )["plan_revision"] == revision
        _write_da(Path(da["workspace_path"]), verdict="REVISE")
        _block(kanban_path, da["id"])
        result = review.reconcile_review_once(
            intake["run_id"],
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )
        if revision < 3:
            assert result["advanced"][0]["status"] == "PLANNER_REVISION_QUEUED"
            current_planner = _latest_task(
                kanban_path, controller.PLANNER_PROFILE
            )["id"]
        else:
            assert result["advanced"][0]["status"] == "JASON_DECISION_REQUIRED"
    assert len([row for row in _tasks(kanban_path) if row["assignee"] == review.CEO_PROFILE]) == 0
    assert len(_tasks(kanban_path)) == 6


def test_review_projector_recovers_after_task_creation_before_delivery(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    workspace = Path(_task(kanban_path, planner_id).workspace_path)
    _write_plan(workspace)
    _complete(kanban_path, planner_id)
    review.submit_planner_completion(
        run_id=intake["run_id"],
        task_id=planner_id,
        kind="planner_intake",
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    conn = controller.connect(control_db)
    try:
        key = conn.execute(
            "SELECT idempotency_key FROM review_outbox WHERE kind = 'da_review'"
        ).fetchone()[0]
    finally:
        conn.close()

    class InjectedCrash(BaseException):
        pass

    def crash(_task_id: str) -> None:
        raise InjectedCrash()

    with pytest.raises(InjectedCrash):
        review.project_review_outbox(
            key,
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
            _after_task_created=crash,
        )
    created = _latest_task(kanban_path, review.DA_PROFILE)
    conn = controller.connect(control_db)
    try:
        row = conn.execute(
            "SELECT status, task_id FROM review_outbox WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
        assert dict(row) == {"status": "PENDING", "task_id": None}
    finally:
        conn.close()

    replay = review.project_review_outbox(
        key,
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    assert replay["status"] == "DELIVERED"
    assert replay["task_id"] == created["id"]
    assert len(_tasks(kanban_path)) == 2


def test_review_schema_identity_and_source_transition_fail_closed(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    workspace = Path(_task(kanban_path, planner_id).workspace_path)
    _write_plan(workspace)
    _complete(kanban_path, planner_id)
    review.submit_planner_completion(
        run_id=intake["run_id"],
        task_id=planner_id,
        kind="planner_intake",
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    conn = controller.connect(control_db)
    try:
        row = conn.execute(
            "SELECT idempotency_key, payload_json FROM review_outbox "
            "WHERE kind = 'da_review'"
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["source_task_id"] = "t_forged"
        conn.execute("DROP TRIGGER review_outbox_payload_no_update")
        conn.execute(
            "UPDATE review_outbox SET payload_json = ? WHERE idempotency_key = ?",
            (review._canonical(payload), row["idempotency_key"]),
        )
    finally:
        conn.close()
    with pytest.raises(review.ReviewCoordinationError) as exc:
        review.project_review_outbox(
            row["idempotency_key"],
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )
    assert exc.value.code == "REVIEW_OUTBOX_AUTHORITY_MISMATCH"
    assert not [row for row in _tasks(kanban_path) if row["assignee"] == review.DA_PROFILE]

    other_db = tmp_path / "identity.db"
    review.init_review_schema(other_db)
    conn = controller.connect(other_db)
    try:
        conn.execute("DROP TRIGGER review_identity_no_update")
        conn.execute(
            "UPDATE review_identity SET controller_id = 'incompatible/v9' "
            "WHERE singleton = 1"
        )
    finally:
        conn.close()
    with pytest.raises(review.ReviewCoordinationError) as exc:
        review.init_review_schema(other_db)
    assert exc.value.code == "REVIEW_IDENTITY_MISMATCH"


def test_programming_error_is_not_hidden_as_review_outage(tmp_path, monkeypatch):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    workspace = Path(_task(kanban_path, planner_id).workspace_path)
    _write_plan(workspace)
    _complete(kanban_path, planner_id)
    review.submit_planner_completion(
        run_id=intake["run_id"],
        task_id=planner_id,
        kind="planner_intake",
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    conn = controller.connect(control_db)
    try:
        key = conn.execute(
            "SELECT idempotency_key FROM review_outbox WHERE kind = 'da_review'"
        ).fetchone()[0]
    finally:
        conn.close()

    def broken_create(*args, **kwargs):
        raise TypeError("simulated review projector defect")

    monkeypatch.setattr(kanban_db, "create_task", broken_create)
    with pytest.raises(TypeError, match="simulated review projector defect"):
        review.project_review_outbox(
            key,
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )
    conn = controller.connect(control_db)
    try:
        row = conn.execute(
            "SELECT status, attempts, last_error_code FROM review_outbox "
            "WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
    finally:
        conn.close()
    assert dict(row) == {
        "status": "PENDING",
        "attempts": 0,
        "last_error_code": None,
    }


def test_concurrent_review_projection_creates_exactly_one_successor(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    workspace = Path(_task(kanban_path, planner_id).workspace_path)
    _write_plan(workspace)
    _complete(kanban_path, planner_id)
    review.submit_planner_completion(
        run_id=intake["run_id"],
        task_id=planner_id,
        kind="planner_intake",
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    conn = controller.connect(control_db)
    try:
        key = conn.execute(
            "SELECT idempotency_key FROM review_outbox WHERE kind = 'da_review'"
        ).fetchone()[0]
    finally:
        conn.close()

    def project(_):
        return review.project_review_outbox(
            key,
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(project, range(24)))
    assert {receipt["status"] for receipt in receipts} == {"DELIVERED"}
    assert len({receipt["task_id"] for receipt in receipts}) == 1
    assert len(_tasks(kanban_path)) == 2


def test_task_workspace_drift_blocks_admission_before_successor(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    _advance_planner(control_db, kanban_path, workspaces, intake, planner_id)
    da = _latest_task(kanban_path, review.DA_PROFILE)
    _write_da(Path(da["workspace_path"]), verdict="PASS")
    _complete(kanban_path, da["id"])
    drifted = tmp_path / "drifted"
    drifted.mkdir()
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET workspace_path = ? WHERE id = ?",
                (str(drifted), da["id"]),
            )
    finally:
        conn.close()

    with pytest.raises(review.ReviewCoordinationError) as exc:
        review.reconcile_review_once(
            intake["run_id"],
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )
    assert exc.value.code == "REVIEW_WORKSPACE_DRIFT"
    assert not [row for row in _tasks(kanban_path) if row["assignee"] == review.CEO_PROFILE]


def test_review_projection_stays_on_frozen_board_without_explicit_db_path(
    tmp_path, monkeypatch
):
    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_KANBAN_DB", raising=False)
    monkeypatch.delenv("HERMES_KANBAN_BOARD", raising=False)
    kanban_db.init_db(board=kanban_db.DEFAULT_BOARD)
    kanban_db.create_board("review-frozen")
    control_db = tmp_path / "control.db"
    workspaces = tmp_path / "workspaces"
    intake = controller.register_intake(
        specification_id="spec-board",
        revision=1,
        artifact_bytes=ARTIFACT,
        frozen_profiles=FROZEN,
        authority_ceiling=[
            "plan",
            "revise_specification",
            "adversarial_review",
            "strategic_review",
        ],
        board="review-frozen",
        db_path=control_db,
    )
    decision = controller.record_decision(
        run_id=intake["run_id"],
        request_id="board-decision-1",
        action="approve",
        actor="dashboard-session:test",
        decision_nonce=intake["decision_nonce"],
        artifact_sha256=intake["artifact_sha256"],
        db_path=control_db,
    )
    projected = controller.project_outbox(
        decision["idempotency_key"],
        db_path=control_db,
        workspace_root=workspaces,
    )
    frozen = kanban_db.connect(board="review-frozen")
    default = kanban_db.connect(board=kanban_db.DEFAULT_BOARD)
    try:
        assert kanban_db.get_task(frozen, projected["task_id"]) is not None
        assert kanban_db.get_task(default, projected["task_id"]) is None
        task = kanban_db.get_task(frozen, projected["task_id"])
        assert task is not None
        _write_plan(Path(task.workspace_path))
        assert kanban_db.complete_task(
            frozen,
            task.id,
            result="bounded plan complete",
            fire_lifecycle_hook=False,
        )
    finally:
        frozen.close()
        default.close()

    result = review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        workspace_root=workspaces,
    )
    assert result["advanced"][0]["status"] == "DA_REVIEW_QUEUED"
    frozen = kanban_db.connect(board="review-frozen")
    default = kanban_db.connect(board=kanban_db.DEFAULT_BOARD)
    try:
        assert len(kanban_db.list_tasks(frozen)) == 2
        assert kanban_db.list_tasks(default) == []
    finally:
        frozen.close()
        default.close()


def test_review_requires_decision_time_da_and_ceo_contracts(tmp_path):
    incomplete = {
        controller.REVISION_PROFILE: FROZEN[controller.REVISION_PROFILE],
        controller.PLANNER_PROFILE: FROZEN[controller.PLANNER_PROFILE],
    }
    control_db, kanban_path, workspaces, intake, _ = _setup(
        tmp_path, frozen=incomplete
    )
    with pytest.raises(review.ReviewCoordinationError) as exc:
        review.reconcile_review_once(
            intake["run_id"],
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )
    assert exc.value.code == "REVIEW_PROFILE_INVENTORY_INCOMPLETE"


def test_review_requires_decision_time_authority_ceiling(tmp_path):
    control_db, kanban_path, workspaces, intake, _ = _setup(
        tmp_path,
        authority=["plan", "revise_specification"],
    )
    with pytest.raises(review.ReviewCoordinationError) as exc:
        review.reconcile_review_once(
            intake["run_id"],
            db_path=control_db,
            kanban_db_path=kanban_path,
            workspace_root=workspaces,
        )
    assert exc.value.code == "REVIEW_AUTHORITY_CEILING_INCOMPLETE"


def test_plan_validator_rejects_cycle_and_governance_executor(tmp_path):
    request = {
        "schema": "planner-request/v1",
        "run_id": "run_" + "1" * 24,
        "specification_id": "spec-review",
        "specification_sha256": hashlib.sha256(ARTIFACT).hexdigest(),
        "plan_revision": 1,
        "output_workspace": str(tmp_path),
        "prior_findings": "none",
    }
    plan = _plan(request)
    plan["tasks"][0]["assignee"] = review.CEO_PROFILE
    with pytest.raises(validators.ArtifactValidationError, match="governance"):
        validators.validate_plan(plan, request=request)

    plan = _plan(request)
    plan["tasks"][0]["dependencies"] = ["build"]
    with pytest.raises(validators.ArtifactValidationError, match="depends on itself"):
        validators.validate_plan(plan, request=request)


def _approved_materialization(tmp_path: Path, *, frozen=FROZEN):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(
        tmp_path, frozen=frozen
    )
    _advance_planner(control_db, kanban_path, workspaces, intake, planner_id)
    da = _latest_task(kanban_path, review.DA_PROFILE)
    _write_da(Path(da["workspace_path"]), verdict="PASS")
    _complete(kanban_path, da["id"])
    review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    ceo = _latest_task(kanban_path, review.CEO_PROFILE)
    _write_ceo(Path(ceo["workspace_path"]), decision="APPROVE")
    _complete(kanban_path, ceo["id"])
    terminal = review.reconcile_review_once(
        intake["run_id"],
        db_path=control_db,
        kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    assert terminal["advanced"][0]["status"] == "CEO_APPROVED_PENDING_MATERIALIZATION"
    intent = materializer.record_materialization_intent(
        run_id=intake["run_id"],
        source_task_id=ceo["id"],
        db_path=control_db,
    )
    board = (
        controller.get_intake(intake["run_id"], db_path=control_db)["board"]
        or kanban_db.DEFAULT_BOARD
    )
    return control_db, kanban_path, intake, ceo["id"], board, intent


def _implementation_rows(kanban_path: Path):
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        return conn.execute(
            "SELECT * FROM tasks WHERE created_by = 'verified-pipeline-materializer' "
            "ORDER BY created_at, id"
        ).fetchall()
    finally:
        conn.close()


def test_materializer_projects_exact_blocked_dag_and_replays(tmp_path):
    control_db, kanban_path, intake, ceo_id, board, intent = _approved_materialization(
        tmp_path
    )
    result = materializer.project_materialization(
        intent["idempotency_key"],
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    assert result["status"] == "DELIVERED"
    assert set(result["task_map"]) == {"build", "verify"}
    rows = _implementation_rows(kanban_path)
    assert len(rows) == 2
    assert {row["status"] for row in rows} == {"blocked"}
    assert {row["assignee"] for row in rows} == {"02-researcher", "09-test"}
    assert all(materializer.INERT_BOUNDARY in row["body"] for row in rows)
    assert all(row["tenant"] == f"verified:{intake['run_id']}" for row in rows)
    assert all(row["max_retries"] == 0 for row in rows)
    assert {row["expected_role_contract_sha256"] for row in rows} == {
        FROZEN["02-researcher"]["sha256"],
        FROZEN["09-test"]["sha256"],
    }
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        links = conn.execute(
            "SELECT parent_id, child_id FROM task_links WHERE child_id IN (?, ?)",
            (result["task_map"]["build"], result["task_map"]["verify"]),
        ).fetchall()
    finally:
        conn.close()
    assert [(row["parent_id"], row["child_id"]) for row in links] == [
        (result["task_map"]["build"], result["task_map"]["verify"])
    ]
    assert materializer.record_materialization_intent(
        run_id=intake["run_id"], source_task_id=ceo_id, db_path=control_db
    )["replayed"]
    replay = materializer.project_materialization(
        intent["idempotency_key"],
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    assert replay == {**result, "replayed": True}
    assert len(_implementation_rows(kanban_path)) == 2


def test_materializer_crash_window_and_concurrency_converge(tmp_path):
    control_db, kanban_path, _, _, board, intent = _approved_materialization(tmp_path)

    class InjectedCrash(BaseException):
        pass

    def crash(_mapping):
        raise InjectedCrash()

    with pytest.raises(InjectedCrash):
        materializer.project_materialization(
            intent["idempotency_key"],
            board=board,
            db_path=control_db,
            kanban_db_path=kanban_path,
            _after_graph_created=crash,
        )
    assert len(_implementation_rows(kanban_path)) == 2
    conn = controller.connect(control_db)
    try:
        assert conn.execute(
            "SELECT status FROM materialization_outbox WHERE idempotency_key = ?",
            (intent["idempotency_key"],),
        ).fetchone()[0] == "PENDING"
    finally:
        conn.close()

    def project(_):
        return materializer.project_materialization(
            intent["idempotency_key"],
            board=board,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(project, range(2)))
    assert {result["status"] for result in results} == {"DELIVERED"}
    assert results[0]["task_map"] == results[1]["task_map"]
    assert len(_implementation_rows(kanban_path)) == 2


def test_materializer_rejects_wrong_board_without_partial_graph(tmp_path):
    control_db, kanban_path, _, _, board, intent = _approved_materialization(tmp_path)
    with pytest.raises(materializer.MaterializationError) as exc:
        materializer.project_materialization(
            intent["idempotency_key"],
            board=board + "-wrong",
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "MATERIALIZATION_BOARD_MISMATCH"
    assert _implementation_rows(kanban_path) == []


def test_materializer_requires_frozen_implementation_profiles(tmp_path):
    frozen = {
        key: value
        for key, value in FROZEN.items()
        if key not in {"02-researcher", "09-test"}
    }
    control_db, kanban_path, workspaces, intake, planner_id = _setup(
        tmp_path, frozen=frozen
    )
    _advance_planner(control_db, kanban_path, workspaces, intake, planner_id)
    da = _latest_task(kanban_path, review.DA_PROFILE)
    _write_da(Path(da["workspace_path"]), verdict="PASS")
    _complete(kanban_path, da["id"])
    review.reconcile_review_once(
        intake["run_id"], db_path=control_db, kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    ceo = _latest_task(kanban_path, review.CEO_PROFILE)
    _write_ceo(Path(ceo["workspace_path"]), decision="APPROVE")
    _complete(kanban_path, ceo["id"])
    review.reconcile_review_once(
        intake["run_id"], db_path=control_db, kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    with pytest.raises(materializer.MaterializationError) as exc:
        materializer.record_materialization_intent(
            run_id=intake["run_id"], source_task_id=ceo["id"], db_path=control_db
        )
    assert exc.value.code == "IMPLEMENTATION_PROFILE_NOT_FROZEN"
    assert _implementation_rows(kanban_path) == []


def test_materializer_replay_rejects_dependency_drift(tmp_path):
    control_db, kanban_path, _, _, board, intent = _approved_materialization(tmp_path)
    result = materializer.project_materialization(
        intent["idempotency_key"], board=board, db_path=control_db,
        kanban_db_path=kanban_path,
    )
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute(
                "DELETE FROM task_links WHERE parent_id = ? AND child_id = ?",
                (result["task_map"]["build"], result["task_map"]["verify"]),
            )
    finally:
        conn.close()
    with pytest.raises(materializer.MaterializationError) as exc:
        materializer.project_materialization(
            intent["idempotency_key"], board=board, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "PLAN_DEPENDENCY_DRIFT"


def test_materializer_requires_approved_ceo_terminal_transition(tmp_path):
    control_db, kanban_path, workspaces, intake, planner_id = _setup(tmp_path)
    _advance_planner(control_db, kanban_path, workspaces, intake, planner_id)
    da = _latest_task(kanban_path, review.DA_PROFILE)
    _write_da(Path(da["workspace_path"]), verdict="PASS")
    _complete(kanban_path, da["id"])
    review.reconcile_review_once(
        intake["run_id"], db_path=control_db, kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    ceo = _latest_task(kanban_path, review.CEO_PROFILE)
    _write_ceo(Path(ceo["workspace_path"]), decision="NEEDS_JASON_DECISION")
    _complete(kanban_path, ceo["id"])
    review.reconcile_review_once(
        intake["run_id"], db_path=control_db, kanban_db_path=kanban_path,
        workspace_root=workspaces,
    )
    with pytest.raises(materializer.MaterializationError) as exc:
        materializer.record_materialization_intent(
            run_id=intake["run_id"], source_task_id=ceo["id"], db_path=control_db
        )
    assert exc.value.code == "CEO_APPROVAL_REQUIRED"
    assert _implementation_rows(kanban_path) == []


def test_materialization_intent_is_immutable_and_wrong_source_fails(tmp_path):
    control_db, kanban_path, intake, _, _, intent = _approved_materialization(tmp_path)
    conn = controller.connect(control_db)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="materialization intent is immutable"):
            with controller._write_txn(conn):
                conn.execute(
                    "UPDATE materialization_outbox SET payload_json = '{}' "
                    "WHERE idempotency_key = ?",
                    (intent["idempotency_key"],),
                )
    finally:
        conn.close()
    da = _latest_task(kanban_path, review.DA_PROFILE)
    with pytest.raises(materializer.MaterializationError) as exc:
        materializer.record_materialization_intent(
            run_id=intake["run_id"], source_task_id=da["id"], db_path=control_db
        )
    assert exc.value.code == "CEO_APPROVAL_NOT_FOUND"
    assert _implementation_rows(kanban_path) == []


def test_materializer_rejects_duplicate_semantic_task_identity(tmp_path):
    control_db, kanban_path, _, _, board, intent = _approved_materialization(tmp_path)

    class InjectedCrash(BaseException):
        pass

    with pytest.raises(InjectedCrash):
        materializer.project_materialization(
            intent["idempotency_key"], board=board, db_path=control_db,
            kanban_db_path=kanban_path,
            _after_graph_created=lambda _mapping: (_ for _ in ()).throw(InjectedCrash()),
        )
    rows = _implementation_rows(kanban_path)
    build = next(row for row in rows if row["assignee"] == "02-researcher")
    planner = _latest_task(kanban_path, controller.PLANNER_PROFILE)
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET idempotency_key = ? WHERE id = ?",
                (build["idempotency_key"], planner["id"]),
            )
    finally:
        conn.close()
    with pytest.raises(materializer.MaterializationError) as exc:
        materializer.project_materialization(
            intent["idempotency_key"], board=board, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "DUPLICATE_MATERIALIZED_TASK"


def _persist_execution_authority(
    control_db: Path,
    intake: dict,
    materialization: dict,
    *,
    signing_key: Ed25519PrivateKey = AUTHORITY_PRIVATE_KEY,
) -> dict:
    execution.init_execution_schema(control_db)
    authority_key = f"authenticated-owner:{intake['run_id']}:execute"
    authorization = {
        "schema": execution.AUTHORIZATION_SCHEMA,
        "authority_key": authority_key,
        "run_id": intake["run_id"],
        "materialization_key": materialization["idempotency_key"],
        "decision": execution.EXECUTION_DECISION,
        "principal": "owner",
        "authentication_context_sha256": execution._digest(
            {"adapter": "isolated-test", "authenticated_principal": "owner"}
        ),
        "issuer": AUTHORITY_VERIFIER["issuer"],
        "key_id": AUTHORITY_VERIFIER["key_id"],
    }
    authorization["signature_b64"] = base64.b64encode(
        signing_key.sign(execution._signed_bytes(authorization))
    ).decode("ascii")
    conn = controller.connect(control_db)
    try:
        with controller._write_txn(conn):
            conn.execute(
                "INSERT INTO execution_authority_receipts "
                "(authority_key, materialization_key, run_id, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    authority_key,
                    materialization["idempotency_key"],
                    intake["run_id"],
                    execution._canonical(authorization),
                    controller._now(),
                ),
            )
    finally:
        conn.close()
    return authorization


def _authorized_execution(tmp_path: Path):
    control_db, kanban_path, intake, _, board, materialization = (
        _approved_materialization(tmp_path)
    )
    projected = materializer.project_materialization(
        materialization["idempotency_key"],
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    authorization = _persist_execution_authority(control_db, intake, materialization)
    intent = execution.record_execution_authorization(
        materialization_key=materialization["idempotency_key"],
        authority_key=authorization["authority_key"],
        authority_verifier=AUTHORITY_VERIFIER,
        db_path=control_db,
    )
    return control_db, kanban_path, intake, board, projected, authorization, intent


def test_execution_authorization_is_inert_until_explicit_arm(tmp_path):
    control_db, kanban_path, _, _, projected, authorization, intent = (
        _authorized_execution(tmp_path)
    )
    assert intent["status"] == "PENDING"
    assert {row["status"] for row in _implementation_rows(kanban_path)} == {"blocked"}
    replay = execution.record_execution_authorization(
        materialization_key=authorization["materialization_key"],
        authority_key=authorization["authority_key"],
        authority_verifier=AUTHORITY_VERIFIER,
        db_path=control_db,
    )
    assert replay == {**intent, "replayed": True}
    assert set(projected["task_map"]) == {"build", "verify"}
    conn = controller.connect(control_db)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="authority receipt is immutable"):
            conn.execute(
                "UPDATE execution_authority_receipts SET payload_json = '{}' "
                "WHERE authority_key = ?",
                (authorization["authority_key"],),
            )
        conn.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="authority receipt is append-only"):
            conn.execute(
                "DELETE FROM execution_authority_receipts WHERE authority_key = ?",
                (authorization["authority_key"],),
            )
    finally:
        conn.close()


def test_execution_rejects_db_writer_self_signed_owner_receipt(tmp_path):
    control_db, kanban_path, intake, _, board, materialization = (
        _approved_materialization(tmp_path)
    )
    projected = materializer.project_materialization(
        materialization["idempotency_key"],
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    attacker_key = Ed25519PrivateKey.generate()
    authorization = _persist_execution_authority(
        control_db, intake, materialization, signing_key=attacker_key
    )
    with pytest.raises(execution.ExecutionError) as exc:
        execution.record_execution_authorization(
            materialization_key=materialization["idempotency_key"],
            authority_key=authorization["authority_key"],
            authority_verifier=AUTHORITY_VERIFIER,
            db_path=control_db,
        )
    assert exc.value.code == "EXECUTION_AUTHORIZATION_SIGNATURE_INVALID"
    assert {row["status"] for row in _implementation_rows(kanban_path)} == {"blocked"}
    conn = controller.connect(control_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM execution_outbox").fetchone()[0] == 0
    finally:
        conn.close()
    assert set(projected["task_map"]) == {"build", "verify"}


def test_execution_normalizes_immutable_custody_conflict(tmp_path):
    control_db, kanban_path, intake, _, board, materialization = (
        _approved_materialization(tmp_path)
    )
    materializer.project_materialization(
        materialization["idempotency_key"],
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    authorization = _persist_execution_authority(control_db, intake, materialization)
    conn = controller.connect(control_db)
    try:
        custody = conn.execute(
            "SELECT * FROM materialization_outbox WHERE idempotency_key = ?",
            (materialization["idempotency_key"],),
        ).fetchone()
        assert custody is not None
        with controller._write_txn(conn):
            conn.execute(
                "INSERT INTO execution_outbox "
                "(idempotency_key, materialization_key, run_id, source_task_id, "
                "board, plan_sha256, authorization_sha256, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "conflicting-execution-custody",
                    custody["idempotency_key"],
                    custody["run_id"],
                    custody["source_task_id"],
                    custody["board"],
                    custody["plan_sha256"],
                    "0" * 64,
                    "{}",
                    controller._now(),
                ),
            )
    finally:
        conn.close()
    with pytest.raises(execution.ExecutionError) as exc:
        execution.record_execution_authorization(
            materialization_key=materialization["idempotency_key"],
            authority_key=authorization["authority_key"],
            authority_verifier=AUTHORITY_VERIFIER,
            db_path=control_db,
        )
    assert exc.value.code == "EXECUTION_AUTHORIZATION_CONFLICT"


def test_execution_arm_preserves_native_dependency_gating(tmp_path):
    control_db, kanban_path, _, board, projected, _, intent = _authorized_execution(
        tmp_path
    )
    armed = execution.arm_execution(
        intent["idempotency_key"],
        board=board,
        authority_verifier=AUTHORITY_VERIFIER,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    assert armed["status"] == "ARMED"
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        statuses = {
            row["id"]: row["status"]
            for row in conn.execute(
                "SELECT id, status FROM tasks WHERE id IN (?, ?)",
                (projected["task_map"]["build"], projected["task_map"]["verify"]),
            ).fetchall()
        }
        events = conn.execute(
            "SELECT task_id, payload FROM task_events WHERE kind = 'unblocked' "
            "AND task_id IN (?, ?)",
            (projected["task_map"]["build"], projected["task_map"]["verify"]),
        ).fetchall()
        arm_receipt = conn.execute(
            "SELECT payload_json FROM verified_execution_arm_receipts "
            "WHERE execution_key = ?",
            (intent["idempotency_key"],),
        ).fetchone()
    finally:
        conn.close()
    assert statuses == {
        projected["task_map"]["build"]: "ready",
        projected["task_map"]["verify"]: "todo",
    }
    armed_rows = _implementation_rows(kanban_path)
    assert all(execution.AUTHORIZED_BOUNDARY in row["body"] for row in armed_rows)
    assert all(materializer.INERT_BOUNDARY not in row["body"] for row in armed_rows)
    assert all("Do not execute" not in row["body"] for row in armed_rows)
    assert len(events) == 2
    assert arm_receipt is not None
    assert json.loads(arm_receipt["payload_json"])["schema"] == (
        execution.BOARD_ARM_RECEIPT_SCHEMA
    )
    assert all(
        json.loads(event["payload"])["authority"] == execution.EXECUTION_CONTROLLER_ID
        for event in events
    )
    replay = execution.arm_execution(
        intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
        kanban_db_path=kanban_path,
    )
    assert replay == {**armed, "replayed": True}
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="arm receipt is immutable"):
            conn.execute(
                "UPDATE verified_execution_arm_receipts SET payload_json = '{}' "
                "WHERE execution_key = ?",
                (intent["idempotency_key"],),
            )
        conn.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="arm receipt is append-only"):
            conn.execute(
                "DELETE FROM verified_execution_arm_receipts WHERE execution_key = ?",
                (intent["idempotency_key"],),
            )
    finally:
        conn.close()
    control_conn = controller.connect(control_db)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="invalid execution arm state"):
            control_conn.execute(
                "UPDATE execution_arm_state SET state = 'PENDING' WHERE execution_key = ?",
                (intent["idempotency_key"],),
            )
        control_conn.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="arm state is append-only"):
            control_conn.execute(
                "DELETE FROM execution_arm_state WHERE execution_key = ?",
                (intent["idempotency_key"],),
            )
    finally:
        control_conn.close()


def test_execution_crash_window_and_concurrent_replays_converge(tmp_path):
    control_db, kanban_path, _, board, _, _, intent = _authorized_execution(tmp_path)

    class InjectedCrash(BaseException):
        pass

    with pytest.raises(InjectedCrash):
        execution.arm_execution(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
            _after_graph_armed=lambda: (_ for _ in ()).throw(InjectedCrash()),
        )
    conn = controller.connect(control_db)
    try:
        crash_state = conn.execute(
            "SELECT o.status, s.state FROM execution_outbox AS o "
            "JOIN execution_arm_state AS s ON s.execution_key = o.idempotency_key "
            "WHERE o.idempotency_key = ?",
            (intent["idempotency_key"],),
        ).fetchone()
        assert dict(crash_state) == {"status": "PENDING", "state": execution.ARMING_STATUS}
    finally:
        conn.close()

    def arm(_):
        return execution.arm_execution(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(arm, range(2)))
    assert {result["status"] for result in results} == {"ARMED"}
    assert results[0]["task_map"] == results[1]["task_map"]
    assert len(_implementation_rows(kanban_path)) == 2


def test_execution_completion_requires_all_bound_tasks_done(tmp_path):
    control_db, kanban_path, intake, board, projected, _, intent = (
        _authorized_execution(tmp_path)
    )
    execution.arm_execution(
        intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
        kanban_db_path=kanban_path,
    )
    with pytest.raises(execution.ExecutionError) as exc:
        execution.record_execution_completion(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_TASK_DRIFT"
    _complete(kanban_path, projected["task_map"]["build"])
    progressed_replay = execution.arm_execution(
        intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
        kanban_db_path=kanban_path,
    )
    assert progressed_replay["status"] == "ARMED"
    assert progressed_replay["replayed"] is True
    _complete(kanban_path, projected["task_map"]["verify"])
    def complete_receipt(_):
        return execution.record_execution_completion(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(complete_receipt, range(2)))
    assert {item["replayed"] for item in receipts} == {False, True}
    receipt = next(item for item in receipts if not item["replayed"])
    assert receipt["status"] == execution.COMPLETION_STATUS
    assert receipt["run_id"] == intake["run_id"]
    assert receipt["final_task_id"] == projected["task_map"]["verify"]
    assert set(receipt["task_results"]) == {"build", "verify"}
    assert execution.record_execution_completion(
        intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
        kanban_db_path=kanban_path,
    ) == {**receipt, "replayed": True}


def test_execution_rejects_tampered_arm_receipts_on_replay_and_completion(tmp_path):
    control_db, kanban_path, _, board, projected, _, intent = _authorized_execution(
        tmp_path
    )
    execution.arm_execution(
        intent["idempotency_key"],
        board=board,
        authority_verifier=AUTHORITY_VERIFIER,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    build_id = projected["task_map"]["build"]
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            event = conn.execute(
                "SELECT id FROM task_events WHERE task_id = ? AND kind = 'unblocked'",
                (build_id,),
            ).fetchone()
            assert event is not None
            conn.execute(
                "UPDATE task_events SET payload = ? WHERE id = ?",
                (
                    json.dumps(
                        {
                            "status": "todo",
                            "authority": execution.EXECUTION_CONTROLLER_ID,
                            "execution_key": intent["idempotency_key"],
                        }
                    ),
                    event["id"],
                ),
            )
    finally:
        conn.close()
    with pytest.raises(execution.ExecutionError) as exc:
        execution.arm_execution(
            intent["idempotency_key"],
            board=board,
            authority_verifier=AUTHORITY_VERIFIER,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_ARM_RECEIPT_DRIFT"

    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute(
                "UPDATE task_events SET payload = ? WHERE id = ?",
                (
                    json.dumps(
                        {
                            "status": "ready",
                            "authority": execution.EXECUTION_CONTROLLER_ID,
                            "execution_key": intent["idempotency_key"],
                        }
                    ),
                    event["id"],
                ),
            )
    finally:
        conn.close()
    _complete(kanban_path, build_id)
    _complete(kanban_path, projected["task_map"]["verify"])
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute("DELETE FROM task_events WHERE id = ?", (event["id"],))
    finally:
        conn.close()
    with pytest.raises(execution.ExecutionError) as exc:
        execution.record_execution_completion(
            intent["idempotency_key"],
            board=board,
            authority_verifier=AUTHORITY_VERIFIER,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_ARM_RECEIPT_DRIFT"


def test_execution_rejects_invalid_authority_board_and_dependency_drift(tmp_path):
    control_db, kanban_path, intake, board, projected, authorization, intent = (
        _authorized_execution(tmp_path)
    )
    with pytest.raises(execution.ExecutionError) as exc:
        execution.record_execution_authorization(
            materialization_key=authorization["materialization_key"],
            authority_key="caller-asserted-forged-authority",
            authority_verifier=AUTHORITY_VERIFIER,
            db_path=control_db,
        )
    assert exc.value.code == "AUTHENTICATED_EXECUTION_AUTHORITY_REQUIRED"
    with pytest.raises(execution.ExecutionError) as exc:
        execution.arm_execution(
            intent["idempotency_key"], board=board + "-wrong",
            authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_BOARD_MISMATCH"
    assert {row["status"] for row in _implementation_rows(kanban_path)} == {"blocked"}
    build = next(
        row for row in _implementation_rows(kanban_path)
        if row["id"] == projected["task_map"]["build"]
    )
    planner = _latest_task(kanban_path, controller.PLANNER_PROFILE)
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute("UPDATE tasks SET title = 'drifted' WHERE id = ?", (build["id"],))
    finally:
        conn.close()
    with pytest.raises(execution.ExecutionError) as exc:
        execution.arm_execution(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_TASK_DRIFT"
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute("UPDATE tasks SET title = ? WHERE id = ?", (build["title"], build["id"]))
            conn.execute(
                "UPDATE tasks SET idempotency_key = ? WHERE id = ?",
                (build["idempotency_key"], planner["id"]),
            )
    finally:
        conn.close()
    with pytest.raises(execution.ExecutionError) as exc:
        execution.arm_execution(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_TASK_IDENTITY_DRIFT"
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET idempotency_key = ? WHERE id = ?",
                (planner["idempotency_key"], planner["id"]),
            )
            kanban_db._append_event(
                conn,
                projected["task_map"]["build"],
                "unblocked",
                {
                    "authority": execution.EXECUTION_CONTROLLER_ID,
                    "execution_key": intent["idempotency_key"],
                },
            )
    finally:
        conn.close()
    with pytest.raises(execution.ExecutionError) as exc:
        execution.arm_execution(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_ARM_RECEIPT_DRIFT"
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute(
                "DELETE FROM task_events WHERE task_id = ? AND kind = 'unblocked'",
                (projected["task_map"]["build"],),
            )
            conn.execute(
                "DELETE FROM task_links WHERE parent_id = ? AND child_id = ?",
                (projected["task_map"]["build"], projected["task_map"]["verify"]),
            )
    finally:
        conn.close()
    with pytest.raises(execution.ExecutionError) as exc:
        execution.arm_execution(
            intent["idempotency_key"], board=board, authority_verifier=AUTHORITY_VERIFIER, db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "EXECUTION_DEPENDENCY_DRIFT"
    assert controller.get_intake(intake["run_id"], db_path=control_db)["run_id"] == intake["run_id"]
