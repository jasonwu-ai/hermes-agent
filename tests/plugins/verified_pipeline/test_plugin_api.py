from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from fastapi import FastAPI
from fastapi.testclient import TestClient

from hermes_cli import kanban_db
from hermes_cli.dashboard_auth.base import Session, TokenPrincipal
from plugins.verified_pipeline import controller, review
from plugins.verified_pipeline.dashboard.plugin_api import router


def _app_with_human_session() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def attach_verified_session(request, call_next):
        request.state.session = Session(
            user_id="user-jason",
            email="jason@example.test",
            display_name="Jason",
            org_id="org-test",
            provider="test-idp",
            expires_at=2_000_000_000,
            access_token="opaque-access-token",
            refresh_token="opaque-refresh-token",
        )
        return await call_next(request)

    app.include_router(router, prefix="/api/plugins/verified-pipeline")
    return app


def _write_contract(home: Path, profile: str) -> None:
    profile_home = home / "profiles" / profile
    profile_home.mkdir(parents=True)
    path = profile_home / "ROLE_CONTRACT.md"
    path.write_text(
        "\n".join(
            [
                "---",
                "schema: hermes-role-contract/v2",
                f"profile: {profile}",
                "version: 1.0.0",
                "allowed_toolsets:",
                "  - kanban",
                "allowed_tools:",
                "  - kanban_show",
                "workspace_only: true",
                "---",
                f"Bound authority for {profile}.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_authenticated_surface_freezes_profiles_and_projects_one_task(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    _write_contract(home, controller.REVISION_PROFILE)
    _write_contract(home, controller.PLANNER_PROFILE)
    _write_contract(home, review.DA_PROFILE)
    _write_contract(home, review.CEO_PROFILE)
    for profile in controller.IMPLEMENTATION_PROFILES:
        _write_contract(home, profile)
    kanban_path = tmp_path / "kanban.db"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_DB", str(kanban_path))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACES_ROOT", str(tmp_path / "kanban-workspaces"))

    app = _app_with_human_session()
    client = TestClient(app)

    health = client.get("/api/plugins/verified-pipeline/health")
    assert health.status_code == 200
    assert health.json()["schema"] == controller.CONTROLLER_ID

    missing_board = client.post(
        "/api/plugins/verified-pipeline/intakes",
        json={
            "specification_id": "spec-missing-board",
            "revision": 1,
            "artifact_text": "# Missing board\n",
            "board": "does-not-exist",
        },
    )
    assert missing_board.status_code == 404
    assert missing_board.json()["detail"]["code"] == "BOARD_NOT_FOUND"

    rejected = client.post(
        "/api/plugins/verified-pipeline/intakes",
        json={
            "specification_id": "spec-api",
            "revision": 1,
            "artifact_text": "# API specification\n",
            "assignee": "attacker-profile",
        },
    )
    assert rejected.status_code == 422

    created = client.post(
        "/api/plugins/verified-pipeline/intakes",
        json={
            "specification_id": "spec-api",
            "revision": 1,
            "artifact_text": "# API specification\n",
        },
    )
    assert created.status_code == 200
    intake = created.json()
    assert sorted(intake["frozen_profiles"]) == sorted(
        [
            controller.REVISION_PROFILE,
            controller.PLANNER_PROFILE,
            review.DA_PROFILE,
            review.CEO_PROFILE,
            *controller.IMPLEMENTATION_PROFILES,
        ]
    )
    assert intake["authority_ceiling"] == [
        "adversarial_review",
        "plan",
        "revise_specification",
        "strategic_review",
    ]
    assert intake["board"] == kanban_db.DEFAULT_BOARD

    readback = client.get(f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}")
    assert readback.status_code == 200
    assert readback.json()["artifact_text"] == "# API specification\n"

    decided = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/decision",
        headers={"user-agent": "verified-pipeline-test"},
        json={
            "request_id": "api-request-1",
            "action": "approve",
            "decision_nonce": intake["decision_nonce"],
            "artifact_sha256": intake["artifact_sha256"],
        },
    )
    assert decided.status_code == 200
    payload = decided.json()
    assert payload["projection"]["status"] == "DELIVERED"

    reconciled = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/reconcile"
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["projection"]["status"] == "DELIVERED"
    assert reconciled.json()["projection"]["task_id"] == payload["projection"]["task_id"]

    review_idle = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/review/reconcile"
    )
    assert review_idle.status_code == 200
    assert review_idle.json()["advanced"] == []
    assert review_idle.json()["delivered"] == []

    kconn = kanban_db.connect(db_path=kanban_path)
    try:
        rows = kconn.execute("SELECT * FROM tasks").fetchall()
    finally:
        kconn.close()
    assert len(rows) == 1
    assert rows[0]["id"] == payload["projection"]["task_id"]
    assert rows[0]["assignee"] == controller.PLANNER_PROFILE
    assert rows[0]["require_role_contract"] == 1
    assert rows[0]["expected_role_contract_sha256"] == intake["frozen_profiles"][
        controller.PLANNER_PROFILE
    ]["sha256"]

    control_path = home / "plugin-data" / controller.PLUGIN_NAME / "pipeline-control.db"
    conn = sqlite3.connect(control_path)
    try:
        actor = conn.execute("SELECT actor FROM decisions").fetchone()[0]
    finally:
        conn.close()
    assert actor == "dashboard-session:test-idp:user-jason"
    assert actor != "attacker-profile"


def test_intake_allows_optional_revision_and_validator_contracts_to_be_absent(
    tmp_path, monkeypatch
):
    home = tmp_path / "hermes-home"
    for profile in (
        controller.PLANNER_PROFILE,
        review.DA_PROFILE,
        review.CEO_PROFILE,
        *controller.MANDATORY_IMPLEMENTATION_PROFILES,
    ):
        _write_contract(home, profile)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_DB", str(tmp_path / "kanban.db"))
    monkeypatch.setenv(
        "HERMES_KANBAN_WORKSPACES_ROOT", str(tmp_path / "kanban-workspaces")
    )

    app = _app_with_human_session()
    created = TestClient(app).post(
        "/api/plugins/verified-pipeline/intakes",
        json={
            "specification_id": "spec-no-validator",
            "revision": 1,
            "artifact_text": "# Optional Validator is absent\n",
        },
    )

    assert created.status_code == 200
    frozen = created.json()["frozen_profiles"]
    assert controller.REVISION_PROFILE not in frozen
    assert controller.OPTIONAL_IMPLEMENTATION_PROFILES[0] not in frozen
    assert set(controller.MANDATORY_IMPLEMENTATION_PROFILES) <= set(frozen)
    assert created.json()["authority_ceiling"] == [
        "adversarial_review",
        "plan",
        "strategic_review",
    ]
    denied_revision = TestClient(app).post(
        f"/api/plugins/verified-pipeline/intakes/{created.json()['run_id']}/decision",
        headers={"user-agent": "verified-pipeline-test"},
        json={
            "request_id": "revision-without-authority",
            "action": "request_changes",
            "decision_nonce": created.json()["decision_nonce"],
            "artifact_sha256": created.json()["artifact_sha256"],
            "feedback": "This route intentionally has no revision authority.",
        },
    )
    assert denied_revision.status_code == 409
    assert denied_revision.json()["detail"]["code"] == "DECISION_AUTHORITY_UNAVAILABLE"
    approved = TestClient(app).post(
        f"/api/plugins/verified-pipeline/intakes/{created.json()['run_id']}/decision",
        headers={"user-agent": "verified-pipeline-test"},
        json={
            "request_id": "approval-without-optional-contracts",
            "action": "approve",
            "decision_nonce": created.json()["decision_nonce"],
            "artifact_sha256": created.json()["artifact_sha256"],
        },
    )
    assert approved.status_code == 200
    review_idle = TestClient(app).post(
        f"/api/plugins/verified-pipeline/intakes/{created.json()['run_id']}/review/reconcile"
    )
    assert review_idle.status_code == 200
    assert review_idle.json()["advanced"] == []


def test_decision_requires_verified_interactive_session(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    for profile in (
        controller.PLANNER_PROFILE,
        review.DA_PROFILE,
        review.CEO_PROFILE,
        *controller.MANDATORY_IMPLEMENTATION_PROFILES,
    ):
        _write_contract(home, profile)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_DB", str(tmp_path / "kanban.db"))

    app = FastAPI()

    @app.middleware("http")
    async def attach_service_principal_only(request, call_next):
        request.state.session = type(
            "ForgedSession",
            (),
            {
                "user_id": "attacker-selected-user",
                "provider": "attacker-selected-provider",
            },
        )()
        request.state.token_authenticated = True
        request.state.token_principal = TokenPrincipal(
            principal="automation",
            provider="test-token-provider",
            scopes=("verified-pipeline:approve",),
        )
        return await call_next(request)

    app.include_router(router, prefix="/api/plugins/verified-pipeline")
    client = TestClient(app)
    intake = client.post(
        "/api/plugins/verified-pipeline/intakes",
        json={
            "specification_id": "spec-human-only",
            "revision": 1,
            "artifact_text": "# Human approval required\n",
        },
    ).json()
    denied = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/decision",
        headers={"user-agent": "spoofed-human-browser"},
        json={
            "request_id": "service-principal-denied",
            "action": "approve",
            "decision_nonce": intake["decision_nonce"],
            "artifact_sha256": intake["artifact_sha256"],
        },
    )
    assert denied.status_code == 401
    assert denied.json()["detail"]["code"] == "AUTHENTICATED_HUMAN_REQUIRED"


def test_dashboard_manifest_declares_bounded_plugin_surface():
    manifest = json.loads(
        (
            Path(__file__).parents[3]
            / "plugins"
            / "verified_pipeline"
            / "dashboard"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["name"] == "verified-pipeline"
    assert manifest["api"] == "plugin_api.py"
    assert manifest["entry"] == "dist/index.js"
