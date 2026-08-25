from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys

import psutil
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from hermes_cli.dashboard_auth.base import Session

from scripts import run_verified_pipeline_live_governance_canary as runner


def test_profile_snapshot_allowlist_excludes_live_credentials() -> None:
    assert ".env" not in runner.SAFE_PROFILE_FILES
    assert "auth.json" not in runner.SAFE_PROFILE_FILES


def test_runner_attaches_typed_canary_session_without_host_auth_claim() -> None:
    app = FastAPI()
    runner._attach_canary_authenticated_session(app)

    @app.get("/session")
    def session(request: Request) -> dict[str, str]:
        attached = request.state.session
        assert isinstance(attached, Session)
        return {
            "provider": attached.provider,
            "user_id": attached.user_id,
            "access_token": attached.access_token,
            "refresh_token": attached.refresh_token,
        }

    response = TestClient(app).get("/session")

    assert response.status_code == 200
    assert response.json() == {
        "provider": runner.CANARY_SESSION_PROVIDER,
        "user_id": runner.CANARY_SESSION_USER_ID,
        "access_token": "",
        "refresh_token": "",
    }


def test_runner_uses_controller_canonical_review_workspace_root(tmp_path: Path) -> None:
    class Controller:
        @staticmethod
        def _default_workspace_root() -> Path:
            return tmp_path / "plugin-data" / "verified_pipeline" / "workspaces"

    assert runner._canonical_review_workspace_root(Controller) == (
        tmp_path / "plugin-data" / "verified_pipeline" / "workspaces"
    )


def test_runner_uses_controller_canonical_control_db_path(tmp_path: Path) -> None:
    class Controller:
        @staticmethod
        def _default_db_path() -> Path:
            return tmp_path / "plugin-data" / "verified_pipeline" / "pipeline-control.db"

    assert runner._canonical_control_db_path(Controller) == (
        tmp_path / "plugin-data" / "verified_pipeline" / "pipeline-control.db"
    )


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX ownership and mode contract")
def test_credential_source_requires_owner_only_regular_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    auth_path = tmp_path / "auth.json"
    auth_path.write_text("{}", encoding="utf-8")
    auth_path.chmod(0o600)

    assert runner._validated_credential_auth(tmp_path) == auth_path

    auth_path.chmod(0o640)
    with pytest.raises(RuntimeError, match="owner-only"):
        runner._validated_credential_auth(tmp_path)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX ownership and mode contract")
def test_credential_source_rejects_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    auth_path = source / "auth.json"
    auth_path.write_text("{}", encoding="utf-8")
    auth_path.chmod(0o600)
    linked = tmp_path / "linked"
    os.symlink(source, linked)

    with pytest.raises(RuntimeError, match="must not be a symlink"):
        runner._validated_credential_auth(linked)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX ownership and mode contract")
def test_credential_source_rejects_live_profile_and_ancestor_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_root = tmp_path / "profiles"
    source = live_root / "07-planner"
    source.mkdir(parents=True, mode=0o700)
    auth_path = source / "auth.json"
    auth_path.write_text("{}", encoding="utf-8")
    auth_path.chmod(0o600)
    monkeypatch.setattr(runner, "LIVE_PROFILES_ROOT", live_root)

    with pytest.raises(RuntimeError, match="must not resolve inside live profiles"):
        runner._validated_credential_auth(source)

    alias = tmp_path / "profile-alias"
    alias.symlink_to(live_root, target_is_directory=True)
    with pytest.raises(RuntimeError, match="must not resolve inside live profiles"):
        runner._validated_credential_auth(alias / "07-planner")


def test_canary_decision_identity_is_explicitly_not_host_authenticated() -> None:
    assert runner._canary_decision_identity() == {
        "host_auth_middleware_exercised": False,
        "decision_session_mode": "typed_canary_harness_session",
        "decision_principal": (
            "dashboard-session:verified-pipeline-canary:profile-canary-owner"
        ),
    }


def test_profile_snapshot_scrub_removes_credentials_and_entire_snapshot(
    tmp_path: Path,
) -> None:
    runtime_home = tmp_path / "runtime-home"
    profile = runtime_home / "profiles" / "07-planner"
    profile.mkdir(parents=True)
    (profile / "auth.json").write_text("sensitive", encoding="utf-8")
    retained = runtime_home / "plugin-data" / "receipt.json"
    retained.parent.mkdir(parents=True)
    retained.write_text("{}", encoding="utf-8")

    assert runner._scrub_profile_snapshots(runtime_home) is True
    assert not (runtime_home / "profiles").exists()
    assert retained.is_file()


def test_worker_drain_waits_for_process_exit() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(0.2)"],
        start_new_session=True,
    )
    try:
        runner._drain_worker_process(process.pid, timeout_seconds=3)
        assert not runner._pid_alive(process.pid)
    finally:
        if psutil.pid_exists(process.pid):
            psutil.Process(process.pid).terminate()
        process.wait(timeout=3)
