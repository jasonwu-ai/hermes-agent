from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli.role_contract import (
    RoleContractError,
    admit_role_contract,
    load_role_contract,
)


def _write_profile(root: Path, name: str = "builder") -> Path:
    profile = root / "profiles" / name
    profile.mkdir(parents=True)
    profile.joinpath("config.yaml").write_text(
        """
platform_toolsets:
  cli:
    - file
    - terminal
    - web
""".lstrip(),
        encoding="utf-8",
    )
    return profile


def _write_contract(profile: Path, *, name: str = "builder", allowed=None) -> bytes:
    allowed = allowed or ["file", "terminal"]
    raw = (
        "---\n"
        "schema: hermes-role-contract/v2\n"
        f"profile: {name}\n"
        "version: 1.0.0\n"
        "allowed_toolsets:\n"
        + "".join(f"  - {toolset}\n" for toolset in allowed)
        + "---\n"
        "# Builder authority\n"
        "May modify only the assigned workspace and must complete through Kanban.\n"
    ).encode("utf-8")
    profile.joinpath("ROLE_CONTRACT.md").write_bytes(raw)
    return raw


@pytest.fixture
def board(tmp_path, monkeypatch):
    root = tmp_path / ".hermes"
    root.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return root


def test_exact_bytes_narrow_profile_toolsets_and_bind_receipt(board):
    profile = _write_profile(board)
    raw = _write_contract(profile)

    admitted = admit_role_contract(
        profile,
        "builder",
        ["file", "terminal", "web"],
        task_id="t_exact",
        run_id=17,
        required=True,
    )

    assert admitted is not None
    assert admitted.contract.sha256 == hashlib.sha256(raw).hexdigest()
    assert admitted.contract.raw_size == len(raw)
    assert admitted.effective_toolsets == ("file", "kanban", "terminal")
    receipt = admitted.receipt()
    assert receipt["task_id"] == "t_exact"
    assert receipt["run_id"] == 17
    assert receipt["contract_sha256"] == hashlib.sha256(raw).hexdigest()
    assert len(receipt["receipt_id"]) == 64


def test_required_missing_wrong_profile_and_unavailable_toolset_fail_closed(board):
    profile = _write_profile(board)
    with pytest.raises(RoleContractError, match="required role contract is missing"):
        load_role_contract(profile, "builder", required=True)

    _write_contract(profile, name="reviewer")
    with pytest.raises(RoleContractError, match="does not match assignee"):
        admit_role_contract(
            profile,
            "builder",
            ["file", "terminal", "web"],
            task_id="t_wrong",
            run_id=1,
            required=True,
        )

    _write_contract(profile, allowed=["file", "browser"])
    with pytest.raises(RoleContractError, match="not enabled by the assignee profile: browser"):
        admit_role_contract(
            profile,
            "builder",
            ["file", "terminal", "web"],
            task_id="t_widen",
            run_id=2,
            required=True,
        )


def test_symlink_and_writable_contract_are_rejected(board):
    profile = _write_profile(board)
    target = board / "outside.md"
    target.write_bytes(_write_contract(profile))
    contract = profile / "ROLE_CONTRACT.md"
    contract.unlink()
    contract.symlink_to(target)
    with pytest.raises(RoleContractError, match="must not be a symlink"):
        load_role_contract(profile, "builder", required=True)

    contract.unlink()
    contract.write_bytes(target.read_bytes())
    contract.chmod(0o666)
    with pytest.raises(RoleContractError, match="must not be group/world-writable"):
        load_role_contract(profile, "builder", required=True)


def test_required_missing_blocks_before_spawn_and_closes_run(board):
    _write_profile(board)
    calls = []
    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="must admit",
            assignee="builder",
            require_role_contract=True,
        )
        result = kb.dispatch_once(
            conn,
            spawn_fn=lambda *args, **kwargs: calls.append((args, kwargs)) or 999,
            max_in_progress=1,
        )
        task = kb.get_task(conn, task_id)
        runs = kb.list_runs(conn, task_id)
        events = kb.list_events(conn, task_id)

    assert calls == []
    assert task is not None and task.status == "blocked"
    assert task_id in result.auto_blocked
    assert runs[-1].outcome == "blocked"
    assert "role_contract_admission" in (runs[-1].summary or "")
    assert not any(event.kind == "role_contract_admitted" for event in events)


def test_valid_dispatch_persists_receipt_before_spawn(board):
    profile = _write_profile(board)
    raw = _write_contract(profile)
    observed = {}

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="admit me",
            assignee="builder",
            require_role_contract=True,
            expected_role_contract_sha256=hashlib.sha256(raw).hexdigest(),
        )

        def fake_spawn(task, workspace, **kwargs):
            row = conn.execute(
                "SELECT metadata FROM task_runs WHERE id = ?", (task.current_run_id,)
            ).fetchone()
            observed["metadata_at_spawn"] = json.loads(row["metadata"])
            observed["admission"] = task._role_contract_admission
            return 4242

        result = kb.dispatch_once(conn, spawn_fn=fake_spawn, max_in_progress=1)
        events = kb.list_events(conn, task_id)

    assert result.spawned and result.spawned[0][0] == task_id
    receipt = observed["metadata_at_spawn"]["role_contract_admission"]
    assert receipt["contract_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["effective_toolsets"] == ["file", "kanban", "terminal"]
    assert observed["admission"].receipt_id == receipt["receipt_id"]
    admitted_events = [event for event in events if event.kind == "role_contract_admitted"]
    assert len(admitted_events) == 1
    assert admitted_events[0].run_id == receipt["run_id"]


def test_completion_preserves_spawn_owned_admission_receipt(board):
    profile = _write_profile(board)
    raw = _write_contract(profile)

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="preserve admission",
            assignee="builder",
            require_role_contract=True,
            expected_role_contract_sha256=hashlib.sha256(raw).hexdigest(),
        )
        result = kb.dispatch_once(
            conn,
            spawn_fn=lambda *_args, **_kwargs: 4244,
            max_in_progress=1,
        )
        assert result.spawned and result.spawned[0][0] == task_id
        active = kb.get_task(conn, task_id)
        assert active is not None and active.current_run_id is not None
        run_id = active.current_run_id
        admitted = kb.list_runs(conn, task_id)[-1].metadata["role_contract_admission"]
        assert kb.complete_task(
            conn,
            task_id,
            summary="completed",
            metadata={
                "role_contract_admission": {"receipt_id": "forged"},
                "worker_note": "preserved",
            },
            expected_run_id=run_id,
        )
        closed = kb.list_runs(conn, task_id)[-1]
        events = kb.list_events(conn, task_id)

    assert closed.outcome == "completed"
    assert closed.metadata["role_contract_admission"] == admitted
    assert closed.metadata["worker_note"] == "preserved"
    assert closed.metadata["role_contract_admission"]["receipt_id"] != "forged"
    admitted_event = next(event for event in events if event.kind == "role_contract_admitted")
    completed_event = next(event for event in events if event.kind == "completed")
    assert admitted_event.run_id == completed_event.run_id == run_id


def test_decision_time_contract_digest_mismatch_blocks_before_spawn(board):
    profile = _write_profile(board)
    _write_contract(profile)
    calls = []

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="frozen contract",
            assignee="builder",
            require_role_contract=True,
            expected_role_contract_sha256="0" * 64,
        )
        task = kb.get_task(conn, task_id)
        assert task is not None
        assert task.expected_role_contract_sha256 == "0" * 64

        result = kb.dispatch_once(
            conn,
            spawn_fn=lambda *args, **kwargs: calls.append(True) or 999,
            max_in_progress=1,
        )
        task = kb.get_task(conn, task_id)
        runs = kb.list_runs(conn, task_id)

    assert calls == []
    assert task is not None and task.status == "blocked"
    assert task_id in result.auto_blocked
    assert "decision-time receipt" in (runs[-1].summary or "")


def test_expected_contract_digest_requires_fail_closed_admission(board):
    with kb.connect_closing() as conn:
        with pytest.raises(ValueError, match="requires require_role_contract"):
            kb.create_task(
                conn,
                title="invalid frozen contract",
                assignee="builder",
                expected_role_contract_sha256="0" * 64,
            )
        with pytest.raises(ValueError, match="64 lowercase hex"):
            kb.create_task(
                conn,
                title="invalid digest",
                assignee="builder",
                require_role_contract=True,
                expected_role_contract_sha256="not-a-digest",
            )


def test_bare_assignee_resolves_one_prefixed_profile_before_admission(board):
    profile = _write_profile(board, "02-builder")
    raw = _write_contract(profile, name="02-builder")
    observed = {}

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="resolve prefixed builder",
            assignee="builder",
            require_role_contract=True,
        )

        def fake_spawn(task, workspace, **kwargs):
            observed["admission"] = task._role_contract_admission
            return 4243

        result = kb.dispatch_once(conn, spawn_fn=fake_spawn, max_in_progress=1)
        runs = kb.list_runs(conn, task_id)

    assert result.spawned and result.spawned[0][0] == task_id
    receipt = runs[-1].metadata["role_contract_admission"]
    assert receipt["profile"] == "02-builder"
    assert receipt["contract_sha256"] == hashlib.sha256(raw).hexdigest()
    assert observed["admission"].contract.path.parent == profile


def test_ambiguous_bare_assignee_is_nonspawnable(board):
    _write_profile(board, "02-builder")
    _write_profile(board, "07-builder")
    calls = []

    with kb.connect_closing() as conn:
        task_id = kb.create_task(conn, title="ambiguous", assignee="builder")
        result = kb.dispatch_once(
            conn,
            spawn_fn=lambda *args, **kwargs: calls.append(True) or 999,
            max_in_progress=1,
        )
        task = kb.get_task(conn, task_id)

    assert calls == []
    assert task is not None and task.status == "ready"
    assert task_id in result.skipped_nonspawnable


def test_contract_drift_after_admission_blocks_before_popen(board, monkeypatch):
    profile = _write_profile(board)
    _write_contract(profile)
    popen_calls = []

    def forbidden_popen(*args, **kwargs):
        popen_calls.append((args, kwargs))
        raise AssertionError("Popen must not be reached after contract drift")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)
    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])

    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="drift must fail closed",
            assignee="builder",
            require_role_contract=True,
        )

        def drift_then_default_spawn(task, workspace, **kwargs):
            contract = profile / "ROLE_CONTRACT.md"
            contract.write_bytes(contract.read_bytes() + b"\nchanged after admission\n")
            return kb._default_spawn(task, workspace, board=kwargs.get("board"))

        result = kb.dispatch_once(
            conn,
            spawn_fn=drift_then_default_spawn,
            max_in_progress=1,
        )
        task = kb.get_task(conn, task_id)
        runs = kb.list_runs(conn, task_id)

    assert popen_calls == []
    assert task is not None and task.status == "blocked"
    assert task_id in result.auto_blocked
    assert result.spawned == []
    assert runs[-1].outcome == "blocked"
    assert "role_contract_pre_spawn" in (runs[-1].summary or "")


def test_direct_default_spawn_rejects_frozen_digest_mismatch(board, monkeypatch, tmp_path):
    _write_contract(_write_profile(board))
    popen_calls = []
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: popen_calls.append((args, kwargs)),
    )
    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])
    workspace = tmp_path / "direct-mismatch"
    workspace.mkdir()
    task = kb.Task(
        id="t_direct_mismatch",
        title="direct mismatch",
        body=None,
        assignee="builder",
        status="running",
        priority=0,
        created_by="test",
        created_at=1,
        started_at=None,
        completed_at=None,
        workspace_kind="dir",
        workspace_path=str(workspace),
        claim_lock="lock",
        claim_expires=None,
        tenant=None,
        current_run_id=2,
        require_role_contract=True,
        expected_role_contract_sha256="0" * 64,
    )

    with pytest.raises(kb._WorkerRoleContractAdmissionError, match="decision-time receipt"):
        kb._default_spawn(task, str(workspace))
    assert popen_calls == []


def test_default_spawn_uses_admitted_toolsets_and_receipt_env(board, monkeypatch, tmp_path):
    profile = _write_profile(board)
    raw = _write_contract(profile)
    captured = {}

    class FakeProc:
        pid = 5150

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs["env"])
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])
    workspace = tmp_path / "work"
    workspace.mkdir()
    task = kb.Task(
        id="t_direct",
        title="direct",
        body=None,
        assignee="builder",
        status="running",
        priority=0,
        created_by="test",
        created_at=1,
        started_at=None,
        completed_at=None,
        workspace_kind="dir",
        workspace_path=str(workspace),
        claim_lock="lock",
        claim_expires=None,
        tenant=None,
        current_run_id=3,
        branch_name="review/exact-branch",
        require_role_contract=True,
        expected_role_contract_sha256=hashlib.sha256(raw).hexdigest(),
    )

    assert kb._default_spawn(task, str(workspace)) == 5150
    pinned = captured["cmd"][captured["cmd"].index("--toolsets") + 1].split(",")
    assert pinned == ["file", "kanban", "terminal"]
    assert captured["env"]["HERMES_ROLE_CONTRACT_SCHEMA"] == "hermes-role-contract/v2"
    assert len(captured["env"]["HERMES_ROLE_CONTRACT_SHA256"]) == 64
    assert len(captured["env"]["HERMES_ROLE_CONTRACT_RECEIPT_ID"]) == 64
    assert task._role_contract_admission.branch_name == "review/exact-branch"


def test_default_spawn_pins_prefixed_runtime_identity(board, monkeypatch, tmp_path):
    profile = _write_profile(board, "02-builder")
    _write_contract(profile, name="02-builder")
    captured = {}

    class FakeProc:
        pid = 5151

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs["env"])
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])
    workspace = tmp_path / "prefixed-work"
    workspace.mkdir()
    task = kb.Task(
        id="t_prefixed_direct",
        title="prefixed direct",
        body=None,
        assignee="builder",
        status="running",
        priority=0,
        created_by="test",
        created_at=1,
        started_at=None,
        completed_at=None,
        workspace_kind="dir",
        workspace_path=str(workspace),
        claim_lock="lock",
        claim_expires=None,
        tenant=None,
        current_run_id=4,
        require_role_contract=True,
    )

    assert kb._default_spawn(task, str(workspace)) == 5151
    profile_flag = captured["cmd"].index("-p")
    assert captured["cmd"][profile_flag + 1] == "02-builder"
    assert Path(captured["env"]["HERMES_HOME"]) == profile
    assert captured["env"]["HERMES_PROFILE"] == "02-builder"


def test_optional_card_without_contract_preserves_existing_spawn(board):
    _write_profile(board)
    called = []
    with kb.connect_closing() as conn:
        task_id = kb.create_task(conn, title="ordinary", assignee="builder")
        result = kb.dispatch_once(
            conn,
            spawn_fn=lambda *args, **kwargs: called.append(True) or 8181,
            max_in_progress=1,
        )
    assert called == [True]
    assert result.spawned[0][0] == task_id
