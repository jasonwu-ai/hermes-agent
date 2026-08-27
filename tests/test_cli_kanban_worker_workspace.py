import os
import sqlite3
import threading
import time

import pytest

import cli


def _claimed_worker(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db_path = tmp_path / "kanban.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE tasks ("
        "id TEXT PRIMARY KEY, status TEXT, assignee TEXT, workspace_path TEXT, "
        "current_run_id INTEGER, claim_lock TEXT, worker_pid INTEGER)"
    )
    conn.execute(
        "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "t_example",
            "running",
            "02-builder",
            str(workspace),
            42,
            "claim-example",
            os.getpid(),
        ),
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_example")
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", "claim-example")
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", "42")
    monkeypatch.setenv("HERMES_PROFILE", "02-builder")
    monkeypatch.setenv("HERMES_KANBAN_DB", str(db_path))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace))
    return db_path, workspace


def test_registers_durably_claimed_kanban_workspace_for_session(monkeypatch, tmp_path):
    _db_path, workspace = _claimed_worker(monkeypatch, tmp_path)
    captured = {}
    monkeypatch.setattr(
        "tools.terminal_tool.register_task_env_overrides",
        lambda session_id, overrides: captured.update(
            {"session_id": session_id, "overrides": overrides}
        ),
    )

    cli._register_kanban_worker_workspace("session-example")

    assert captured == {
        "session_id": "session-example",
        "overrides": {"cwd": str(workspace.resolve()), "cwd_source": "session"},
    }


def test_registered_workspace_is_docker_session_mount(monkeypatch, tmp_path):
    from tools import terminal_tool

    _db_path, workspace = _claimed_worker(monkeypatch, tmp_path)
    monkeypatch.setattr(terminal_tool, "_docker_session_isolation_enabled", lambda: True)
    config = {
        "env_type": "docker",
        "docker_mount_cwd_to_workspace": True,
        "host_cwd": None,
    }

    try:
        cli._register_kanban_worker_workspace("session-example")
        assert terminal_tool._resolve_task_host_cwd(config, "session-example") == str(
            workspace.resolve()
        )
    finally:
        terminal_tool.clear_task_env_overrides("session-example")


def test_waits_for_dispatcher_to_persist_spawned_worker_pid(monkeypatch, tmp_path):
    db_path, workspace = _claimed_worker(monkeypatch, tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE tasks SET worker_pid = NULL WHERE id = ?", ("t_example",))
    conn.commit()
    conn.close()
    monkeypatch.setattr(cli, "_KANBAN_WORKSPACE_BIND_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(cli, "_KANBAN_WORKSPACE_BIND_POLL_SECONDS", 0.01)
    captured = {}
    monkeypatch.setattr(
        "tools.terminal_tool.register_task_env_overrides",
        lambda session_id, overrides: captured.update(
            {"session_id": session_id, "overrides": overrides}
        ),
    )

    def persist_spawned_pid():
        time.sleep(0.05)
        update = sqlite3.connect(db_path)
        update.execute(
            "UPDATE tasks SET worker_pid = ? WHERE id = ?",
            (os.getpid(), "t_example"),
        )
        update.commit()
        update.close()

    updater = threading.Thread(target=persist_spawned_pid)
    updater.start()
    try:
        cli._register_kanban_worker_workspace("session-example")
    finally:
        updater.join()

    assert captured == {
        "session_id": "session-example",
        "overrides": {"cwd": str(workspace.resolve()), "cwd_source": "session"},
    }


@pytest.mark.parametrize(
    ("env_key", "env_value", "column", "db_value"),
    [
        ("HERMES_KANBAN_CLAIM_LOCK", "wrong", None, None),
        ("HERMES_KANBAN_RUN_ID", "999", None, None),
        ("HERMES_PROFILE", "09-test", None, None),
        (None, None, "status", "blocked"),
        (None, None, "worker_pid", -1),
        (None, None, "claim_lock", "different-claim"),
    ],
)
def test_refuses_substituted_durable_authority(
    monkeypatch, tmp_path, env_key, env_value, column, db_value
):
    db_path, _workspace = _claimed_worker(monkeypatch, tmp_path)
    if env_key is not None:
        monkeypatch.setenv(env_key, env_value)
    if column is not None:
        conn = sqlite3.connect(db_path)
        conn.execute(f"UPDATE tasks SET {column} = ? WHERE id = ?", (db_value, "t_example"))
        conn.commit()
        conn.close()
    if column == "worker_pid":
        monkeypatch.setattr(cli, "_KANBAN_WORKSPACE_BIND_TIMEOUT_SECONDS", 0.0)
    called = []
    monkeypatch.setattr(
        "tools.terminal_tool.register_task_env_overrides",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    cli._register_kanban_worker_workspace("session-example")

    assert called == []


def test_refuses_substituted_workspace(monkeypatch, tmp_path):
    _db_path, _workspace = _claimed_worker(monkeypatch, tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(other))
    called = []
    monkeypatch.setattr(
        "tools.terminal_tool.register_task_env_overrides",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    cli._register_kanban_worker_workspace("session-example")

    assert called == []


def test_noop_outside_kanban_worker(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace))
    called = []
    monkeypatch.setattr(
        "tools.terminal_tool.register_task_env_overrides",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    cli._register_kanban_worker_workspace("session-example")

    assert called == []
