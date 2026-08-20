from __future__ import annotations

import json

from agent.tool_executor import _role_contract_tool_block


def _policy(monkeypatch, workspace, *, task_id="t_governance"):
    monkeypatch.setenv(
        "HERMES_ROLE_CONTRACT_ALLOWED_TOOLS",
        json.dumps(
            [
                "kanban_block",
                "kanban_comment",
                "kanban_complete",
                "kanban_show",
                "read_file",
                "search_files",
                "write_file",
            ]
        ),
    )
    monkeypatch.setenv("HERMES_ROLE_CONTRACT_WORKSPACE_ONLY", "1")
    monkeypatch.setenv("HERMES_ROLE_CONTRACT_WORKSPACE_PATH", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)


def test_role_contract_blocks_unadmitted_tool_and_foreign_task(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _policy(monkeypatch, workspace)

    assert "outside the admitted role contract" in _role_contract_tool_block(
        "terminal", {"command": "cat /etc/passwd"}
    )
    assert "current task" in _role_contract_tool_block(
        "kanban_comment", {"task_id": "t_foreign", "body": "poison"}
    )


def test_role_contract_blocks_path_and_symlink_escape(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    _policy(monkeypatch, workspace)

    assert "escapes" in _role_contract_tool_block(
        "read_file", {"path": "../outside/secret.txt"}
    )
    assert "escapes" in _role_contract_tool_block(
        "write_file", {"path": "escape/secret.txt", "content": "x"}
    )


def test_role_contract_allows_current_task_workspace_operations(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _policy(monkeypatch, workspace)

    assert _role_contract_tool_block(
        "write_file", {"path": "plan.json", "content": "{}"}
    ) is None
    assert _role_contract_tool_block(
        "kanban_complete", {"task_id": "t_governance", "summary": "done"}
    ) is None
