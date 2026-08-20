from __future__ import annotations

import json

from agent.tool_executor import _role_contract_tool_block


# These unit tests exercise the shared policy primitive directly. The dispatch-level
# regression in tests/run_agent/test_run_agent.py separately proves that rewritten
# plugin arguments are rechecked by this same primitive immediately before execution.
def _policy(monkeypatch, workspace, *, task_id="t_governance"):
    monkeypatch.setenv(
        "HERMES_ROLE_CONTRACT_ALLOWED_TOOLS",
        json.dumps(
            [
                "kanban_block",
                "kanban_comment",
                "kanban_complete",
                "kanban_show",
                "patch",
                "read_file",
                "search_files",
                "write_file",
            ]
        ),
    )
    monkeypatch.setenv("HERMES_ROLE_CONTRACT_WORKSPACE_ONLY", "1")
    monkeypatch.setenv("HERMES_ROLE_CONTRACT_WORKSPACE_PATH", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "verified-board")


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
    assert "admitted board" in _role_contract_tool_block(
        "kanban_comment",
        {"task_id": "t_governance", "board": "foreign-board", "body": "poison"},
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
    assert "multi-file patch" in _role_contract_tool_block(
        "patch",
        {
            "mode": "patch",
            "patch": "*** Begin Patch\n*** Update File: /tmp/outside.txt\n+x\n*** End Patch",
        },
    )
    assert "escapes" in _role_contract_tool_block(
        "kanban_complete",
        {
            "summary": "done",
            "metadata": {"artifacts": [str(outside / "secret.txt")]},
        },
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
