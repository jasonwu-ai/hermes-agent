#!/usr/bin/env python3
"""Real dispatcher -> 02-builder Docker file/artifact custody canary.

This bounded canary uses the production dispatcher, Docker-backed file tools,
and production Kanban completion attachment capture.  It does not call a model,
GitHub, merge, deployment, gateway, or activation surfaces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parents[1]
CANARY_BYTES = b"verified-pipeline-docker-custody-canary\n"


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _worker_program() -> str:
    return r'''from __future__ import annotations
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

source_root = Path(os.environ["CANARY_SOURCE_ROOT"])
sys.path.insert(0, str(source_root))
task_id = os.environ["HERMES_KANBAN_TASK"]
db_path = Path(os.environ["HERMES_KANBAN_DB"])
workspace = Path(os.environ["HERMES_KANBAN_WORKSPACE"])
profile_name = os.environ["CANARY_PROFILE"]
profile_root = Path(os.environ["HERMES_HOME"]) / "profiles" / profile_name
profile_root.joinpath("logs").mkdir(parents=True, exist_ok=True)
profile_root.joinpath("state").mkdir(parents=True, exist_ok=True)

# Wait until the dispatcher has persisted this exact child PID and run binding.
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    connection = sqlite3.connect(db_path)
    row = connection.execute(
        "SELECT status, worker_pid, current_run_id, claim_lock FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()
    connection.close()
    if row and row[0] == "running" and row[1] == os.getpid():
        break
    time.sleep(0.05)
else:
    raise RuntimeError("dispatcher did not durably bind the canary worker PID")

from tools import terminal_tool
from agent.tool_executor import _role_contract_tool_block
from tools.file_tools import read_file_tool, write_file_tool
from tools.kanban_tools import _handle_complete

terminal_tool.register_task_env_overrides(
    task_id,
    {"cwd": str(workspace), "cwd_source": "session"},
)
absolute_host_artifact = workspace / "canary.txt"
write_result = write_file_tool(
    str(absolute_host_artifact),
    "verified-pipeline-docker-custody-canary\n",
    task_id=task_id,
)
read_result = read_file_tool("canary.txt", task_id=task_id)
if not absolute_host_artifact.is_file():
    raise RuntimeError("Docker file-tool write was not visible in the host workspace")
if absolute_host_artifact.read_bytes() != b"verified-pipeline-docker-custody-canary\n":
    raise RuntimeError("Docker file-tool host-visible bytes drifted")
if "verified-pipeline-docker-custody-canary" not in read_result:
    raise RuntimeError("Docker file-tool readback did not return the canary bytes")

profile_root.joinpath("logs", "canary.log").write_text("before-complete\n", encoding="utf-8")
profile_root.joinpath("state", "canary.state").write_text("before-complete\n", encoding="utf-8")
completion_args = {
    "task_id": task_id,
    "summary": "Docker workspace custody canary completed",
    "artifacts": ["/workspace/canary.txt"],
    "metadata": {"claim": "attachment-only substrate canary"},
}
policy_block = _role_contract_tool_block(
    "kanban_complete", completion_args, task_id=task_id,
)
if policy_block is not None:
    raise RuntimeError(f"role-contract completion policy blocked: {policy_block}")
if completion_args["artifacts"] != [str(absolute_host_artifact)]:
    raise RuntimeError("container artifact alias did not canonicalize to host custody")
completion = _handle_complete(completion_args)
parsed = json.loads(completion)
if parsed.get("ok") is not True:
    raise RuntimeError(f"kanban_complete failed: {completion}")

# Keep writing after the terminal task transition.  The controller must retain
# and drain the running PID rather than scrubbing this profile immediately.
with profile_root.joinpath("logs", "canary.log").open("a", encoding="utf-8") as handle:
    handle.write("after-complete\n")
with profile_root.joinpath("state", "canary.state").open("a", encoding="utf-8") as handle:
    handle.write("after-complete\n")
time.sleep(3)
'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", default="02-builder")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"refusing non-empty evidence root: {output}")
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)

    runtime_home = output / "runtime-home"
    profile_name = args.profile.strip()
    if not profile_name or "/" in profile_name or "\\" in profile_name:
        raise SystemExit("profile must be one plain profile name")
    workspace = output / "workspaces" / f"{profile_name}-task"
    workspace.mkdir(parents=True, mode=0o700)
    runtime_home.mkdir(mode=0o700)
    target_profile = runtime_home / "profiles" / profile_name
    target_profile.mkdir(parents=True, mode=0o700)
    target_profile.joinpath("config.yaml").write_text(
        "toolsets:\n  - file\n  - kanban\n",
        encoding="utf-8",
    )
    target_profile.joinpath("config.yaml").chmod(0o600)
    worker_path = output / "worker.py"
    worker_path.write_text(_worker_program(), encoding="utf-8")
    worker_path.chmod(0o600)
    db_path = output / "kanban.db"
    kanban_home = output / "kanban-home"
    env_updates = {
        "HERMES_HOME": str(runtime_home),
        "HERMES_KANBAN_DB": str(db_path),
        "HERMES_KANBAN_HOME": str(kanban_home),
        "HERMES_KANBAN_WORKSPACES_ROOT": str(output / "workspaces"),
        "HERMES_KANBAN_BOARD": "default",
        "TERMINAL_ENV": "docker",
        "TERMINAL_CONTAINER_PERSISTENT": "false",
        "TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE": "true",
        "TERMINAL_DOCKER_IMAGE": "python:3.13-slim",
        "CANARY_SOURCE_ROOT": str(SOURCE_ROOT),
        "CANARY_PROFILE": profile_name,
        "PYTHONPATH": str(SOURCE_ROOT),
    }
    os.environ.update(env_updates)

    from hermes_cli import kanban_db
    from scripts import run_verified_pipeline_live_full_flow_canary as full_flow

    report: dict[str, Any] = {
        "schema": "verified-pipeline/builder-docker-custody-canary/v1",
        "profile": profile_name,
        "source_tree": subprocess.run(
            ["git", "-C", str(SOURCE_ROOT), "write-tree"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip(),
        "started_at_epoch": int(time.time()),
        "status": "FAIL",
        "boundary": {
            "model": False,
            "github": False,
            "merge": False,
            "deployment": False,
            "gateway": False,
            "activation": False,
        },
    }
    child: subprocess.Popen[str] | None = None
    try:
        conn = kanban_db.connect(db_path=db_path)
        try:
            task_id = kanban_db.create_task(
                conn,
                title=f"{profile_name} Docker workspace custody canary",
                body="Write/read exact canary bytes and complete with the absolute host artifact path.",
                assignee=profile_name,
                created_by="verified-pipeline-custody-canary",
                workspace_kind="scratch",
                workspace_path=str(workspace),
                max_runtime_seconds=120,
            )

            def spawn(task, claimed_workspace, board=None):
                nonlocal child
                if task.id != task_id or task.assignee != profile_name:
                    raise RuntimeError("dispatcher selected the wrong canary task/profile")
                child_env = dict(os.environ)
                child_env.update(
                    {
                        "HERMES_KANBAN_TASK": task.id,
                        "HERMES_KANBAN_WORKSPACE": str(claimed_workspace),
                        "HERMES_KANBAN_RUN_ID": str(task.current_run_id),
                        "HERMES_KANBAN_CLAIM_LOCK": str(task.claim_lock),
                        "HERMES_PROFILE": profile_name,
                        "HERMES_ROLE_CONTRACT_ALLOWED_TOOLS": json.dumps(
                            ["kanban_complete"]
                        ),
                        "HERMES_ROLE_CONTRACT_WORKSPACE_ONLY": "1",
                        "HERMES_ROLE_CONTRACT_WORKSPACE_PATH": str(claimed_workspace),
                    }
                )
                child = subprocess.Popen(
                    [sys.executable, str(worker_path)],
                    cwd=str(SOURCE_ROOT),
                    env=child_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                return child.pid

            original_dispatch = kanban_db.dispatch_once

            def canary_dispatch(connection, **kwargs):
                return original_dispatch(connection, spawn_fn=spawn, **kwargs)

            terminal = full_flow._dispatch_exact_task(
                task_id=task_id,
                kanban_path=db_path,
                conn=conn,
                kanban_db=type(
                    "CanaryKanban",
                    (),
                    {"DEFAULT_BOARD": kanban_db.DEFAULT_BOARD, "dispatch_once": staticmethod(canary_dispatch)},
                ),
                timeout_seconds=60,
            )
            if child is None:
                raise RuntimeError("dispatcher did not create the canary worker")
            stdout, stderr = child.communicate(timeout=5)
            (output / "worker.stdout").write_text(stdout, encoding="utf-8")
            (output / "worker.stderr").write_text(stderr, encoding="utf-8")
            if child.returncode != 0:
                raise RuntimeError(f"canary worker exited {child.returncode}")

            attachments = kanban_db.list_attachments(conn, task_id)
            completed = [item for item in attachments if item.uploaded_by == "kanban_complete"]
            if len(completed) != 1:
                raise RuntimeError("expected exactly one completion attachment")
            attachment = completed[0]
            stored = Path(attachment.stored_path)
            if stored.read_bytes() != CANARY_BYTES:
                raise RuntimeError("durable attachment bytes drifted")
            digest = _sha256(stored)
            if digest != attachment.sha256:
                raise RuntimeError("controller digest disagreed with admitted attachment digest")

            profile_log = runtime_home / "profiles" / profile_name / "logs" / "canary.log"
            profile_state = runtime_home / "profiles" / profile_name / "state" / "canary.state"
            expected_profile_bytes = b"before-complete\nafter-complete\n"
            if profile_log.read_bytes() != expected_profile_bytes:
                raise RuntimeError("profile log did not persist through worker drain")
            if profile_state.read_bytes() != expected_profile_bytes:
                raise RuntimeError("profile state did not persist through worker drain")
            persisted = output / "persisted-profile-evidence"
            persisted.mkdir(mode=0o700)
            shutil.copy2(profile_log, persisted / "canary.log")
            shutil.copy2(profile_state, persisted / "canary.state")

            workspace_survived = workspace.exists()
            profiles_root = runtime_home / "profiles"
            shutil.rmtree(profiles_root)
            if profiles_root.exists():
                raise RuntimeError("profile snapshot scrub did not converge after drain")
            if not stored.is_file() or _sha256(stored) != digest:
                raise RuntimeError("completion attachment did not survive cleanup")

            receipt = {
                "task_id": task_id,
                "assignee": terminal["assignee"],
                "runtime_worker_pid": terminal["runtime_worker_pid"],
                "container_mount": "/workspace",
                "host_workspace": str(workspace),
                "host_workspace_survived_completion": workspace_survived,
                "attachment_path": str(stored),
                "attachment_size": stored.stat().st_size,
                "controller_sha256": digest,
                "admitted_sha256": attachment.sha256,
                "profile_log_sha256": _sha256(persisted / "canary.log"),
                "profile_state_sha256": _sha256(persisted / "canary.state"),
                "profile_scrubbed_after_drain": True,
                "attachment_survived_cleanup": True,
            }
            _write_json(output / "controller-receipt.json", receipt)
            report["receipt"] = receipt
            report["status"] = "PASS"
        finally:
            conn.close()
    except Exception as exc:
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    finally:
        report["finished_at_epoch"] = int(time.time())
        _write_json(output / "run-report.json", report)
    print(json.dumps({"status": report["status"], "report": str(output / "run-report.json")}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
