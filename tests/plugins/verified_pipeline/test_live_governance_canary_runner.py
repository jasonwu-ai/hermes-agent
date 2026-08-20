from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import psutil

from scripts import run_verified_pipeline_live_governance_canary as runner


def test_runner_uses_controller_canonical_review_workspace_root(tmp_path: Path) -> None:
    class Controller:
        @staticmethod
        def _default_workspace_root() -> Path:
            return tmp_path / "plugin-data" / "verified_pipeline" / "workspaces"

    assert runner._canonical_review_workspace_root(Controller) == (
        tmp_path / "plugin-data" / "verified_pipeline" / "workspaces"
    )


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
