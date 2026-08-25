from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def test_connected_canary_runs_to_generic_completion_with_release_fail_closed(
    tmp_path: Path,
) -> None:
    output = tmp_path / "connected-canary"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_verified_pipeline_canary.py",
            "--output-dir",
            str(output),
        ],
        cwd=Path(__file__).parents[3],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    report = json.loads((output / "canary-report.json").read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert report["canary_class"] == "deterministic-control-plane"
    assert report["task_count"] == 7
    assert set(report["implementation_task_map"]) == {
        "build",
        "test",
        "integrate",
        "release",
    }
    assert all(report["replay"].values())
    assert set(report["forbidden_authority_receipts"].values()) == {0}
    assert report["boundary"] == {
        "actuator_invoked": False,
        "authenticated_host_session_exercised": False,
        "credentials": False,
        "deployment": False,
        "installation": False,
        "live_enablement": False,
        "live_worker_profiles_exercised": False,
        "merge": False,
        "production_ready": False,
    }
    html = (output / "canary-report.html").read_text(encoding="utf-8")
    assert "Control-plane canary PASS" in html
    assert "does not claim that host authentication was exercised" in html
    assert "live LLM worker profiles produced or reviewed" in html
    assert "No merge authorization" in html
