#!/usr/bin/env python3
"""Run one fail-closed real-profile governance canary in disposable state.

This runner snapshots only the configuration/authentication bytes required to invoke
Planner, DA, and CEO, overlays controller-canonical candidate contracts/skills, pins
all Kanban/plugin state to one output directory, and removes every profile snapshot
in a finally block. It never materializes or arms implementation work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import time
from typing import Any

import psutil


SOURCE_ROOT = Path(__file__).resolve().parents[1]
OVERLAYS = SOURCE_ROOT / "plugins" / "verified_pipeline" / "profile_overlays"
LIVE_PROFILES_ROOT = Path("/root/.hermes/profiles")
GOVERNANCE_PROFILES = ("07-planner", "11-devils-advocate", "01-ceo")
MANDATORY_CONTRACT_PROFILES = (
    "02-builder",
    "09-test",
    "06-integration",
    "08-release",
)
SAFE_PROFILE_FILES = (
    ".no-bundled-skills",
    "AGENTS.md",
    "SOUL.md",
    "config.yaml",
    "context_length_cache.yaml",
    "profile.yaml",
)
TERMINAL_STATUSES = {"done", "blocked", "triage", "archived"}
FINAL_REVIEW_STATUSES = {
    "CEO_APPROVED_PENDING_MATERIALIZATION",
    "JASON_DECISION_REQUIRED",
    "DA_ESCALATED",
}
CANARY_SESSION_PROVIDER = "verified-pipeline-canary"
CANARY_SESSION_USER_ID = "profile-canary-owner"
SPECIFICATION = """# Tier-2 governance-only canary specification

## Goal
Produce a validated, bounded four-stage implementation plan for a disposable text-file canary. This specification authorizes governance review only. It does not authorize materialization, worker execution, merge, deployment, publication, release, credential changes, or gateway changes.

## Required plan DAG
Use exactly these implementation profiles and no Validator:

1. `02-builder` — create a disposable `canary.txt` containing exactly `verified-pipeline-canary\\n`; workspace `scratch`.
2. `09-test` — verify exact bytes, file count, and SHA-256 receipt from Builder; depends on Builder; workspace `scratch`.
3. `06-integration` — verify the tested candidate identity and prepare an integration receipt without external effects; depends on Test; workspace `scratch`.
4. `08-release` — verify all receipts and produce release evidence only, explicitly stopping before merge/deploy/publish; depends on Integration; workspace `scratch`.

Use stable task ids `build-canary`, `test-canary`, `integrate-canary`, and `release-evidence`; set `release-evidence` as `final_task_id`.

## Acceptance criteria
- The Planner output passes the task-local validator against the exact request.
- DA performs an evidence/authority/lifecycle premortem and emits a validator-backed verdict.
- CEO emits a validator-backed bounded strategic decision.
- A CEO APPROVE means `CEO_APPROVED_PENDING_MATERIALIZATION` only.
- No implementation card is materialized or dispatched by this canary.
- Any malformed packet, role-contract mismatch, timeout, or unadmitted block stops the run without operator repair.
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(0o600)


def _validated_credential_auth(source_home: Path) -> Path:
    if source_home.is_symlink():
        raise RuntimeError("credential source home must not be a symlink")
    try:
        resolved_home = source_home.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RuntimeError("credential source home is missing") from exc
    home_stat = resolved_home.stat()
    if not stat.S_ISDIR(home_stat.st_mode):
        raise RuntimeError("credential source home must be a directory")
    if stat.S_IMODE(home_stat.st_mode) & 0o077:
        raise RuntimeError("credential source home must be owner-only")
    if hasattr(os, "getuid") and home_stat.st_uid != os.getuid():
        raise RuntimeError("credential source home must be owned by the current user")
    live_profiles_root = LIVE_PROFILES_ROOT.resolve()
    if resolved_home.is_relative_to(live_profiles_root):
        raise RuntimeError("credential source home must not resolve inside live profiles")
    auth_path = resolved_home / "auth.json"
    if auth_path.is_symlink():
        raise RuntimeError("credential source auth.json must not be a symlink")
    try:
        auth_stat = auth_path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError("credential source auth.json is missing") from exc
    if not stat.S_ISREG(auth_stat.st_mode):
        raise RuntimeError("credential source auth.json must be a regular file")
    if auth_stat.st_nlink != 1:
        raise RuntimeError("credential source auth.json must have exactly one hardlink")
    if stat.S_IMODE(auth_stat.st_mode) & 0o077:
        raise RuntimeError("credential source auth.json must be owner-only")
    if hasattr(os, "getuid") and auth_stat.st_uid != os.getuid():
        raise RuntimeError("credential source auth.json must be owned by the current user")
    if auth_path.resolve(strict=True).is_relative_to(live_profiles_root):
        raise RuntimeError("credential source auth.json must not resolve inside live profiles")
    return auth_path


def _snapshot_profiles(
    runtime_home: Path,
    credential_auth: Path | None = None,
) -> dict[str, Any]:
    profiles_root = runtime_home / "profiles"
    profiles_root.mkdir(parents=True, mode=0o700)
    manifest: dict[str, Any] = {"profiles": {}, "credential_files": []}
    for profile in GOVERNANCE_PROFILES:
        live = LIVE_PROFILES_ROOT / profile
        target = profiles_root / profile
        target.mkdir(mode=0o700)
        (target / "logs").mkdir(mode=0o700)
        for name in SAFE_PROFILE_FILES:
            source = live / name
            if source.is_file():
                _copy_file(source, target / name)
        if credential_auth is not None:
            _copy_file(credential_auth, target / "auth.json")
            auth_target = str(target / "auth.json")
            if auth_target not in manifest["credential_files"]:
                manifest["credential_files"].append(auth_target)
        overlay = OVERLAYS / profile
        _copy_file(overlay / "ROLE_CONTRACT.md", target / "ROLE_CONTRACT.md")
        shutil.copytree(overlay / "skills", target / "skills")
        for path in (target / "skills").rglob("*"):
            if path.is_file():
                path.chmod(0o600)
        manifest["profiles"][profile] = {
            "contract_sha256": _sha256(target / "ROLE_CONTRACT.md"),
            "config_sha256": _sha256(target / "config.yaml"),
            "overlay_skill_sha256": {
                path.parent.name: _sha256(path)
                for path in sorted((target / "skills").glob("*/SKILL.md"))
            },
        }
    for profile in MANDATORY_CONTRACT_PROFILES:
        source = OVERLAYS / profile / "ROLE_CONTRACT.md"
        if not source.is_file():
            raise RuntimeError(f"mandatory candidate role contract missing: {profile}")
        target = profiles_root / profile
        target.mkdir(mode=0o700)
        _copy_file(source, target / "ROLE_CONTRACT.md")
        profile_identity = LIVE_PROFILES_ROOT / profile / "profile.yaml"
        if profile_identity.is_file():
            _copy_file(profile_identity, target / "profile.yaml")
        manifest["profiles"][profile] = {
            "contract_sha256": _sha256(target / "ROLE_CONTRACT.md"),
            "contract_only": True,
        }
    return manifest


def _task_rows(db_path: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM tasks ORDER BY created_at, id")]
    finally:
        conn.close()


def _task(db_path: Path, task_id: str) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise RuntimeError(f"task disappeared: {task_id}")
        return dict(row)
    finally:
        conn.close()


def _active_pid(rows: list[dict[str, Any]]) -> int | None:
    for row in rows:
        if row["status"] == "running" and row.get("worker_pid"):
            return int(row["worker_pid"])
    return None


def _terminate_worker_groups(db_path: Path) -> None:
    if not db_path.exists():
        return
    for row in _task_rows(db_path):
        pid = row.get("worker_pid")
        if not pid or row["status"] not in {"running", "ready"}:
            continue
        _terminate_process_tree(int(pid))


def _terminate_process_tree(pid: int) -> None:
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    targets = process.children(recursive=True) + [process]
    for target in targets:
        try:
            target.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(targets, timeout=5)
    for target in alive:
        try:
            target.kill()
        except psutil.NoSuchProcess:
            pass


def _pid_alive(pid: int) -> bool:
    try:
        process = psutil.Process(pid)
        return process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        return True


def _drain_worker_process(pid: int | None, *, timeout_seconds: int = 30) -> None:
    if pid is None:
        return
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return
        time.sleep(0.25)
    _terminate_process_tree(pid)
    raise TimeoutError(f"worker process did not exit after task completion: {pid}")


def _wait_for_terminal(
    *,
    db_path: Path,
    task_id: str,
    conn: sqlite3.Connection,
    kanban_db: Any,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_tick = 0.0
    runtime_worker_pid: int | None = None
    while time.monotonic() < deadline:
        row = _task(db_path, task_id)
        if row.get("worker_pid"):
            runtime_worker_pid = int(row["worker_pid"])
        if row["status"] in TERMINAL_STATUSES:
            _drain_worker_process(runtime_worker_pid)
            row["runtime_worker_pid"] = runtime_worker_pid
            return row
        now = time.monotonic()
        if now - last_tick >= 8:
            kanban_db.dispatch_once(
                conn,
                max_spawn=1,
                max_in_progress=1,
                max_in_progress_per_profile=1,
                failure_limit=1,
                stale_timeout_seconds=0,
                board=kanban_db.DEFAULT_BOARD,
            )
            last_tick = now
        time.sleep(2)
    _terminate_worker_groups(db_path)
    raise TimeoutError(f"task timed out after {timeout_seconds}s: {task_id}")


def _latest_review_outcome(control_db: Path, run_id: str) -> str | None:
    conn = sqlite3.connect(control_db)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT payload_json FROM review_transitions WHERE run_id = ? "
            "ORDER BY created_at DESC, transition_key DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        return str(payload.get("status") or "") or None
    finally:
        conn.close()


def _receipt_files(workspaces_root: Path) -> list[dict[str, Any]]:
    names = {
        "planner-request.json",
        "plan.md",
        "plan.json",
        "validation.md",
        "da-request.json",
        "premortem.md",
        "verdict.json",
        "ceo-request.json",
        "decision.md",
        "decision.json",
    }
    receipts = []
    for path in sorted(workspaces_root.rglob("*")):
        if path.is_file() and path.name in names:
            receipts.append(
                {
                    "path": str(path.relative_to(workspaces_root)),
                    "sha256": _sha256(path),
                    "size": path.stat().st_size,
                }
            )
    return receipts


def _canonical_review_workspace_root(controller_module: Any) -> Path:
    return Path(controller_module._default_workspace_root())


def _canonical_control_db_path(controller_module: Any) -> Path:
    return Path(controller_module._default_db_path())


def _canary_decision_identity() -> dict[str, Any]:
    return {
        "host_auth_middleware_exercised": False,
        "decision_session_mode": "typed_canary_harness_session",
        "decision_principal": (
            f"dashboard-session:{CANARY_SESSION_PROVIDER}:{CANARY_SESSION_USER_ID}"
        ),
    }


def _scrub_profile_snapshots(runtime_home: Path) -> bool:
    profiles_root = runtime_home / "profiles"
    if profiles_root.exists():
        shutil.rmtree(profiles_root)
    return not profiles_root.exists()


def _attach_canary_authenticated_session(app: Any) -> None:
    """Attach a typed, canary-only dashboard session to in-process requests.

    This runner explicitly reports that it does not exercise host authentication
    middleware. The synthetic session only satisfies the hardened plugin API's
    typed interactive-principal boundary after host auth is qualified separately.
    """
    from hermes_cli.dashboard_auth.base import Session

    @app.middleware("http")
    async def attach_canary_session(request: Any, call_next: Any) -> Any:
        request.state.session = Session(
            user_id=CANARY_SESSION_USER_ID,
            email="",
            display_name="Verified Pipeline Profile Canary",
            org_id="",
            provider=CANARY_SESSION_PROVIDER,
            expires_at=2_000_000_000,
            access_token="",
            refresh_token="",
        )
        return await call_next(request)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--task-timeout", type=int, default=900)
    parser.add_argument("--max-tasks", type=int, default=9)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--credential-source-home", type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"refusing non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    runtime_home = output / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    kanban_path = output / "kanban.db"
    workspaces_root = output / "workspaces"
    kanban_home = output / "kanban-home"
    report_path = output / "run-report.json"
    source_head = os.popen(f"git -C {SOURCE_ROOT} rev-parse HEAD").read().strip()
    report: dict[str, Any] = {
        "schema": "verified-pipeline/live-governance-canary/v1",
        "source_head": source_head,
        "source_root": str(SOURCE_ROOT),
        "started_at_epoch": int(time.time()),
        "status": "PREFLIGHT",
        "production_gateway_exercised": False,
        "implementation_authority": False,
        "tasks": [],
        "reconciliations": [],
    }
    report.update(_canary_decision_identity())
    exit_code = 1
    try:
        credential_auth = None
        if args.credential_source_home is not None:
            source_home = args.credential_source_home.expanduser().absolute()
            credential_auth = _validated_credential_auth(source_home)
            report["credential_source_sha256"] = _sha256(credential_auth)
        report["profile_snapshot"] = _snapshot_profiles(
            runtime_home,
            credential_auth=credential_auth,
        )
        os.environ.update(
            {
                "HERMES_HOME": str(runtime_home),
                "HERMES_KANBAN_DB": str(kanban_path),
                "HERMES_KANBAN_WORKSPACES_ROOT": str(workspaces_root),
                "HERMES_KANBAN_HOME": str(kanban_home),
                "HERMES_KANBAN_BOARD": "default",
                "HERMES_BIN": str(SOURCE_ROOT / ".venv" / "bin" / "hermes"),
                "PYTHONPATH": str(SOURCE_ROOT),
            }
        )
        hermes_bin = Path(os.environ["HERMES_BIN"])
        if not hermes_bin.is_file():
            raise RuntimeError(f"source-coherent Hermes executable missing: {hermes_bin}")

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hermes_cli import kanban_db
        from plugins.verified_pipeline import controller, review, validators
        from plugins.verified_pipeline.dashboard.plugin_api import router

        review_root = _canonical_review_workspace_root(controller)
        control_db_path = _canonical_control_db_path(controller)

        app = FastAPI()
        _attach_canary_authenticated_session(app)
        app.include_router(router, prefix="/api/plugins/verified-pipeline")
        client = TestClient(app)
        created = client.post(
            "/api/plugins/verified-pipeline/intakes",
            json={
                "specification_id": "tier2-governance-canary",
                "revision": 1,
                "artifact_text": SPECIFICATION,
            },
        )
        if created.status_code != 200:
            raise RuntimeError(f"intake failed: {created.status_code} {created.text}")
        intake = created.json()
        report["run_id"] = intake["run_id"]
        report["artifact_sha256"] = intake["artifact_sha256"]
        report["authority_ceiling"] = intake["authority_ceiling"]
        report["frozen_profiles"] = intake["frozen_profiles"]
        if "00-cos" in intake["frozen_profiles"] or "10-validator" in intake["frozen_profiles"]:
            raise RuntimeError("optional absent profiles unexpectedly entered frozen inventory")
        approved = client.post(
            f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/decision",
            headers={"user-agent": "tier2-governance-canary"},
            json={
                "request_id": "tier2-governance-canary-approval-v1",
                "action": "approve",
                "decision_nonce": intake["decision_nonce"],
                "artifact_sha256": intake["artifact_sha256"],
            },
        )
        if approved.status_code != 200:
            raise RuntimeError(f"approval failed: {approved.status_code} {approved.text}")
        initial = client.post(
            f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/review/reconcile"
        )
        if initial.status_code != 200:
            raise RuntimeError(f"initial reconcile failed: {initial.status_code} {initial.text}")
        report["reconciliations"].append(initial.json())

        rows = _task_rows(kanban_path)
        if len(rows) != 1 or rows[0]["assignee"] != controller.PLANNER_PROFILE:
            raise RuntimeError("preflight expected exactly one Planner card")
        planner_workspace = Path(rows[0]["workspace_path"])
        request = json.loads(
            (planner_workspace / "planner-request.json").read_text(encoding="utf-8")
        )
        validators.validate_plan_request(request)
        if json.loads(rows[0]["skills"]) != [controller.PLANNER_SKILL]:
            raise RuntimeError("Planner forced skill drifted")
        if rows[0]["expected_role_contract_sha256"] != intake["frozen_profiles"][controller.PLANNER_PROFILE]["sha256"]:
            raise RuntimeError("Planner role-contract digest drifted")
        if args.preflight_only:
            report["status"] = "PREFLIGHT_PASS"
            exit_code = 0
            return exit_code
        report["status"] = "ACTIVATED"
        _write_json(report_path, report)

        conn = kanban_db.connect(db_path=kanban_path)
        try:
            processed: set[str] = set()
            for _ in range(args.max_tasks):
                rows = _task_rows(kanban_path)
                active = [row for row in rows if row["status"] in {"ready", "running"} and row["id"] not in processed]
                if not active:
                    outcome = _latest_review_outcome(control_db_path, intake["run_id"])
                    if outcome in FINAL_REVIEW_STATUSES:
                        break
                    raise RuntimeError(f"controller reached quiescence without final governance outcome: {outcome}")
                row = active[0]
                if row["status"] == "ready":
                    result = kanban_db.dispatch_once(
                        conn,
                        max_spawn=1,
                        max_in_progress=1,
                        max_in_progress_per_profile=1,
                        failure_limit=1,
                        stale_timeout_seconds=0,
                        board=kanban_db.DEFAULT_BOARD,
                    )
                    if not result.spawned:
                        raise RuntimeError(f"dispatcher did not spawn ready task {row['id']}: {result}")
                terminal = _wait_for_terminal(
                    db_path=kanban_path,
                    task_id=row["id"],
                    conn=conn,
                    kanban_db=kanban_db,
                    timeout_seconds=args.task_timeout,
                )
                processed.add(row["id"])
                report["tasks"].append(
                    {
                        "id": terminal["id"],
                        "assignee": terminal["assignee"],
                        "status": terminal["status"],
                        "consecutive_failures": terminal.get("consecutive_failures", 0),
                        "workspace_path": terminal["workspace_path"],
                        "worker_pid": terminal["runtime_worker_pid"],
                    }
                )
                reconciled = review.reconcile_review_once(
                    intake["run_id"],
                    db_path=None,
                    kanban_db_path=kanban_path,
                    workspace_root=review_root,
                )
                report["reconciliations"].append(reconciled)
                final = next(
                    (
                        item["status"]
                        for item in reconciled["advanced"]
                        if item["status"] in FINAL_REVIEW_STATUSES
                    ),
                    None,
                )
                _write_json(report_path, report)
                if final is not None:
                    report["final_review_status"] = final
                    break
            else:
                raise RuntimeError(f"governance task limit exceeded: {args.max_tasks}")
        finally:
            conn.close()

        if report.get("final_review_status") != "CEO_APPROVED_PENDING_MATERIALIZATION":
            raise RuntimeError(
                "governance canary did not reach bounded CEO approval: "
                f"{report.get('final_review_status') or _latest_review_outcome(control_db_path, intake['run_id'])}"
            )
        report["receipts"] = _receipt_files(output)
        report["materialized_implementation_tasks"] = 0
        report["status"] = "PASS"
        exit_code = 0
    except Exception as exc:
        report["status"] = "FAIL"
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)
    finally:
        _terminate_worker_groups(kanban_path)
        report["profile_snapshots_scrubbed"] = _scrub_profile_snapshots(runtime_home)
        report["finished_at_epoch"] = int(time.time())
        if kanban_path.exists():
            report["final_tasks"] = [
                {
                    "id": row["id"],
                    "assignee": row["assignee"],
                    "status": row["status"],
                    "consecutive_failures": row.get("consecutive_failures", 0),
                }
                for row in _task_rows(kanban_path)
            ]
        _write_json(report_path, report)
    print(json.dumps({"status": report["status"], "output": str(output), "report": str(report_path), "error": report.get("error")}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
