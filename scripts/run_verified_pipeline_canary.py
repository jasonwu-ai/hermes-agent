#!/usr/bin/env python3
"""Run a disposable, side-effect-inert verified-pipeline canary.

This deterministic control-plane canary exercises dashboard decision binding,
Planner/DA/CEO reconciliation, exact DAG materialization, signed execution
arming, native dependency promotion, completion custody, and read-only release
readiness. Its worker adapter records simulated task completions; it does not
claim that live LLM profile sessions built or reviewed an artifact. It never
authorizes or performs merge, deployment, installation, credentials, or live
enablement.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from hermes_cli import kanban_db
from hermes_cli.role_contract import admit_role_contract, load_role_contract
from hermes_cli.dashboard_auth.base import Session
from plugins.verified_pipeline import controller, execution, materializer, release, review, validators
from plugins.verified_pipeline.dashboard.plugin_api import router


SPECIFICATION = """# Deterministic verified-pipeline control-plane canary

Exercise exact approval, review, materialization, dependency, and generic graph
completion custody using deterministic contract-compatible worker receipts. Do not claim a live worker-produced implementation artifact.
No merge, deploy, installation, credential, production, or live-enablement
authority is granted.
"""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _write_contract(home: Path, profile: str) -> None:
    profile_home = home / "profiles" / profile
    profile_home.mkdir(parents=True, exist_ok=True)
    contract = profile_home / "ROLE_CONTRACT.md"
    contract.write_text(
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
                f"Disposable canary authority for {profile}.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    contract.chmod(0o600)


def _rows(kanban_path: Path):
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        return conn.execute("SELECT * FROM tasks ORDER BY created_at, id").fetchall()
    finally:
        conn.close()


def _task(kanban_path: Path, task_id: str):
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        task = kanban_db.get_task(conn, task_id)
        if task is None:
            raise RuntimeError(f"canary task not found: {task_id}")
        return task
    finally:
        conn.close()


def _latest(kanban_path: Path, assignee: str):
    matches = [row for row in _rows(kanban_path) if row["assignee"] == assignee]
    if not matches:
        raise RuntimeError(f"no canary task for {assignee}")
    return matches[-1]


def _complete(kanban_path: Path, task_id: str, result: str) -> None:
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        task = kanban_db.claim_task(conn, task_id, claimer="connected-canary-adapter")
        if task is None or task.current_run_id is None:
            raise RuntimeError(f"could not claim canary task: {task_id}")
        if task.workspace_kind == "worktree" and not task.workspace_path:
            workspace = kanban_db.workspaces_root() / task.id
            workspace.mkdir(parents=True, exist_ok=True)
        else:
            workspace = kanban_db.resolve_workspace(task)
        kanban_db.set_workspace_path(conn, task.id, workspace)
        task = kanban_db.get_task(conn, task.id)
        assert task is not None
        run_id = int(task.current_run_id)
        workspace = Path(task.workspace_path).resolve()
        profile_home = Path(os.environ["HERMES_HOME"]) / "profiles" / task.assignee
        contract = load_role_contract(profile_home, task.assignee, required=True)
        assert contract is not None
        admission = admit_role_contract(
            profile_home,
            task.assignee,
            contract.allowed_toolsets,
            task_id=task.id,
            run_id=run_id,
            workspace_path=str(workspace),
            branch_name=task.branch_name,
            required=True,
        )
        assert admission is not None
        receipt = admission.receipt()
        with kanban_db.write_txn(conn):
            conn.execute(
                "UPDATE task_runs SET metadata = ? WHERE id = ? AND task_id = ?",
                (json.dumps({"role_contract_admission": receipt}), run_id, task.id),
            )
            kanban_db._append_event(
                conn, task.id, "role_contract_admitted", receipt, run_id=run_id
            )
        artifact = workspace / f"{task.assignee}-canary-stage-receipt.txt"
        artifact.write_text(f"{result}\n", encoding="utf-8")
        completion_metadata = {"artifacts": [str(artifact)]}
        if not kanban_db.complete_task(
            conn,
            task_id,
            result=result,
            metadata=completion_metadata,
            expected_run_id=run_id,
            fire_lifecycle_hook=False,
        ):
            raise RuntimeError(f"could not complete canary task: {task_id}")
    finally:
        conn.close()


def _plan(request: dict[str, Any]) -> dict[str, Any]:
    tasks = [
        {
            "id": "build",
            "title": "Build bounded canary artifact",
            "assignee": "02-builder",
            "goal": "Record only the accepted deterministic Builder-stage receipt.",
            "dependencies": [],
            "deliverable": "A deterministic Builder-stage completion receipt.",
            "acceptance_criteria": ["Receipt is bound to the accepted canary specification."],
            "workspace": "scratch",
        },
        {
            "id": "test",
            "title": "Independently test canary artifact",
            "assignee": "09-test",
            "goal": "Exercise the independent Test dependency gate without implementation authority.",
            "dependencies": ["build"],
            "deliverable": "A deterministic Test-stage completion receipt.",
            "acceptance_criteria": ["Test cannot advance before Builder completes."],
            "workspace": "scratch",
        },
        {
            "id": "integrate",
            "title": "Integrate qualified canary artifact",
            "assignee": "06-integration",
            "goal": "Exercise the Integration dependency gate after Test.",
            "dependencies": ["test"],
            "deliverable": "A deterministic Integration-stage completion receipt.",
            "acceptance_criteria": ["Integration cannot advance before Test completes."],
            "workspace": "scratch",
        },
        {
            "id": "release",
            "title": "Review canary release readiness",
            "assignee": "08-release",
            "goal": "Perform read-only release review without merge or deployment authority.",
            "dependencies": ["integrate"],
            "deliverable": "A deterministic read-only Release-stage completion receipt.",
            "acceptance_criteria": ["Release cannot advance before Integration; no live side effect occurs."],
            "workspace": "scratch",
        },
    ]
    return {
        "schema": validators.PLAN_SCHEMA,
        "specification_id": request["specification_id"],
        "specification_sha256": request["specification_sha256"],
        "plan_revision": request["plan_revision"],
        "title": "Connected disposable canary",
        "summary": "Exercise deterministic Builder, Test, Integration, and Release gates.",
        "tasks": tasks,
        "final_task_id": "release",
        "review_dispositions": [],
    }


def _write_planner(workspace: Path) -> None:
    request = json.loads((workspace / "planner-request.json").read_text(encoding="utf-8"))
    plan = _plan(request)
    (workspace / "plan.md").write_text(
        "# Canary plan\n\nBuilder → independent Test → Integration → read-only Release.\n",
        encoding="utf-8",
    )
    (workspace / "plan.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    digest = hashlib.sha256((review._canonical(plan) + "\n").encode()).hexdigest()
    (workspace / "validation.md").write_text(f"VALID: {digest}\n", encoding="utf-8")


def _write_da(workspace: Path) -> None:
    request = json.loads((workspace / "da-request.json").read_text(encoding="utf-8"))
    verdict = {
        "schema": validators.DA_VERDICT_SCHEMA,
        "specification_id": request["specification_id"],
        "plan_revision": request["plan_revision"],
        "review_round": request["plan_revision"],
        "verdict": "PASS",
        "findings": [],
        "score": 100,
        "most_likely_failure": "A hidden operator bridge bypasses durable projection.",
        "most_dangerous_failure": "Execution authority escapes the exact canary scope.",
        "cross_cutting_assumption": "Every transition is replay-safe and task-bound.",
        "escalate_to_jason": False,
        "decision_question": None,
    }
    (workspace / "premortem.md").write_text(
        "# Canary premortem\n\nNo blocking finding in the disposable route.\n",
        encoding="utf-8",
    )
    (workspace / "verdict.json").write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_ceo(workspace: Path) -> None:
    request = json.loads((workspace / "ceo-request.json").read_text(encoding="utf-8"))
    decision = {
        "schema": validators.CEO_DECISION_SCHEMA,
        "specification_id": request["specification_id"],
        "plan_revision": request["plan_revision"],
        "decision": "APPROVE",
        "rationale": "The bounded canary stays within the accepted disposable scope.",
        "required_changes": [],
        "decision_question": None,
        "material_scope_or_risk_change": False,
    }
    (workspace / "decision.md").write_text(
        "# Canary CEO decision\n\nApproved for disposable materialization.\n",
        encoding="utf-8",
    )
    (workspace / "decision.json").write_text(
        json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _verifier(signing_key: Ed25519PrivateKey) -> dict[str, str]:
    return {
        "issuer": "verified-pipeline-disposable-canary",
        "key_id": "ephemeral-canary-ed25519",
        "public_key_b64": base64.b64encode(
            signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii"),
    }


def _persist_execution_authority(
    control_db: Path,
    intake: dict[str, Any],
    materialization: dict[str, Any],
    signing_key: Ed25519PrivateKey,
    verifier: dict[str, str],
) -> dict[str, Any]:
    execution.init_execution_schema(control_db)
    authority = {
        "schema": execution.AUTHORIZATION_SCHEMA,
        "authority_key": f"canary:{intake['run_id']}:execute",
        "run_id": intake["run_id"],
        "materialization_key": materialization["idempotency_key"],
        "decision": execution.EXECUTION_DECISION,
        # The production consumer deliberately recognizes only the authenticated
        # owner principal. The disposable adapter records its canary identity in
        # the signed authentication-context digest instead of inventing a weaker
        # principal class.
        "principal": "owner",
        "authentication_context_sha256": execution._digest(
            {"adapter": "disposable-canary", "authenticated_principal": "owner"}
        ),
        "issuer": verifier["issuer"],
        "key_id": verifier["key_id"],
    }
    authority["signature_b64"] = base64.b64encode(
        signing_key.sign(execution._signed_bytes(authority))
    ).decode("ascii")
    conn = controller.connect(control_db)
    try:
        with controller._write_txn(conn):
            conn.execute(
                "INSERT INTO execution_authority_receipts "
                "(authority_key, materialization_key, run_id, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    authority["authority_key"],
                    materialization["idempotency_key"],
                    intake["run_id"],
                    execution._canonical(authority),
                    controller._now(),
                ),
            )
    finally:
        conn.close()
    return authority


def _persist_release_ready_authority(
    control_db: Path,
    execution_key: str,
    completion: dict[str, Any],
    signing_key: Ed25519PrivateKey,
    verifier: dict[str, str],
) -> dict[str, Any]:
    canonical_completion = dict(completion)
    canonical_completion.pop("replayed", None)
    authority = {
        "schema": release.RELEASE_READY_AUTH_SCHEMA,
        "authority_key": f"canary:{execution_key}:release-ready",
        "execution_key": execution_key,
        "decision": release.RELEASE_READY_DECISION,
        "completion_sha256": execution._digest(canonical_completion),
        "repository": canonical_completion["source_candidate"]["repository"],
        "base_ref": "sandbox",
        "head_sha": canonical_completion["source_candidate"]["commit_sha"],
        "evidence_sha256": hashlib.sha256(b"connected-canary-evidence").hexdigest(),
        "issuer": verifier["issuer"],
        "key_id": verifier["key_id"],
    }
    authority["signature_b64"] = base64.b64encode(
        signing_key.sign(execution._signed_bytes(authority))
    ).decode("ascii")
    conn = controller.connect(control_db)
    try:
        with controller._write_txn(conn):
            conn.execute(
                "INSERT INTO release_authority_receipts "
                "(authority_key, execution_key, decision, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    authority["authority_key"],
                    execution_key,
                    authority["decision"],
                    execution._canonical(authority),
                    controller._now(),
                ),
            )
    finally:
        conn.close()
    return authority


def _html(report: dict[str, Any]) -> str:
    stages = "".join(
        f"<li><b>{item['stage']}</b><span>{item['status']}</span></li>"
        for item in report["stages"]
    )
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Verified Pipeline Control-Plane Canary</title><style>
:root{{color-scheme:dark;--bg:#08111e;--panel:#121f33;--text:#edf4ff;--muted:#9eb0c9;--ok:#48dda4;--line:#2a4160}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 90% 0,#19345d,transparent 35%),var(--bg);color:var(--text);font:16px/1.5 system-ui,sans-serif}}main{{width:min(920px,calc(100% - 24px));margin:auto;padding:28px 0 60px}}section{{background:rgba(18,31,51,.94);border:1px solid var(--line);border-radius:20px;padding:24px;margin:14px 0}}h1{{font-size:clamp(2rem,7vw,3.6rem);line-height:1.02;margin:.4rem 0}}.ok{{color:var(--ok);font-weight:800}}.muted{{color:var(--muted)}}code{{color:#b9d0ff;overflow-wrap:anywhere}}ul{{list-style:none;padding:0;margin:0}}li{{display:flex;justify-content:space-between;gap:16px;padding:12px 0;border-top:1px solid var(--line)}}li:first-child{{border:0}}li span{{color:var(--ok);font-weight:700;text-align:right;overflow-wrap:anywhere}}@media(max-width:560px){{section{{padding:18px}}li{{display:block}}li span{{display:block;text-align:left;margin-top:4px}}}}
</style></head><body><main><section><div class='muted'>TIER 1 · DETERMINISTIC CONTROL-PLANE CANARY</div><h1>Control-plane canary {report['status']}</h1><p class='ok'>Zero hidden manual control-plane transitions</p><p>Run <code>{report['run_id']}</code> exercised dashboard decision binding through read-only release readiness using a deterministic sandbox worker adapter.</p><p class='muted'>This does not claim that host authentication was exercised or that live LLM worker profiles produced or reviewed an implementation artifact.</p></section><section><h2>Stages</h2><ul>{stages}</ul></section><section><h2>Safety boundary</h2><p>No merge authorization, merge result, deployment authorization, actuator invocation, installation, credential, production mutation, or live enablement occurred.</p></section></main></body></html>"""


def run(output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    home = output_dir / "hermes-home"
    kanban_path = output_dir / "kanban.db"
    workspaces = output_dir / "workspaces"
    os.environ["HERMES_HOME"] = str(home)
    os.environ["HERMES_KANBAN_DB"] = str(kanban_path)
    os.environ["HERMES_KANBAN_WORKSPACES_ROOT"] = str(workspaces)

    profiles = (
        controller.REVISION_PROFILE,
        controller.PLANNER_PROFILE,
        review.DA_PROFILE,
        review.CEO_PROFILE,
        *controller.IMPLEMENTATION_PROFILES,
    )
    for profile in profiles:
        _write_contract(home, profile)

    signing_key = Ed25519PrivateKey.generate()
    verifier = _verifier(signing_key)
    authority_policy = {
        release.EXECUTION_POLICY_KEY: verifier,
        release.RELEASE_READY_DECISION: verifier,
        release.MERGE_DECISION: verifier,
        release.MERGE_RESULT_DECISION: verifier,
        release.DEPLOY_DECISION: verifier,
    }
    os.environ[release.AUTHORITY_POLICY_PIN_ENV] = hashlib.sha256(
        execution._canonical(authority_policy).encode("utf-8")
    ).hexdigest()
    importlib.reload(release)

    app = FastAPI()

    @app.middleware("http")
    async def attach_deterministic_verified_session(request, call_next):
        # Exercise the plugin's trusted host-session boundary without claiming
        # that this disposable canary ran a real identity-provider login.
        request.state.session = Session(
            user_id="connected-canary-operator",
            email="canary@example.invalid",
            display_name="Connected Canary",
            org_id="canary",
            provider="deterministic-canary",
            expires_at=2_000_000_000,
            access_token="non-secret-canary-token",
            refresh_token="non-secret-canary-refresh",
        )
        return await call_next(request)

    app.include_router(router, prefix="/api/plugins/verified-pipeline")
    client = TestClient(app)
    created = client.post(
        "/api/plugins/verified-pipeline/intakes",
        json={
            "specification_id": "connected-canary",
            "revision": 1,
            "artifact_text": SPECIFICATION,
        },
    )
    created.raise_for_status()
    intake = created.json()
    decided = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/decision",
        headers={"user-agent": "verified-pipeline-connected-canary"},
        json={
            "request_id": "connected-canary-approval-1",
            "action": "approve",
            "decision_nonce": intake["decision_nonce"],
            "artifact_sha256": intake["artifact_sha256"],
        },
    )
    decided.raise_for_status()
    planner_id = decided.json()["projection"]["task_id"]
    decision_replay = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/decision",
        headers={"user-agent": "verified-pipeline-connected-canary"},
        json={
            "request_id": "connected-canary-approval-1",
            "action": "approve",
            "decision_nonce": intake["decision_nonce"],
            "artifact_sha256": intake["artifact_sha256"],
        },
    ).json()["decision"]["replayed"]

    _write_planner(Path(_task(kanban_path, planner_id).workspace_path))
    _complete(kanban_path, planner_id, "planner artifacts complete")
    first = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/review/reconcile"
    )
    first.raise_for_status()

    da = _latest(kanban_path, review.DA_PROFILE)
    _write_da(Path(da["workspace_path"]))
    _complete(kanban_path, da["id"], "DA premortem complete")
    second = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/review/reconcile"
    )
    second.raise_for_status()

    ceo = _latest(kanban_path, review.CEO_PROFILE)
    _write_ceo(Path(ceo["workspace_path"]))
    _complete(kanban_path, ceo["id"], "CEO decision complete")
    third = client.post(
        f"/api/plugins/verified-pipeline/intakes/{intake['run_id']}/review/reconcile"
    )
    third.raise_for_status()

    materialization = materializer.record_materialization_intent(
        run_id=intake["run_id"], source_task_id=ceo["id"], db_path=home / "plugin-data" / controller.PLUGIN_NAME / "pipeline-control.db"
    )
    control_db = home / "plugin-data" / controller.PLUGIN_NAME / "pipeline-control.db"
    projected = materializer.project_materialization(
        materialization["idempotency_key"],
        board=kanban_db.DEFAULT_BOARD,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    materialization_replay = materializer.project_materialization(
        materialization["idempotency_key"],
        board=kanban_db.DEFAULT_BOARD,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )["replayed"]
    authority = _persist_execution_authority(
        control_db, intake, materialization, signing_key, verifier
    )
    execution_intent = execution.record_execution_authorization(
        materialization_key=materialization["idempotency_key"],
        authority_key=authority["authority_key"],
        authority_verifier=verifier,
        db_path=control_db,
    )
    armed = execution.arm_execution(
        execution_intent["idempotency_key"],
        board=kanban_db.DEFAULT_BOARD,
        authority_verifier=verifier,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    arming_replay = execution.arm_execution(
        execution_intent["idempotency_key"],
        board=kanban_db.DEFAULT_BOARD,
        authority_verifier=verifier,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )["replayed"]

    for logical_id in ("build", "test", "integrate", "release"):
        task_id = projected["task_map"][logical_id]
        task = _task(kanban_path, task_id)
        if task.status != "ready":
            raise RuntimeError(f"native dependency gate did not promote {logical_id}: {task.status}")
        _complete(kanban_path, task_id, f"disposable {logical_id} stage complete")

    completion = execution.record_execution_completion(
        execution_intent["idempotency_key"],
        board=kanban_db.DEFAULT_BOARD,
        authority_verifier=verifier,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    completion_replay = execution.record_execution_completion(
        execution_intent["idempotency_key"],
        board=kanban_db.DEFAULT_BOARD,
        authority_verifier=verifier,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )["replayed"]
    release.init_release_schema(control_db, authority_verifiers=authority_policy)
    if completion.get("source_candidate") is not None:
        raise RuntimeError("artifact-only canary unexpectedly produced executable source custody")
    executable_evidence_rejected = False
    try:
        execution._assert_source_evidence_supported("02-builder")
    except execution.ExecutionError as exc:
        executable_evidence_rejected = (
            exc.code == "EXECUTION_EXECUTABLE_EVIDENCE_UNSUPPORTED"
        )
    if not executable_evidence_rejected:
        raise RuntimeError("Builder executable evidence did not fail closed")

    replay = {
        "decision": decision_replay,
        "materialization": materialization_replay,
        "arming": arming_replay,
        "completion": completion_replay,

    }

    conn = controller.connect(control_db)
    try:
        forbidden = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "merge_authorization_receipts",
                "merge_result_receipts",
                "deployment_authorization_receipts",
            )
        }
    finally:
        conn.close()
    if forbidden != {key: 0 for key in forbidden}:
        raise RuntimeError(f"forbidden authority escaped canary: {forbidden}")
    if not all(replay.values()):
        raise RuntimeError(f"canary replay did not converge: {replay}")

    report = {
        "schema": "verified-pipeline-connected-canary/v1",
        "canary_class": "deterministic-control-plane",
        "status": "PASS",
        "run_id": intake["run_id"],
        "task_count": len(_rows(kanban_path)),
        "implementation_task_map": projected["task_map"],
        "execution_key": execution_intent["idempotency_key"],
        "executable_evidence_rejected": executable_evidence_rejected,

        "replay": replay,
        "forbidden_authority_receipts": forbidden,
        "stages": [
            {"stage": "Dashboard API decision-byte binding (test client)", "status": "PASS"},
            {"stage": "Deterministic Planner contract artifacts", "status": "PASS"},
            {"stage": "Deterministic DA contract artifacts", "status": "PASS"},
            {"stage": "Deterministic CEO contract artifacts", "status": "PASS"},
            {"stage": "Exactly-once inert DAG", "status": "PASS"},
            {"stage": "Signed exact-scope arming", "status": armed["status"]},
            {
                "stage": "Contract-admitted Builder → Test → Integration → Release artifact gates",
                "status": "PASS",
            },
            {"stage": "Immutable generic graph completion", "status": completion["status"]},
            {
                "stage": "Executable release readiness unavailable without sandbox proof",
                "status": "PASS_FAIL_CLOSED",
            },
        ],
        "boundary": {
            "merge": False,
            "deployment": False,
            "installation": False,
            "credentials": False,
            "live_enablement": False,
            "actuator_invoked": False,
            "authenticated_host_session_exercised": False,
            "live_worker_profiles_exercised": False,
            "production_ready": False,
        },
    }
    (output_dir / "canary-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "canary-report.html").write_text(_html(report), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.output_dir)
    print(_canonical(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
