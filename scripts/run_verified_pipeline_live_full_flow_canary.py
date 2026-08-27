#!/usr/bin/env python3
"""Run a genuine disposable verified-pipeline flow through a closed GitHub PR.

The runner composes the live governance canary with signed materialization and
attachment-only implementation workers. After Builder, Test, and Integration
complete, it creates an acceptance-only GitHub commit/PR, waits for exact-head
required CI, attaches the handoff packet to Release, and dispatches genuine
Release review. It never records release-ready, merge, deployment, or live
authority and closes/deletes the disposable PR branch in a finally block.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from typing import Any
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import run_verified_pipeline_canary as deterministic
from scripts import run_verified_pipeline_live_governance_canary as governance


SOURCE_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_PROFILES = governance.GOVERNANCE_PROFILES + governance.MANDATORY_CONTRACT_PROFILES
CANARY_BYTES = b"verified-pipeline-canary\n"
REQUIRED_CHECK_NAME = "All required checks pass"
CANARY_COMMIT_IDENTITY = {
    "name": "github-actions[bot]",
    "email": "41898282+github-actions[bot]@users.noreply.github.com",
}
MAX_CHECK_RUNS = 1000
PR_DISCOVERY_ATTEMPTS = 30
REQUIRED_LOGICAL_TASKS = (
    "build-canary",
    "test-canary",
    "integrate-canary",
    "release-evidence",
)
FORBIDDEN_AUTHORITY_TABLES = (
    "release_ready_receipts",
    "merge_authorization_receipts",
    "merge_result_receipts",
    "deployment_authorization_receipts",
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _release_assignee() -> str:
    """Resolve the one release profile from the controller's admitted role set."""
    candidates = [
        profile
        for profile in governance.MANDATORY_CONTRACT_PROFILES
        if profile.endswith("-release")
    ]
    if len(candidates) != 1:
        raise RuntimeError(
            "full-flow acceptance requires exactly one admitted release profile"
        )
    return candidates[0]


def _clean_source_head() -> str:
    status = _run(["git", "-C", str(SOURCE_ROOT), "status", "--porcelain"])
    if status.stdout.strip():
        raise RuntimeError("live full-flow acceptance requires a clean committed source tree")
    head = _run(["git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"]).stdout.strip().lower()
    if len(head) != 40:
        raise RuntimeError("source HEAD is not an exact 40-hex commit")
    return head


def _canary_commit_identity(source_head: str) -> dict[str, str]:
    """Return a fixed automation identity for a source-bound disposable commit."""
    if len(source_head) != 40 or any(character not in "0123456789abcdef" for character in source_head):
        raise RuntimeError("canary commit identity requires an exact lowercase 40-hex source head")
    return dict(CANARY_COMMIT_IDENTITY)


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _sensitive_report_key(key: str) -> bool:
    lowered = key.lower()
    return (
        lowered == "auth"
        or lowered.startswith("auth_")
        or lowered.endswith("_auth")
        or "authentication" in lowered
        or "authorization" in lowered
        or "credential" in lowered
        or "token" in lowered
        or "secret" in lowered
        or "password" in lowered
    )


def _redacted_report(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _redacted_report(item)
            for key, item in value.items()
            if not _sensitive_report_key(key)
        }
    if isinstance(value, list):
        return [_redacted_report(item) for item in value]
    if isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in ("auth.json", "bearer ", "access_token", "refresh_token")):
            return "[redacted-sensitive-string]"
    return value


def _run(
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
        timeout=timeout,
    )


def _gh_json(args: list[str], *, payload: dict[str, Any] | None = None) -> Any:
    command = ["gh", *args]
    input_text = None
    if payload is not None:
        command.extend(["--input", "-"])
        input_text = json.dumps(payload)
    result = _run(command, input_text=input_text)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"GitHub command returned non-JSON output: {' '.join(command)}") from exc


def _all_check_runs(repository: str, head_sha: str) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    expected_total: int | None = None
    page = 1
    while True:
        payload = _gh_json(
            [
                "api",
                f"repos/{repository}/commits/{head_sha}/check-runs?filter=all&per_page=100&page={page}",
            ]
        )
        total = payload.get("total_count")
        page_runs = payload.get("check_runs")
        if not isinstance(total, int) or total < 0 or not isinstance(page_runs, list):
            raise RuntimeError("GitHub check-runs response is malformed")
        if total > MAX_CHECK_RUNS:
            raise RuntimeError(f"GitHub check-runs exceeds bounded audit cap: {total}")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise RuntimeError("GitHub check-runs total drifted during pagination")
        if any(not isinstance(item, dict) for item in page_runs):
            raise RuntimeError("GitHub check-runs page contains a malformed item")
        runs.extend(page_runs)
        if len(runs) >= total or not page_runs:
            break
        page += 1
        if page > 10:
            raise RuntimeError("GitHub check-runs pagination exceeded bounded page cap")
    if expected_total is None or len(runs) != expected_total:
        raise RuntimeError(
            f"GitHub check-runs pagination was incomplete: expected={expected_total} observed={len(runs)}"
        )
    return runs


def _assert_ref_absent(repository: str, branch: str) -> None:
    encoded = quote(branch, safe="")
    probe = _run(
        ["gh", "api", f"repos/{repository}/git/ref/heads/{encoded}"],
        check=False,
    )
    if probe.returncode == 0:
        raise RuntimeError(f"refusing to overwrite pre-existing disposable branch: {branch}")
    if "HTTP 404" not in probe.stderr:
        raise RuntimeError(f"unable to prove disposable branch is absent: {probe.stderr.strip()}")


def _create_ref(repository: str, branch: str, head_sha: str) -> None:
    result = _run(
        ["gh", "api", "-X", "POST", f"repos/{repository}/git/refs", "--input", "-"],
        input_text=json.dumps({"ref": f"refs/heads/{branch}", "sha": head_sha}),
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "GitHub ref creation returned nonzero")
    try:
        created = json.loads(result.stdout)
        created_ref = created.get("ref")
        created_sha = str((created.get("object") or {}).get("sha") or "").lower()
    except (AttributeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub ref creation returned malformed custody evidence") from exc
    if created_ref != f"refs/heads/{branch}" or created_sha != head_sha:
        raise RuntimeError("GitHub ref creation custody evidence did not match exact ref and head")


def _github_handoff(
    *,
    repository: str,
    base_ref: str,
    branch: str,
    artifact_path: str,
    artifact_bytes: bytes,
    run_id: str,
    timeout_seconds: int,
    cleanup_context: dict[str, Any],
    source_head: str | None = None,
) -> dict[str, Any]:
    if repository.count("/") != 1 or not all(repository.split("/")):
        raise RuntimeError("GitHub repository must be owner/name")
    if not branch.startswith("fleet/acceptance-canary-"):
        raise RuntimeError("GitHub branch is outside the disposable canary namespace")
    if artifact_path.startswith("/") or ".." in Path(artifact_path).parts:
        raise RuntimeError("GitHub artifact path is unsafe")
    cleanup_context.update(
        {
            "repository": repository,
            "branch": branch,
            "ref_created": False,
            "pull_request": None,
            "head_sha": None,
            "ref_creation_attempted": False,
            "ref_creation_ambiguous": False,
            "pr_creation_attempted": False,
        }
    )
    try:
        protection = _gh_json(
            [
                "api",
                f"repos/{repository}/branches/{quote(base_ref, safe='')}/protection/required_status_checks",
            ]
        )
        protected_checks = protection.get("checks")
        protected_contexts = {str(item) for item in protection.get("contexts", []) if item}
        protected_check = protected_checks[0] if isinstance(protected_checks, list) and len(protected_checks) == 1 else None
        required_app_id = protected_check.get("app_id") if isinstance(protected_check, dict) else None
        if (
            protection.get("strict") is not True
            or protected_contexts != {REQUIRED_CHECK_NAME}
            or not isinstance(protected_check, dict)
            or protected_check.get("context") != REQUIRED_CHECK_NAME
            or not isinstance(required_app_id, int)
            or isinstance(required_app_id, bool)
            or required_app_id <= 0
        ):
            raise RuntimeError(
                "GitHub branch protection drifted from the exact strict app-bound aggregator"
            )
        if not isinstance(source_head, str):
            raise RuntimeError("GitHub canary commit requires an exact source head")
        commit_identity = _canary_commit_identity(source_head)
        base = _gh_json(["api", f"repos/{repository}/commits/{quote(base_ref, safe='')}"])
        base_sha = str(base.get("sha") or "").lower()
        base_tree = str(((base.get("commit") or {}).get("tree") or {}).get("sha") or "").lower()
        if len(base_sha) != 40 or len(base_tree) != 40:
            raise RuntimeError("GitHub base commit response is incomplete")
        blob = _gh_json(
            ["api", "-X", "POST", f"repos/{repository}/git/blobs"],
            payload={"content": artifact_bytes.decode("utf-8"), "encoding": "utf-8"},
        )
        blob_sha = str(blob.get("sha") or "").lower()
        tree = _gh_json(
            ["api", "-X", "POST", f"repos/{repository}/git/trees"],
            payload={
                "base_tree": base_tree,
                "tree": [{"path": artifact_path, "mode": "100644", "type": "blob", "sha": blob_sha}],
            },
        )
        tree_sha = str(tree.get("sha") or "").lower()
        commit = _gh_json(
            ["api", "-X", "POST", f"repos/{repository}/git/commits"],
            payload={
                "message": f"test: disposable verified-pipeline acceptance {run_id}",
                "tree": tree_sha,
                "parents": [base_sha],
                "author": dict(commit_identity),
                "committer": dict(commit_identity),
            },
        )
        head_sha = str(commit.get("sha") or "").lower()
        if len(blob_sha) != 40 or len(tree_sha) != 40 or len(head_sha) != 40:
            raise RuntimeError("GitHub object creation returned an invalid SHA")
        cleanup_context["head_sha"] = head_sha
        _assert_ref_absent(repository, branch)
        cleanup_context["ref_creation_attempted"] = True
        try:
            _create_ref(repository, branch, head_sha)
        except Exception:
            cleanup_context["ref_creation_ambiguous"] = True
            raise
        cleanup_context["ref_created"] = True
        cleanup_context["pr_creation_attempted"] = True
        pull = _gh_json(
            ["api", "-X", "POST", f"repos/{repository}/pulls"],
            payload={
                "title": f"test: disposable verified-pipeline acceptance {run_id}",
                "head": branch,
                "base": base_ref,
                "body": (
                    "Automated disposable full-flow acceptance handoff. "
                    "This PR must never merge and will be closed after exact-head Release review."
                ),
            },
        )
        number = pull.get("number")
        url = str(pull.get("html_url") or "")
        if not isinstance(number, int) or number <= 0 or not url.startswith("https://github.com/"):
            raise RuntimeError("GitHub pull request response is incomplete")
        cleanup_context.update({"pull_request": number, "pull_request_url": url})
        deadline = time.monotonic() + timeout_seconds
        last_check: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            exact = _gh_json(
                ["pr", "view", str(number), "--repo", repository, "--json", "headRefOid,state,url"]
            )
            if str(exact.get("headRefOid") or "").lower() != head_sha:
                raise RuntimeError("GitHub PR head drifted from the exact canary commit")
            runs = _all_check_runs(repository, head_sha)
            exact_runs = [
                item
                for item in runs
                if item.get("name") == REQUIRED_CHECK_NAME
                and str(item.get("head_sha") or "").lower() == head_sha
            ]
            if len(exact_runs) > 1:
                raise RuntimeError(f"{REQUIRED_CHECK_NAME} exact-head evidence is ambiguous")
            if exact_runs:
                observed = exact_runs[0]
                last_check = {
                    "name": observed.get("name"),
                    "head_sha": str(observed.get("head_sha") or "").lower(),
                    "app_slug": (observed.get("app") or {}).get("slug"),
                    "app_id": (observed.get("app") or {}).get("id"),
                    "status": observed.get("status"),
                    "conclusion": observed.get("conclusion"),
                    "details_url": observed.get("details_url"),
                    "completed_at": observed.get("completed_at"),
                }
                if last_check["status"] == "completed":
                    if last_check["app_slug"] != "github-actions" or last_check["app_id"] != required_app_id:
                        raise RuntimeError(f"{REQUIRED_CHECK_NAME} came from an unexpected app: {last_check}")
                    if last_check["conclusion"] != "success":
                        raise RuntimeError(f"{REQUIRED_CHECK_NAME} failed for exact head: {last_check}")
                    return {
                        "schema": "verified-pipeline/github-handoff/v1",
                        "repository": repository,
                        "base_ref": base_ref,
                        "base_sha": base_sha,
                        "branch_protection": {
                            "strict": True,
                            "required_contexts": [REQUIRED_CHECK_NAME],
                            "required_app_id": required_app_id,
                        },
                        "branch": branch,
                        "head_sha": head_sha,
                        "tree_sha": tree_sha,
                        "blob_sha": blob_sha,
                        "artifact_path": artifact_path,
                        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                        "pull_request": number,
                        "pull_request_url": url,
                        "required_check": last_check,
                        "merge_authority": False,
                    }
            time.sleep(10)
        raise TimeoutError(f"GitHub {REQUIRED_CHECK_NAME} timed out: {last_check}")
    except Exception as exc:
        cleanup = _cleanup_github_handoff(cleanup_context)
        if not (cleanup["pr_closed"] and cleanup["branch_deleted"]):
            raise RuntimeError(f"GitHub handoff failed and cleanup did not converge: {cleanup}") from exc
        raise


def _cleanup_github_handoff(handoff: dict[str, Any] | None) -> dict[str, Any]:
    if not handoff:
        return {"pr_closed": True, "branch_deleted": True, "not_created": True}
    repository = handoff["repository"]
    number = handoff.get("pull_request")
    branch = handoff["branch"]
    expected_head = handoff.get("head_sha")
    attempted = bool(handoff.get("pr_creation_attempted"))
    close_errors: list[str] = []
    numbers: list[int] = [number] if isinstance(number, int) else []

    if not numbers and attempted:
        discovered: list[dict[str, Any]] | None = None
        for attempt in range(PR_DISCOVERY_ATTEMPTS):
            listed = _run(
                [
                    "gh",
                    "pr",
                    "list",
                    "--repo",
                    repository,
                    "--head",
                    branch,
                    "--state",
                    "all",
                    "--limit",
                    "100",
                    "--json",
                    "number,state,headRefOid,url",
                ],
                check=False,
            )
            if listed.returncode == 0:
                try:
                    candidate = json.loads(listed.stdout)
                    if isinstance(candidate, list):
                        discovered = candidate
                except json.JSONDecodeError:
                    discovered = None
            if discovered:
                break
            if attempt < PR_DISCOVERY_ATTEMPTS - 1:
                time.sleep(1)
        if not discovered:
            close_errors.append("unable to prove no PR exists after ambiguous creation attempt")
        elif not all(
            isinstance(item, dict)
            and isinstance(item.get("number"), int)
            and not isinstance(item.get("number"), bool)
            and int(item["number"]) > 0
            for item in discovered
        ):
            close_errors.append("refused malformed PR discovery response")
        elif len({int(item["number"]) for item in discovered}) != len(discovered):
            close_errors.append("refused duplicate PR discovery response")
        elif any(str(item.get("headRefOid") or "").lower() != expected_head for item in discovered):
            close_errors.append("refused to close discovered PR with mismatched head identity")
        else:
            numbers = sorted(int(item["number"]) for item in discovered)

    closed_numbers: list[int] = []
    if not close_errors:
        for pr_number in numbers:
            closed = _run(
                [
                    "gh",
                    "pr",
                    "close",
                    str(pr_number),
                    "--repo",
                    repository,
                    "--comment",
                    "Disposable acceptance completed; closing without merge.",
                ],
                check=False,
            )
            state = _run(
                ["gh", "pr", "view", str(pr_number), "--repo", repository, "--json", "state,headRefOid"],
                check=False,
            )
            try:
                state_payload = json.loads(state.stdout)
                identity_ok = expected_head is None or str(state_payload.get("headRefOid") or "").lower() == expected_head
                state_ok = state.returncode == 0 and state_payload.get("state") == "CLOSED"
            except (AttributeError, json.JSONDecodeError):
                identity_ok = False
                state_ok = False
            if identity_ok and state_ok:
                closed_numbers.append(pr_number)
            else:
                close_errors.append((closed.stderr + state.stderr).strip() or f"PR {pr_number} did not verify CLOSED")
    pr_closed = not close_errors and len(closed_numbers) == len(numbers)

    branch_deleted = not handoff.get("ref_created", True)
    delete_error = ""
    if handoff.get("ref_creation_ambiguous"):
        branch_deleted = False
        delete_error = "refused cleanup because ref creation ownership remained ambiguous"
    elif handoff.get("ref_created", True) and not pr_closed:
        branch_deleted = False
        delete_error = "refused to delete disposable branch before PR closure was proven"
    elif handoff.get("ref_created", True):
        encoded = quote(branch, safe="")
        ref_path = f"repos/{repository}/git/ref/heads/{encoded}"
        current = _run(["gh", "api", ref_path], check=False)
        if current.returncode != 0 and "HTTP 404" in current.stderr:
            branch_deleted = True
        elif current.returncode != 0:
            branch_deleted = False
            delete_error = current.stderr.strip() or "unable to read disposable branch before cleanup"
        else:
            try:
                current_sha = str((json.loads(current.stdout).get("object") or {}).get("sha") or "").lower()
            except (AttributeError, json.JSONDecodeError):
                current_sha = ""
            if expected_head is None or current_sha != expected_head:
                branch_deleted = False
                delete_error = (
                    "refused to delete disposable branch with mismatched head identity: "
                    f"expected={expected_head} observed={current_sha or 'invalid'}"
                )
            else:
                deleted = _run(
                    ["gh", "api", "-X", "DELETE", f"repos/{repository}/git/refs/heads/{encoded}"],
                    check=False,
                )
                absent = _run(["gh", "api", ref_path], check=False)
                branch_deleted = absent.returncode != 0 and "HTTP 404" in absent.stderr
                delete_error = (deleted.stderr + absent.stderr).strip() if not branch_deleted else ""
    return {
        "pr_closed": pr_closed,
        "branch_deleted": branch_deleted,
        "close_error": "; ".join(item for item in close_errors if item),
        "delete_error": delete_error,
        "closed_pull_requests": closed_numbers,
    }


def _attachment_manifest(kanban_db: Any, conn: sqlite3.Connection, task_id: str) -> list[dict[str, Any]]:
    manifest = []
    for attachment in kanban_db.list_attachments(conn, task_id):
        if attachment.task_id != task_id:
            raise RuntimeError(f"attachment task custody drifted: expected={task_id} observed={attachment.task_id}")
        path = Path(attachment.stored_path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if attachment.size != path.stat().st_size:
            raise RuntimeError(f"attachment custody drifted for task {task_id}: {attachment.filename}")
        if attachment.sha256 is not None and attachment.sha256 != digest:
            raise RuntimeError(f"attachment custody drifted for task {task_id}: {attachment.filename}")
        if attachment.uploaded_by == "kanban_complete" and attachment.sha256 is None:
            raise RuntimeError(
                f"completion attachment lacks an admitted digest for task {task_id}: {attachment.filename}"
            )
        manifest.append(
            {
                "attachment_id": attachment.id,
                "task_id": attachment.task_id,
                "filename": attachment.filename,
                "stored_path": attachment.stored_path,
                "size": attachment.size,
                "sha256": digest,
                "admitted_sha256": attachment.sha256,
                "uploaded_by": attachment.uploaded_by,
                "created_at": attachment.created_at,
            }
        )
    completed = [item for item in manifest if item["uploaded_by"] == "kanban_complete"]
    if not completed:
        raise RuntimeError(f"task produced no durable completion attachment: {task_id}")
    return manifest


def _dispatch_exact_task(
    *,
    task_id: str,
    kanban_path: Path,
    conn: sqlite3.Connection,
    kanban_db: Any,
    timeout_seconds: int,
) -> dict[str, Any]:
    row = governance._task(kanban_path, task_id)
    if row["status"] != "ready":
        raise RuntimeError(f"expected ready implementation task {task_id}, got {row['status']}")
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
        raise RuntimeError(f"dispatcher did not spawn implementation task {task_id}: {result}")
    spawned = governance._task(kanban_path, task_id)
    if spawned["status"] not in {"running", "done"}:
        raise RuntimeError(f"dispatcher spawned a different task before {task_id}: {spawned['status']}")
    runtime_worker_pid = (
        int(spawned["worker_pid"]) if spawned.get("worker_pid") is not None else None
    )
    deadline = time.monotonic() + timeout_seconds
    terminal = spawned
    while terminal["status"] not in {"done", "blocked", "todo", "ready"} and time.monotonic() < deadline:
        time.sleep(2)
        terminal = governance._task(kanban_path, task_id)
        if terminal.get("worker_pid") is not None:
            runtime_worker_pid = int(terminal["worker_pid"])
    if terminal["status"] in {"done", "blocked", "todo", "ready"}:
        # Terminal transitions clear task.worker_pid atomically.  Drain the
        # last PID observed while the task was running before profile logs,
        # session state, and accounting databases can be scrubbed.
        governance._drain_worker_process(runtime_worker_pid)
    else:
        governance._terminate_worker_groups(kanban_path)
        raise TimeoutError(f"implementation task timed out without redispatch: {task_id}")
    if terminal["status"] != "done":
        raise RuntimeError(
            f"implementation task did not complete: {task_id} status={terminal['status']} "
            f"error={terminal.get('last_failure_error')}"
        )
    terminal["runtime_worker_pid"] = runtime_worker_pid
    return terminal


def _release_run_authority(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    expected_profile: str,
) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT id, task_id, profile, status, outcome, started_at, ended_at "
        "FROM task_runs WHERE task_id = ? ORDER BY id ASC",
        (task_id,),
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError(f"expected exactly one Release worker run, observed={len(rows)}")
    row = rows[0]
    authority = {key: row[key] for key in row.keys()}
    if (
        authority["task_id"] != task_id
        or authority["profile"] != expected_profile
        or authority["status"] != "done"
        or authority["outcome"] != "completed"
        or not isinstance(authority["started_at"], int)
        or not isinstance(authority["ended_at"], int)
        or authority["ended_at"] < authority["started_at"]
    ):
        raise RuntimeError(f"Release worker run authority did not verify: {authority}")
    return authority


def _release_completion_authority(
    conn: sqlite3.Connection,
    *,
    terminal: dict[str, Any],
    task_id: str,
    assignee: str,
) -> dict[str, Any]:
    """Bind the terminal Release identity to its one durable worker run."""
    if terminal.get("id") != task_id or terminal.get("assignee") != assignee:
        raise RuntimeError(
            "completed Release task identity did not match the designated authority"
        )
    return _release_run_authority(
        conn,
        task_id=task_id,
        expected_profile=assignee,
    )


def _forbidden_authority_counts(control_db: Path) -> dict[str, int]:
    conn = sqlite3.connect(control_db)
    try:
        counts: dict[str, int] = {}
        for table in FORBIDDEN_AUTHORITY_TABLES:
            present = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (table,)
            ).fetchone()
            counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if present else 0
        return counts
    finally:
        conn.close()


def _release_output_contract(
    run_id: str,
    handoff: dict[str, Any],
    *,
    release_task_id: str,
    release_assignee: str,
) -> dict[str, Any]:
    check_sha256 = hashlib.sha256(_canonical(handoff["required_check"]).encode()).hexdigest()
    return {
        "schema": "verified-pipeline/full-flow-final-review-contract/v1",
        "machine_filename": "final-review.json",
        "human_filename_suffixes": [".html", ".md"],
        "required_exact_fields": {
            "schema": "verified-pipeline/full-flow-final-review/v1",
            "run_id": run_id,
            "release_task_id": release_task_id,
            "release_assignee": release_assignee,
            "verdict": "READY_FOR_JASON",
            "repository": handoff["repository"],
            "pull_request": handoff["pull_request"],
            "pull_request_url": handoff["pull_request_url"],
            "head_sha": handoff["head_sha"],
            "required_check_sha256": check_sha256,
            "merge_authority": False,
        },
        "required_human_content": [
            "READY_FOR_JASON",
            release_task_id,
            release_assignee,
            handoff["head_sha"],
            handoff["pull_request_url"],
        ],
    }


def _release_contract_instruction() -> str:
    """Tell Release where the controller-owned exact output contract lives."""
    return """## Controller final-review contract (mandatory)

Before producing output, call `kanban_attachments` for this task and read the
`inline_text` of `github-handoff.json`. Its `required_output_contract` is the
authoritative output schema. Produce exactly the requested `final-review.json`
and exactly one requested human-readable `.md` or `.html` review, then declare
both files through `kanban_complete(artifacts=[...])`. Do not substitute a
generic release-evidence file or a different verdict. The controller will
independently validate exact fields, content bindings, worker identity, and
artifact custody. This remains evidence-only: no merge, deployment, publish,
promotion, operation, or release authority is granted.
"""


def _validate_release_review(
    release_manifest: list[dict[str, Any]],
    contract: dict[str, Any],
    release_authority: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    completed = [item for item in release_manifest if item["uploaded_by"] == "kanban_complete"]
    expected_task_id = contract["required_exact_fields"]["release_task_id"]
    expected_assignee = contract["required_exact_fields"]["release_assignee"]
    if (
        release_authority.get("task_id") != expected_task_id
        or release_authority.get("profile") != expected_assignee
        or release_authority.get("status") != "done"
        or release_authority.get("outcome") != "completed"
    ):
        raise RuntimeError("Release worker-run authority does not match the output contract")
    if not completed or any(item.get("task_id") != expected_task_id for item in completed):
        raise RuntimeError("Release artifacts are not bound to the designated Release task")
    expected_machine_filename = contract["machine_filename"]
    expected_human_filenames = {
        f"final-review{suffix}" for suffix in contract["human_filename_suffixes"]
    }
    permitted_filenames = {expected_machine_filename, *expected_human_filenames}
    if any(item.get("filename") not in permitted_filenames for item in completed):
        raise RuntimeError("Release completion contains an unrequested artifact")
    if any(
        not isinstance(item.get("created_at"), int)
        or item["created_at"] < release_authority["started_at"]
        or item["created_at"] > release_authority["ended_at"]
        for item in completed
    ):
        raise RuntimeError("Release artifacts are not bound to the designated worker-run interval")
    machine = [item for item in completed if item["filename"] == contract["machine_filename"]]
    if len(machine) != 1:
        raise RuntimeError("Release final-review.json is missing or ambiguous")
    try:
        payload = json.loads(Path(machine[0]["stored_path"]).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Release final-review.json is unreadable or invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Release final-review.json must be a JSON object")
    if set(payload) != set(contract["required_exact_fields"]):
        raise RuntimeError("Release final-review.json has an unexpected or missing machine key")
    for key, expected in contract["required_exact_fields"].items():
        if payload.get(key) != expected:
            raise RuntimeError(f"Release final-review.json binding mismatch: {key}")
    human = [item for item in completed if item["filename"] in expected_human_filenames]
    if len(human) != 1:
        raise RuntimeError("Release human-readable final review is missing or ambiguous")
    try:
        review_text = Path(human[0]["stored_path"]).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError("Release human-readable final review is unreadable") from exc
    for exact_text in contract["required_human_content"]:
        if exact_text not in review_text:
            raise RuntimeError(f"Release human review is not exact-evidence-bound: {exact_text}")
    return machine[0], human[0]


def _html_report(report: dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(item['stage'])}</td><td>{html.escape(item['status'])}</td></tr>"
        for item in report.get("stages", [])
    )
    handoff = report.get("github_handoff") or {}
    pr_url = html.escape(str(handoff.get("pull_request_url") or "not created"))
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Verified Pipeline Full-Flow Acceptance</title>
<style>body{{font:16px system-ui;max-width:960px;margin:40px auto;padding:0 20px;background:#0b1020;color:#e8ecf6}}h1{{color:#8bd5ff}}table{{border-collapse:collapse;width:100%}}td{{padding:10px;border-bottom:1px solid #29324a}}td:last-child{{font-weight:700;color:#9ee6a3}}code{{color:#ffd580}}</style></head><body>
<h1>Verified Pipeline Full-Flow Acceptance — {html.escape(report['status'])}</h1>
<p>Source <code>{html.escape(report.get('source_head',''))}</code></p>
<p>Disposable PR: {pr_url}</p><table>{rows}</table>
<p><b>Boundary:</b> no merge, release-ready, deployment, installation, gateway, or live activation authority.</p>
</body></html>"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--credential-source-home", type=Path, required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--base-ref", default="fleet/main")
    parser.add_argument("--allow-live-github-handoff", action="store_true")
    parser.add_argument("--task-timeout", type=int, default=900)
    parser.add_argument("--github-timeout", type=int, default=1200)
    args = parser.parse_args()
    if not args.allow_live_github_handoff:
        raise SystemExit("refusing live GitHub handoff without --allow-live-github-handoff")
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"refusing non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    report_path = output / "run-report.json"
    html_path = output / "final-review.html"
    governance_output = output / "governance"
    source_head = _clean_source_head()
    report: dict[str, Any] = {
        "schema": "verified-pipeline/live-full-flow-acceptance/v1",
        "source_head": source_head,
        "started_at_epoch": int(time.time()),
        "status": "STARTING",
        "stages": [],
        "boundary": {
            "merge": False,
            "release_ready": False,
            "deployment": False,
            "installation": False,
            "gateway": False,
            "live_activation": False,
        },
    }
    handoff: dict[str, Any] | None = None
    cleanup_context: dict[str, Any] = {}
    runtime_home = governance_output / "runtime-home"
    kanban_path = governance_output / "kanban.db"
    exit_code = 1
    try:
        governance_command = [
            sys.executable,
            str(SOURCE_ROOT / "scripts" / "run_verified_pipeline_live_governance_canary.py"),
            "--output-dir",
            str(governance_output),
            "--credential-source-home",
            str(args.credential_source_home),
            "--task-timeout",
            str(args.task_timeout),
            "--max-tasks",
            "8",
        ]
        completed = _run(governance_command, timeout=max(600, args.task_timeout * 4))
        governance_report = json.loads((governance_output / "run-report.json").read_text(encoding="utf-8"))
        if completed.returncode != 0 or governance_report.get("status") != "PASS":
            raise RuntimeError(f"genuine governance stage failed: {governance_report.get('error')}")
        report["governance"] = _redacted_report(governance_report)
        report["run_id"] = governance_report["run_id"]
        report["stages"].append({"stage": "Genuine Planner → DA → CEO governance", "status": "PASS"})
        _write_json(report_path, _redacted_report(report))

        credential_auth = governance._validated_credential_auth(args.credential_source_home)
        profile_snapshot = governance._snapshot_profiles(
            runtime_home,
            credential_auth=credential_auth,
            active_profiles=ACTIVE_PROFILES,
        )
        report["implementation_profile_snapshot"] = _redacted_report(profile_snapshot)
        os.environ.update(
            {
                "HERMES_HOME": str(runtime_home),
                "HERMES_KANBAN_DB": str(kanban_path),
                "HERMES_KANBAN_WORKSPACES_ROOT": str(governance_output / "workspaces"),
                "HERMES_KANBAN_HOME": str(governance_output / "kanban-home"),
                "HERMES_KANBAN_BOARD": "default",
                "HERMES_BIN": str(SOURCE_ROOT / ".venv" / "bin" / "hermes"),
                "PYTHONPATH": str(SOURCE_ROOT),
            }
        )

        from hermes_cli import kanban_db
        from plugins.verified_pipeline import controller
        from plugins.verified_pipeline import execution, materializer

        control_db = runtime_home / "plugin-data" / controller.PLUGIN_NAME / "pipeline-control.db"
        ceo_rows = [row for row in governance._task_rows(kanban_path) if row["assignee"] == "01-ceo"]
        if len(ceo_rows) != 1 or ceo_rows[0]["status"] != "done":
            raise RuntimeError("genuine CEO approval task is missing or non-terminal")
        materialization = materializer.record_materialization_intent(
            run_id=governance_report["run_id"],
            source_task_id=ceo_rows[0]["id"],
            db_path=control_db,
        )
        projected = materializer.project_materialization(
            materialization["idempotency_key"],
            board=kanban_db.DEFAULT_BOARD,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
        if set(projected["task_map"]) != set(REQUIRED_LOGICAL_TASKS):
            raise RuntimeError(f"materialized plan task identity drifted: {projected['task_map']}")
        signing_key = Ed25519PrivateKey.generate()
        verifier = deterministic._verifier(signing_key)
        authority = deterministic._persist_execution_authority(
            control_db, governance_report, materialization, signing_key, verifier
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
        report["materialization"] = materialization
        report["implementation_task_map"] = projected["task_map"]
        report["execution_key"] = execution_intent["idempotency_key"]
        report["stages"].append({"stage": "Signed materialization and execution arming", "status": armed["status"]})

        conn = kanban_db.connect(db_path=kanban_path)
        try:
            manifests: dict[str, list[dict[str, Any]]] = {}
            for logical_id in REQUIRED_LOGICAL_TASKS[:3]:
                task_id = projected["task_map"][logical_id]
                terminal = _dispatch_exact_task(
                    task_id=task_id,
                    kanban_path=kanban_path,
                    conn=conn,
                    kanban_db=kanban_db,
                    timeout_seconds=args.task_timeout,
                )
                manifests[logical_id] = _attachment_manifest(kanban_db, conn, task_id)
                report["stages"].append(
                    {"stage": f"Genuine {terminal['assignee']} worker", "status": "PASS"}
                )
                _write_json(report_path, _redacted_report(report))
            builder = [item for item in manifests["build-canary"] if item["filename"] == "canary.txt"]
            if len(builder) != 1 or Path(builder[0]["stored_path"]).read_bytes() != CANARY_BYTES:
                raise RuntimeError("Builder canary.txt exact bytes are missing or ambiguous")

            branch = f"fleet/acceptance-canary-{governance_report['run_id'].replace('_', '-')[:48]}"
            artifact_path = f"acceptance-artifacts/{governance_report['run_id']}/canary.txt"
            handoff = _github_handoff(
                repository=args.github_repository,
                base_ref=args.base_ref,
                branch=branch,
                artifact_path=artifact_path,
                artifact_bytes=CANARY_BYTES,
                run_id=governance_report["run_id"],
                timeout_seconds=args.github_timeout,
                cleanup_context=cleanup_context,
                source_head=source_head,
            )
            release_task_id = projected["task_map"]["release-evidence"]
            release_row = governance._task(kanban_path, release_task_id)
            release_assignee = _release_assignee()
            if release_row.get("assignee") != release_assignee:
                raise RuntimeError(
                    f"release-evidence authority drifted: expected={release_assignee} "
                    f"observed={release_row.get('assignee')}"
                )
            release_contract = _release_output_contract(
                governance_report["run_id"],
                handoff,
                release_task_id=release_task_id,
                release_assignee=release_assignee,
            )
            evidence_packet = {
                "schema": "verified-pipeline/full-flow-release-evidence/v1",
                "run_id": governance_report["run_id"],
                "stage_attachments": manifests,
                "github_handoff": handoff,
                "required_output_contract": release_contract,
                "boundary": "acceptance review only; PR must not merge",
            }
            kanban_db.store_attachment_bytes(
                conn,
                release_task_id,
                "github-handoff.json",
                (json.dumps(evidence_packet, indent=2, sort_keys=True) + "\n").encode(),
                content_type="application/json",
                uploaded_by="verified-pipeline-full-flow-controller",
                board=kanban_db.DEFAULT_BOARD,
            )
            kanban_db.add_comment(
                conn,
                release_task_id,
                "verified-pipeline-full-flow-controller",
                _release_contract_instruction(),
            )
            report["github_handoff"] = handoff
            report["stages"].append({"stage": "Controller-owned disposable GitHub PR and exact-head CI", "status": "PASS"})
            release_terminal = _dispatch_exact_task(
                task_id=release_task_id,
                kanban_path=kanban_path,
                conn=conn,
                kanban_db=kanban_db,
                timeout_seconds=args.task_timeout,
            )
            release_authority = _release_completion_authority(
                conn,
                terminal=release_terminal,
                task_id=release_task_id,
                assignee=release_assignee,
            )
            release_manifest = _attachment_manifest(kanban_db, conn, release_task_id)
            manifests["release-evidence"] = release_manifest
            machine_review, human_review = _validate_release_review(
                release_manifest,
                release_contract,
                release_authority,
            )
            report["release_worker_authority"] = release_authority
            report["stage_attachments"] = manifests
            report["release_review_machine_artifact"] = machine_review
            report["release_review_artifact"] = human_review
            report["stages"].append(
                {"stage": f"Genuine {release_terminal['assignee']} final review", "status": "PASS"}
            )
        finally:
            conn.close()

        completion = execution.record_execution_completion(
            execution_intent["idempotency_key"],
            board=kanban_db.DEFAULT_BOARD,
            authority_verifier=verifier,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
        if completion.get("source_candidate") is not None:
            raise RuntimeError("attachment-only acceptance unexpectedly claimed executable source custody")
        report["completion_sha256"] = execution._digest(
            {key: value for key, value in completion.items() if key != "replayed"}
        )
        forbidden = _forbidden_authority_counts(control_db)
        if any(forbidden.values()):
            raise RuntimeError(f"forbidden authority receipts escaped acceptance: {forbidden}")
        report["forbidden_authority_receipts"] = forbidden
        report["stages"].append({"stage": "Immutable aggregate completion and authority boundary", "status": "PASS"})
        report["status"] = "PASS"
        exit_code = 0
    except Exception as exc:
        report["status"] = "FAIL"
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)
    finally:
        governance._terminate_worker_groups(kanban_path)
        cleanup = _cleanup_github_handoff(cleanup_context)
        report["github_cleanup"] = cleanup
        if cleanup_context and not (cleanup["pr_closed"] and cleanup["branch_deleted"]):
            report["status"] = "FAIL"
            report["error"] = "disposable GitHub handoff cleanup did not converge"
            exit_code = 1
        report["profile_snapshots_scrubbed"] = governance._scrub_profile_snapshots(runtime_home)
        report["finished_at_epoch"] = int(time.time())
        public_report = _redacted_report(report)
        _write_json(report_path, public_report)
        html_path.write_text(_html_report(public_report), encoding="utf-8")
        html_path.chmod(0o600)
    print(_canonical({"status": report["status"], "report": str(report_path), "html": str(html_path), "error": report.get("error")}))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
