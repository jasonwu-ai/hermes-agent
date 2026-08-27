from __future__ import annotations

from pathlib import Path
import hashlib
import importlib.util
import json
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from hermes_cli import kanban_db
from hermes_cli.role_contract import admit_role_contract
from scripts import run_verified_pipeline_live_full_flow_canary as runner
from scripts import run_verified_pipeline_live_governance_canary as governance


def test_clean_source_head_rejects_dirty_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [
            subprocess.CompletedProcess([], 0, " M scripts/canary.py\n", ""),
        ]
    )
    monkeypatch.setattr(runner, "_run", lambda *args, **kwargs: next(responses))

    with pytest.raises(RuntimeError, match="clean committed source tree"):
        runner._clean_source_head()


def test_canary_commit_identity_uses_attribution_exempt_automation_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head = "a" * 40
    monkeypatch.setattr(runner, "_run", lambda *args, **kwargs: pytest.fail("identity must not inspect Git"))

    identity = runner._canary_commit_identity(head)

    assert identity == runner.CANARY_COMMIT_IDENTITY
    assert identity == {
        "name": "github-actions[bot]",
        "email": "41898282+github-actions[bot]@users.noreply.github.com",
    }
    assert identity is not runner.CANARY_COMMIT_IDENTITY


@pytest.mark.parametrize(
    "head",
    [
        "not-a-head",
        "A" * 40,
        "a" * 39,
        "g" * 40,
    ],
)
def test_canary_commit_identity_rejects_unbound_source_head(head: str) -> None:
    with pytest.raises(RuntimeError, match="source head"):
        runner._canary_commit_identity(head)


def test_required_check_name_matches_orchestrator_workflow() -> None:
    workflow = (runner.SOURCE_ROOT / ".github" / "workflows" / "ci.yaml").read_text(encoding="utf-8")
    assert f"name: {runner.REQUIRED_CHECK_NAME}" in workflow


def test_governance_spec_respects_attachment_only_implementation_contracts() -> None:
    specification = governance.SPECIFICATION
    expected_digest = hashlib.sha256(runner.CANARY_BYTES).hexdigest()

    assert "kanban_complete(artifacts=[...])" in specification
    assert "MUST NOT require Builder to calculate a hash" in specification
    assert "kanban_attachments" in specification
    assert expected_digest in specification
    assert "Test has only file and Kanban tools" in specification


def test_release_contract_instruction_requires_inline_controller_packet_and_exact_outputs() -> None:
    instruction = runner._release_contract_instruction()

    assert "kanban_attachments" in instruction
    assert "inline_text" in instruction
    assert "github-handoff.json" in instruction
    assert "required_output_contract" in instruction
    assert "final-review.json" in instruction
    assert "kanban_complete(artifacts=[...])" in instruction
    normalized = " ".join(instruction.split())
    assert "Do not substitute a generic release-evidence file" in normalized
    assert "no merge, deployment" in normalized


def test_local_full_flow_controller_handoff_reaches_real_worker_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise controller storage and an unmodified tool import before Release validation."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kanban_db._INITIALIZED_PATHS.clear()
    kanban_db.init_db()
    conn = kanban_db.connect()
    try:
        task_id = kanban_db.create_task(conn, title="release", assignee="08-release")
        kanban_db.claim_task(conn, task_id)
        raw = b'{"required_output_contract":{"machine_filename":"final-review.json"}}\n'
        kanban_db.store_attachment_bytes(
            conn, task_id, "github-handoff.json", raw,
            content_type="application/json", uploaded_by="verified-pipeline-full-flow-controller",
        )
    finally:
        conn.close()

    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    from tools import kanban_tools as kt

    response = json.loads(kt._handle_attachments({"task_id": task_id}))
    handoff = next(att for att in response["attachments"] if att["filename"] == "github-handoff.json")
    assert handoff["inline_text"] == raw.decode("utf-8")
    assert handoff["inline_sha256"] == hashlib.sha256(raw).hexdigest()
    # The handler must work before Release consumes its required output contract.
    assert "required_output_contract" in runner._release_contract_instruction()


def test_all_check_runs_uses_filter_all_and_collects_conflict_on_second_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head_sha = "d" * 40
    calls: list[list[str]] = []
    success = {"name": runner.REQUIRED_CHECK_NAME, "head_sha": head_sha, "conclusion": "success"}
    conflict = {"name": runner.REQUIRED_CHECK_NAME, "head_sha": head_sha, "conclusion": "failure"}

    def fake_gh(args: list[str], *, payload=None):
        calls.append(args)
        joined = " ".join(args)
        if "&page=1" in joined:
            return {"total_count": 101, "check_runs": [success, *({"name": f"other-{i}"} for i in range(99))]}
        if "page=2" in joined:
            return {"total_count": 101, "check_runs": [conflict]}
        raise AssertionError(args)

    monkeypatch.setattr(runner, "_gh_json", fake_gh)
    runs = runner._all_check_runs("owner/repo", head_sha)
    exact = [item for item in runs if item.get("name") == runner.REQUIRED_CHECK_NAME]
    assert len(runs) == 101
    assert len(exact) == 2
    assert {item["conclusion"] for item in exact} == {"success", "failure"}
    assert all("filter=all" in " ".join(call) for call in calls)
    assert any("page=2" in " ".join(call) for call in calls)


def test_all_check_runs_rejects_unbounded_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "_gh_json",
        lambda *args, **kwargs: {"total_count": runner.MAX_CHECK_RUNS + 1, "check_runs": []},
    )
    with pytest.raises(RuntimeError, match="bounded audit cap"):
        runner._all_check_runs("owner/repo", "d" * 40)


def test_github_handoff_rejects_unsafe_scope() -> None:
    with pytest.raises(RuntimeError, match="owner/name"):
        runner._github_handoff(
            repository="unsafe",
            base_ref="main",
            branch="fleet/acceptance-canary-safe",
            artifact_path="acceptance/canary.txt",
            artifact_bytes=runner.CANARY_BYTES,
            run_id="run_safe",
            timeout_seconds=1,
            cleanup_context={},
        )
    with pytest.raises(RuntimeError, match="namespace"):
        runner._github_handoff(
            repository="owner/repo",
            base_ref="main",
            branch="feature/not-a-canary",
            artifact_path="acceptance/canary.txt",
            artifact_bytes=runner.CANARY_BYTES,
            run_id="run_safe",
            timeout_seconds=1,
            cleanup_context={},
        )
    with pytest.raises(RuntimeError, match="unsafe"):
        runner._github_handoff(
            repository="owner/repo",
            base_ref="main",
            branch="fleet/acceptance-canary-safe",
            artifact_path="../canary.txt",
            artifact_bytes=runner.CANARY_BYTES,
            run_id="run_safe",
            timeout_seconds=1,
            cleanup_context={},
        )


@pytest.mark.parametrize(
    "protection",
    [
        {"strict": False, "contexts": [runner.REQUIRED_CHECK_NAME], "checks": []},
        {
            "strict": True,
            "contexts": [runner.REQUIRED_CHECK_NAME],
            "checks": [{"context": runner.REQUIRED_CHECK_NAME}],
        },
        {
            "strict": True,
            "contexts": [runner.REQUIRED_CHECK_NAME],
            "checks": [{"context": runner.REQUIRED_CHECK_NAME, "app_id": True}],
        },
    ],
)
def test_github_handoff_rejects_branch_protection_drift_before_ref_creation(
    monkeypatch: pytest.MonkeyPatch,
    protection,
) -> None:
    monkeypatch.setattr(runner, "_gh_json", lambda *args, **kwargs: protection)
    context: dict = {}
    with pytest.raises(RuntimeError, match="branch protection drifted"):
        runner._github_handoff(
            repository="owner/repo",
            base_ref="main",
            branch="fleet/acceptance-canary-safe",
            artifact_path="acceptance/canary.txt",
            artifact_bytes=runner.CANARY_BYTES,
            run_id="run_safe",
            timeout_seconds=1,
            cleanup_context=context,
        )
    assert context["ref_created"] is False
    assert context["pull_request"] is None


def test_assert_ref_absent_requires_explicit_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, '{"object":{"sha":"existing"}}', ""),
    )
    with pytest.raises(RuntimeError, match="pre-existing disposable branch"):
        runner._assert_ref_absent("owner/repo", "fleet/acceptance-canary-safe")

    monkeypatch.setattr(
        runner,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, "", "gh: Forbidden (HTTP 403)"),
    )
    with pytest.raises(RuntimeError, match="unable to prove"):
        runner._assert_ref_absent("owner/repo", "fleet/acceptance-canary-safe")

    monkeypatch.setattr(
        runner,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, "", "gh: Not Found (HTTP 404)"),
    )
    runner._assert_ref_absent("owner/repo", "fleet/acceptance-canary-safe")


def test_create_ref_requires_exact_successful_custody(monkeypatch: pytest.MonkeyPatch) -> None:
    head_sha = "d" * 40
    branch = "fleet/acceptance-canary-safe"
    seen: dict = {}

    def successful_run(args, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(
            args,
            0,
            json.dumps({"ref": f"refs/heads/{branch}", "object": {"sha": head_sha}}),
            "",
        )

    monkeypatch.setattr(runner, "_run", successful_run)
    runner._create_ref("owner/repo", branch, head_sha)
    assert json.loads(seen["input_text"]) == {"ref": f"refs/heads/{branch}", "sha": head_sha}
    assert seen["check"] is False

    monkeypatch.setattr(
        runner,
        "_run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 1, "", "gh: rejected (HTTP 422)"),
    )
    with pytest.raises(RuntimeError, match="HTTP 422"):
        runner._create_ref("owner/repo", branch, head_sha)

    monkeypatch.setattr(
        runner,
        "_run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, json.dumps({"ref": f"refs/heads/{branch}", "object": {"sha": "e" * 40}}), ""
        ),
    )
    with pytest.raises(RuntimeError, match="did not match exact ref and head"):
        runner._create_ref("owner/repo", branch, head_sha)


def test_cleanup_preserves_ref_after_ambiguous_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "_run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("ambiguous ref must not be touched")),
    )
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": None,
            "pr_creation_attempted": False,
            "branch": "fleet/acceptance-canary-safe",
            "ref_created": False,
            "ref_creation_attempted": True,
            "ref_creation_ambiguous": True,
            "head_sha": "d" * 40,
        }
    )
    assert result["pr_closed"] is True
    assert result["branch_deleted"] is False
    assert "ownership remained ambiguous" in result["delete_error"]


def test_github_handoff_binds_exact_head_and_required_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict | None]] = []
    head_sha = "d" * 40

    def fake_gh(args: list[str], *, payload=None):
        calls.append((list(args), payload))
        joined = " ".join(args)
        if "/protection/required_status_checks" in joined:
            return {
                "strict": True,
                "contexts": [runner.REQUIRED_CHECK_NAME],
                "checks": [{"context": runner.REQUIRED_CHECK_NAME, "app_id": 15368}],
            }
        if "/commits/main" in joined:
            return {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}}
        if "/git/blobs" in joined:
            return {"sha": "c" * 40}
        if "/git/trees" in joined:
            return {"sha": "e" * 40}
        if "/git/commits" in joined:
            return {"sha": head_sha}
        if "/git/refs" in joined:
            return {"ref": "refs/heads/fleet/acceptance-canary-safe"}
        if joined.endswith("/pulls"):
            return {"number": 42, "html_url": "https://github.com/owner/repo/pull/42"}
        if args[:2] == ["pr", "view"]:
            return {"headRefOid": head_sha, "state": "OPEN", "url": "https://github.com/owner/repo/pull/42"}
        if "/check-runs?" in joined:
            return {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": runner.REQUIRED_CHECK_NAME,
                        "head_sha": head_sha,
                        "app": {"slug": "github-actions", "id": 15368},
                        "status": "completed",
                        "conclusion": "success",
                        "details_url": "https://github.com/owner/repo/actions/runs/1",
                        "completed_at": "2026-08-26T00:00:00Z",
                    }
                ]
            }
        raise AssertionError(args)

    monkeypatch.setattr(runner, "_gh_json", fake_gh)
    monkeypatch.setattr(runner, "_assert_ref_absent", lambda repository, branch: None)
    monkeypatch.setattr(runner, "_create_ref", lambda repository, branch, head_sha: None)
    monkeypatch.setattr(
        runner,
        "_canary_commit_identity",
        lambda head: {"name": "Candidate", "email": "123+candidate@users.noreply.github.com"},
    )
    cleanup_context: dict = {}
    receipt = runner._github_handoff(
        repository="owner/repo",
        base_ref="main",
        branch="fleet/acceptance-canary-safe",
        artifact_path="acceptance/canary.txt",
        artifact_bytes=runner.CANARY_BYTES,
        run_id="run_safe",
        timeout_seconds=1,
        cleanup_context=cleanup_context,
        source_head="d" * 40,
    )

    assert receipt["head_sha"] == head_sha
    assert receipt["merge_authority"] is False
    assert receipt["artifact_sha256"] == hashlib.sha256(runner.CANARY_BYTES).hexdigest()
    assert receipt["required_check"]["conclusion"] == "success"
    assert receipt["required_check"]["app_slug"] == "github-actions"
    assert receipt["required_check"]["app_id"] == 15368
    assert receipt["branch_protection"]["required_app_id"] == 15368
    assert cleanup_context["pull_request"] == 42
    commit_payloads = [payload for args, payload in calls if "/git/commits" in " ".join(args)]
    assert commit_payloads == [
        {
            "message": "test: disposable verified-pipeline acceptance run_safe",
            "tree": "e" * 40,
            "parents": ["a" * 40],
            "author": {"name": "Candidate", "email": "123+candidate@users.noreply.github.com"},
            "committer": {"name": "Candidate", "email": "123+candidate@users.noreply.github.com"},
        }
    ]
    flattened = "\n".join(" ".join(args) for args, _ in calls)
    assert "/labels" not in flattened
    assert "merge" not in flattened.lower()


def test_cleanup_closes_and_deletes_without_merge(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    head_sha = "d" * 40
    ref_reads = 0

    def fake_run(args: list[str], **kwargs):
        nonlocal ref_reads
        calls.append(args)
        if args[1:3] == ["pr", "view"]:
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"state": "CLOSED", "headRefOid": head_sha}), ""
            )
        if args[1:3] == ["api", "repos/owner/repo/git/ref/heads/fleet%2Facceptance-canary-safe"]:
            ref_reads += 1
            if ref_reads == 1:
                return subprocess.CompletedProcess(args, 0, json.dumps({"object": {"sha": head_sha}}), "")
            return subprocess.CompletedProcess(args, 1, "", "gh: Not Found (HTTP 404)\n")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner, "_run", fake_run)
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": 42,
            "branch": "fleet/acceptance-canary-safe",
            "ref_created": True,
            "head_sha": head_sha,
        }
    )

    assert result["pr_closed"] is True
    assert result["branch_deleted"] is True
    assert calls[0][:3] == ["gh", "pr", "close"]
    assert calls[3][:4] == ["gh", "api", "-X", "DELETE"]
    assert all(call[1:3] != ["pr", "merge"] for call in calls)
    assert all("/merges" not in " ".join(call).lower() for call in calls)


def test_cleanup_fails_without_verified_closed_pr_and_absent_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(args: list[str], **kwargs):
        if args[1:3] == ["pr", "view"]:
            return subprocess.CompletedProcess(args, 0, '{"state":"OPEN"}\n', "")
        if args[1:2] == ["api"] and "git/ref/heads" in " ".join(args):
            return subprocess.CompletedProcess(args, 0, '{"ref":"still-present"}\n', "")
        return subprocess.CompletedProcess(args, 1, "", "auth failure")

    monkeypatch.setattr(runner, "_run", fake_run)
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": 42,
            "branch": "fleet/acceptance-canary-safe",
            "ref_created": True,
        }
    )
    assert result["pr_closed"] is False
    assert result["branch_deleted"] is False


def test_cleanup_refuses_to_delete_preexisting_mismatched_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps({"object": {"sha": "e" * 40}}), "")

    monkeypatch.setattr(runner, "_run", fake_run)
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": None,
            "branch": "fleet/acceptance-canary-safe",
            "ref_created": True,
            "head_sha": "d" * 40,
        }
    )
    assert result["branch_deleted"] is False
    assert "mismatched head identity" in result["delete_error"]
    assert all(call[1:4] != ["api", "-X", "DELETE"] for call in calls)


def test_cleanup_discovers_ambiguous_pr_creation_by_exact_head(monkeypatch: pytest.MonkeyPatch) -> None:
    head_sha = "d" * 40
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs):
        calls.append(args)
        if args[1:3] == ["pr", "list"]:
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps([{"number": 43, "state": "OPEN", "headRefOid": head_sha}]),
                "",
            )
        if args[1:3] == ["pr", "view"]:
            return subprocess.CompletedProcess(args, 0, json.dumps({"state": "CLOSED", "headRefOid": head_sha}), "")
        if args[1:3] == ["api", "repos/owner/repo/git/ref/heads/fleet%2Facceptance-canary-safe"]:
            return subprocess.CompletedProcess(args, 1, "", "gh: Not Found (HTTP 404)\n")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner, "_run", fake_run)
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": None,
            "branch": "fleet/acceptance-canary-safe",
            "head_sha": head_sha,
            "pr_creation_attempted": True,
            "ref_created": True,
        }
    )
    assert result["pr_closed"] is True
    assert result["closed_pull_requests"] == [43]
    assert result["branch_deleted"] is True
    assert any(call[1:3] == ["pr", "close"] for call in calls)


def test_cleanup_preserves_branch_when_ambiguous_pr_remains_undiscovered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs):
        calls.append(args)
        if args[1:3] == ["pr", "list"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        raise AssertionError(f"cleanup must not mutate or inspect the ref before PR closure: {args}")

    monkeypatch.setattr(runner, "_run", fake_run)
    monkeypatch.setattr(runner, "PR_DISCOVERY_ATTEMPTS", 3)
    monkeypatch.setattr(runner.time, "sleep", lambda seconds: None)
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": None,
            "pr_creation_attempted": True,
            "branch": "fleet/acceptance-canary-safe",
            "ref_created": True,
            "head_sha": "d" * 40,
        }
    )
    assert result["pr_closed"] is False
    assert result["branch_deleted"] is False
    assert "unable to prove no PR exists" in result["close_error"]
    assert "before PR closure was proven" in result["delete_error"]
    assert len(calls) == 3


@pytest.mark.parametrize(
    "discovered",
    [
        [{"headRefOid": "d" * 40}],
        [{"number": True, "headRefOid": "d" * 40}],
        ["not-a-pull-request"],
        [
            {"number": 43, "headRefOid": "d" * 40},
            {"number": 43, "headRefOid": "d" * 40},
        ],
    ],
)
def test_cleanup_preserves_branch_for_malformed_pr_discovery(
    monkeypatch: pytest.MonkeyPatch,
    discovered,
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs):
        calls.append(args)
        if args[1:3] == ["pr", "list"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(discovered), "")
        raise AssertionError(f"malformed discovery must not trigger cleanup mutation: {args}")

    monkeypatch.setattr(runner, "_run", fake_run)
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": None,
            "pr_creation_attempted": True,
            "branch": "fleet/acceptance-canary-safe",
            "ref_created": True,
            "head_sha": "d" * 40,
        }
    )
    assert result["pr_closed"] is False
    assert result["branch_deleted"] is False
    assert "PR discovery response" in result["close_error"]
    assert len(calls) == 1


def test_cleanup_refuses_ambiguous_pr_with_mismatched_head(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args: list[str], **kwargs):
        if args[1:3] == ["pr", "list"]:
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps([{"number": 43, "state": "OPEN", "headRefOid": "e" * 40}]),
                "",
            )
        if args[1:3] == ["api", "repos/owner/repo/git/ref/heads/fleet%2Facceptance-canary-safe"]:
            return subprocess.CompletedProcess(args, 1, "", "gh: Not Found (HTTP 404)\n")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner, "_run", fake_run)
    result = runner._cleanup_github_handoff(
        {
            "repository": "owner/repo",
            "pull_request": None,
            "branch": "fleet/acceptance-canary-safe",
            "head_sha": "d" * 40,
            "pr_creation_attempted": True,
            "ref_created": True,
        }
    )
    assert result["pr_closed"] is False
    assert "mismatched head" in result["close_error"]


def test_attachment_manifest_requires_matching_completion_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "canary.txt"
    artifact.write_bytes(runner.CANARY_BYTES)
    digest = hashlib.sha256(runner.CANARY_BYTES).hexdigest()
    attachment = SimpleNamespace(
        id=1,
        task_id="t_builder",
        filename="canary.txt",
        stored_path=str(artifact),
        size=len(runner.CANARY_BYTES),
        sha256=digest,
        uploaded_by="kanban_complete",
        created_at=150,
    )
    controller_input = tmp_path / "github-handoff.json"
    controller_input.write_text('{"handoff":"safe"}\n', encoding="utf-8")
    generic_attachment = SimpleNamespace(
        id=2,
        task_id="t_builder",
        filename="github-handoff.json",
        stored_path=str(controller_input),
        size=controller_input.stat().st_size,
        sha256=None,
        uploaded_by="verified-pipeline-full-flow-controller",
        created_at=149,
    )
    kanban_db = SimpleNamespace(
        list_attachments=lambda conn, task_id: [generic_attachment, attachment]
    )

    manifest = runner._attachment_manifest(kanban_db, object(), "t_builder")
    assert manifest[0]["sha256"] == hashlib.sha256(controller_input.read_bytes()).hexdigest()
    assert manifest[0]["admitted_sha256"] is None
    assert manifest[1]["sha256"] == digest
    assert manifest[1]["admitted_sha256"] == digest
    assert manifest[1]["task_id"] == "t_builder"

    attachment.task_id = "other-task"
    with pytest.raises(RuntimeError, match="task custody drifted"):
        runner._attachment_manifest(kanban_db, object(), "t_builder")
    attachment.task_id = "t_builder"

    attachment.uploaded_by = "controller"
    with pytest.raises(RuntimeError, match="no durable completion attachment"):
        runner._attachment_manifest(kanban_db, object(), "t_builder")
    attachment.uploaded_by = "kanban_complete"
    attachment.sha256 = None
    with pytest.raises(RuntimeError, match="lacks an admitted digest"):
        runner._attachment_manifest(kanban_db, object(), "t_builder")
    attachment.sha256 = digest
    artifact.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="custody drifted"):
        runner._attachment_manifest(kanban_db, object(), "t_builder")


def test_github_handoff_failure_uses_partial_cleanup_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head_sha = "d" * 40
    cleanup_seen: dict = {}

    def fake_gh(args: list[str], *, payload=None):
        joined = " ".join(args)
        if "/protection/required_status_checks" in joined:
            return {
                "strict": True,
                "contexts": [runner.REQUIRED_CHECK_NAME],
                "checks": [{"context": runner.REQUIRED_CHECK_NAME, "app_id": 15368}],
            }
        if "/commits/main" in joined:
            return {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}}
        if "/git/blobs" in joined:
            return {"sha": "c" * 40}
        if "/git/trees" in joined:
            return {"sha": "e" * 40}
        if "/git/commits" in joined:
            return {"sha": head_sha}
        if "/git/refs" in joined:
            return {"ref": "created"}
        if joined.endswith("/pulls"):
            return {"number": 42, "html_url": "https://github.com/owner/repo/pull/42"}
        if args[:2] == ["pr", "view"]:
            return {"headRefOid": head_sha, "state": "OPEN"}
        if "/check-runs?" in joined:
            return {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": runner.REQUIRED_CHECK_NAME,
                        "head_sha": head_sha,
                        "app": {"slug": "github-actions", "id": 15368},
                        "status": "completed",
                        "conclusion": "failure",
                    }
                ]
            }
        raise AssertionError(args)

    def fake_cleanup(context):
        cleanup_seen.update(context)
        return {"pr_closed": True, "branch_deleted": True}

    monkeypatch.setattr(runner, "_gh_json", fake_gh)
    monkeypatch.setattr(runner, "_assert_ref_absent", lambda repository, branch: None)
    monkeypatch.setattr(runner, "_create_ref", lambda repository, branch, head_sha: None)
    monkeypatch.setattr(
        runner,
        "_canary_commit_identity",
        lambda head: {"name": "Candidate", "email": "123+candidate@users.noreply.github.com"},
    )
    monkeypatch.setattr(runner, "_cleanup_github_handoff", fake_cleanup)
    context: dict = {}
    with pytest.raises(RuntimeError, match="All required checks pass failed"):
        runner._github_handoff(
            repository="owner/repo",
            base_ref="main",
            branch="fleet/acceptance-canary-safe",
            artifact_path="acceptance/canary.txt",
            artifact_bytes=runner.CANARY_BYTES,
            run_id="run_safe",
            timeout_seconds=1,
            cleanup_context=context,
            source_head="d" * 40,
        )
    assert cleanup_seen["ref_created"] is True
    assert cleanup_seen["pull_request"] == 42
    assert cleanup_seen["pr_creation_attempted"] is True


def test_github_handoff_marks_ref_custody_before_ambiguous_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_seen: dict = {}

    def fake_gh(args: list[str], *, payload=None):
        joined = " ".join(args)
        if "/protection/required_status_checks" in joined:
            return {
                "strict": True,
                "contexts": [runner.REQUIRED_CHECK_NAME],
                "checks": [{"context": runner.REQUIRED_CHECK_NAME, "app_id": 15368}],
            }
        if "/commits/main" in joined:
            return {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}}
        if "/git/blobs" in joined:
            return {"sha": "c" * 40}
        if "/git/trees" in joined:
            return {"sha": "e" * 40}
        if "/git/commits" in joined:
            return {"sha": "d" * 40}
        if "/git/refs" in joined:
            raise RuntimeError("response lost after POST")
        raise AssertionError(args)

    def fake_cleanup(context):
        cleanup_seen.update(context)
        return {"pr_closed": True, "branch_deleted": True}

    monkeypatch.setattr(runner, "_gh_json", fake_gh)
    monkeypatch.setattr(runner, "_assert_ref_absent", lambda repository, branch: None)
    monkeypatch.setattr(
        runner,
        "_canary_commit_identity",
        lambda head: {"name": "Candidate", "email": "123+candidate@users.noreply.github.com"},
    )

    def ambiguous_create(repository, branch, head_sha):
        raise RuntimeError("response lost after POST")

    monkeypatch.setattr(runner, "_create_ref", ambiguous_create)
    monkeypatch.setattr(runner, "_cleanup_github_handoff", fake_cleanup)
    with pytest.raises(RuntimeError, match="response lost"):
        runner._github_handoff(
            repository="owner/repo",
            base_ref="main",
            branch="fleet/acceptance-canary-safe",
            artifact_path="acceptance/canary.txt",
            artifact_bytes=runner.CANARY_BYTES,
            run_id="run_safe",
            timeout_seconds=1,
            cleanup_context={},
            source_head="d" * 40,
        )
    assert cleanup_seen["ref_created"] is False
    assert cleanup_seen["ref_creation_attempted"] is True
    assert cleanup_seen["ref_creation_ambiguous"] is True
    assert cleanup_seen["head_sha"] == "d" * 40
    assert cleanup_seen["pr_creation_attempted"] is False


def test_dispatch_exact_task_never_redispatches_while_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states = iter(
        [
            {"id": "task", "status": "ready", "assignee": "02-builder", "worker_pid": None},
            {"id": "task", "status": "running", "assignee": "02-builder", "worker_pid": 123},
            # Kanban terminal transitions clear worker_pid; the runner must
            # retain and drain the last PID observed while running.
            {"id": "task", "status": "done", "assignee": "02-builder", "worker_pid": None},
        ]
    )
    dispatch_calls = 0

    def fake_dispatch(*args, **kwargs):
        nonlocal dispatch_calls
        dispatch_calls += 1
        return SimpleNamespace(spawned=1)

    monkeypatch.setattr(governance, "_task", lambda *args, **kwargs: next(states))
    drained: list[int | None] = []
    monkeypatch.setattr(governance, "_drain_worker_process", drained.append)
    kanban_db = SimpleNamespace(dispatch_once=fake_dispatch, DEFAULT_BOARD="default")
    result = runner._dispatch_exact_task(
        task_id="task",
        kanban_path=Path("board.db"),
        conn=object(),
        kanban_db=kanban_db,
        timeout_seconds=1,
    )
    assert result["status"] == "done"
    assert result["runtime_worker_pid"] == 123
    assert dispatch_calls == 1
    assert drained == [123]


def test_release_assignee_comes_from_the_admitted_role_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = [
        profile
        for profile in governance.MANDATORY_CONTRACT_PROFILES
        if profile.endswith("-release")
    ]
    assert len(expected) == 1
    assert runner._release_assignee() == expected[0]

    monkeypatch.setattr(
        governance,
        "MANDATORY_CONTRACT_PROFILES",
        ("02-builder", "09-test", "06-integration"),
    )
    with pytest.raises(RuntimeError, match="exactly one admitted release profile"):
        runner._release_assignee()

    monkeypatch.setattr(
        governance,
        "MANDATORY_CONTRACT_PROFILES",
        ("02-builder", "08-release", "10-release"),
    )
    with pytest.raises(RuntimeError, match="exactly one admitted release profile"):
        runner._release_assignee()


def test_release_completion_binds_resolved_assignee_to_run_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_authority(conn, *, task_id, expected_profile):
        observed.update(
            conn=conn,
            task_id=task_id,
            expected_profile=expected_profile,
        )
        return {"task_id": task_id, "profile": expected_profile}

    monkeypatch.setattr(runner, "_release_run_authority", fake_authority)
    assignee = runner._release_assignee()
    authority = runner._release_completion_authority(
        "connection",
        terminal={"id": "release-task-safe", "assignee": assignee},
        task_id="release-task-safe",
        assignee=assignee,
    )
    assert authority == {"task_id": "release-task-safe", "profile": assignee}
    assert observed == {
        "conn": "connection",
        "task_id": "release-task-safe",
        "expected_profile": assignee,
    }

    with pytest.raises(RuntimeError, match="designated authority"):
        runner._release_completion_authority(
            "connection",
            terminal={"id": "release-task-safe", "assignee": "other-profile"},
            task_id="release-task-safe",
            assignee=assignee,
        )


def test_release_review_requires_exact_machine_and_human_binding(tmp_path: Path) -> None:
    handoff = {
        "repository": "owner/repo",
        "pull_request": 42,
        "pull_request_url": "https://github.com/owner/repo/pull/42",
        "head_sha": "d" * 40,
        "required_check": {
            "name": runner.REQUIRED_CHECK_NAME,
            "head_sha": "d" * 40,
            "status": "completed",
            "conclusion": "success",
        },
    }
    contract = runner._release_output_contract(
        "run_safe",
        handoff,
        release_task_id="release-task-safe",
        release_assignee=runner._release_assignee(),
    )
    machine = tmp_path / "final-review.json"
    human = tmp_path / "final-review.md"
    machine.write_text(runner._canonical(contract["required_exact_fields"]), encoding="utf-8")
    human.write_text("\n".join(contract["required_human_content"]), encoding="utf-8")
    authority = {
        "id": 7,
        "task_id": "release-task-safe",
        "profile": runner._release_assignee(),
        "status": "done",
        "outcome": "completed",
        "started_at": 100,
        "ended_at": 200,
    }
    manifest = [
        {
            "attachment_id": 11,
            "task_id": "release-task-safe",
            "filename": machine.name,
            "stored_path": str(machine),
            "uploaded_by": "kanban_complete",
            "created_at": 150,
        },
        {
            "attachment_id": 12,
            "task_id": "release-task-safe",
            "filename": human.name,
            "stored_path": str(human),
            "uploaded_by": "kanban_complete",
            "created_at": 151,
        },
    ]
    machine_row, human_row = runner._validate_release_review(manifest, contract, authority)
    assert machine_row["filename"] == "final-review.json"
    assert human_row["filename"] == "final-review.md"
    assert contract["required_exact_fields"]["release_assignee"] == runner._release_assignee()

    substituted = [dict(item, task_id="other-task") for item in manifest]
    with pytest.raises(RuntimeError, match="designated Release task"):
        runner._validate_release_review(substituted, contract, authority)

    wrong_profile = dict(authority, profile="02-builder")
    with pytest.raises(RuntimeError, match="worker-run authority"):
        runner._validate_release_review(manifest, contract, wrong_profile)

    outside_run = [dict(item, created_at=99) for item in manifest]
    with pytest.raises(RuntimeError, match="worker-run interval"):
        runner._validate_release_review(outside_run, contract, authority)

    payload = {**contract["required_exact_fields"], "verdict": "NOT_READY"}
    machine.write_text(runner._canonical(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="verdict"):
        runner._validate_release_review(manifest, contract, authority)

    machine.write_text(
        runner._canonical({**contract["required_exact_fields"], "unexpected": True}), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="unexpected or missing machine key"):
        runner._validate_release_review(manifest, contract, authority)

    machine.write_text(runner._canonical(contract["required_exact_fields"]), encoding="utf-8")
    extra = tmp_path / "extra.txt"
    extra.write_text("not requested", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unrequested artifact"):
        runner._validate_release_review(
            [*manifest, {**manifest[0], "attachment_id": 13, "filename": extra.name, "stored_path": str(extra)}],
            contract,
            authority,
        )

    alternate = [dict(manifest[0], filename="alternate.json"), *manifest[1:]]
    with pytest.raises(RuntimeError, match="unrequested artifact"):
        runner._validate_release_review(alternate, contract, authority)

    duplicate_human = [*manifest, dict(manifest[1], attachment_id=14, filename="final-review.html")]
    with pytest.raises(RuntimeError, match="missing or ambiguous"):
        runner._validate_release_review(duplicate_human, contract, authority)


def test_release_run_authority_requires_one_completed_release_run() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE task_runs ("
        "id INTEGER PRIMARY KEY, task_id TEXT, profile TEXT, status TEXT, outcome TEXT, "
        "started_at INTEGER, ended_at INTEGER)"
    )
    conn.execute(
        "INSERT INTO task_runs VALUES (1, ?, ?, 'done', 'completed', 100, 200)",
        ("release-task-safe", runner._release_assignee()),
    )
    authority = runner._release_run_authority(
        conn,
        task_id="release-task-safe",
        expected_profile=runner._release_assignee(),
    )
    assert authority["id"] == 1
    assert authority["profile"] == runner._release_assignee()

    conn.execute(
        "INSERT INTO task_runs VALUES (2, ?, ?, 'done', 'completed', 201, 300)",
        ("release-task-safe", runner._release_assignee()),
    )
    with pytest.raises(RuntimeError, match="exactly one Release worker run"):
        runner._release_run_authority(
            conn,
            task_id="release-task-safe",
            expected_profile=runner._release_assignee(),
        )


def test_report_redaction_removes_auth_and_credential_fields() -> None:
    redacted = runner._redacted_report(
        {
            "credential_source_sha256": "digest",
            "credential_files": ["/tmp/auth.json"],
            "nested": {
                "refresh_token": "secret",
                "auth_path": "/tmp/store.dat",
                "authorization_file": "/tmp/opaque.bin",
                "token_path": "/tmp/token.bin",
                "path": "prefix /tmp/auth.json suffix",
                "safe": "ok",
            },
        }
    )
    rendered = runner._canonical(redacted)
    assert "digest" not in rendered
    assert "secret" not in rendered
    assert "auth.json" not in rendered
    assert "opaque.bin" not in rendered
    assert "token.bin" not in rendered
    assert redacted["nested"]["safe"] == "ok"


def test_snapshot_active_profiles_copies_config_auth_and_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_root = tmp_path / "live"
    overlays = tmp_path / "overlays"
    runtime = tmp_path / "runtime"
    credential = tmp_path / "auth.json"
    credential.write_text("{}", encoding="utf-8")
    credential.chmod(0o600)
    active = governance.GOVERNANCE_PROFILES + ("02-builder",)
    for profile in active:
        live = live_root / profile
        live.mkdir(parents=True)
        (live / "config.yaml").write_text("model: test\n", encoding="utf-8")
        (live / "profile.yaml").write_text(f"name: {profile}\n", encoding="utf-8")
        overlay = overlays / profile
        overlay.mkdir(parents=True)
        (overlay / "ROLE_CONTRACT.md").write_text(
            "---\n"
            "schema: hermes-role-contract/v2\n"
            f"profile: {profile}\n"
            "version: 1.0.0\n"
            "allowed_toolsets:\n"
            "  - file\n"
            "allowed_tools:\n"
            "  - read_file\n"
            "workspace_only: true\n"
            "---\n"
            "# Test role\n",
            encoding="utf-8",
        )
        if profile in governance.GOVERNANCE_PROFILES:
            skill = overlay / "skills" / "task"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text("---\nname: task\n---\n", encoding="utf-8")
    for profile in set(governance.MANDATORY_CONTRACT_PROFILES) - {"02-builder"}:
        overlay = overlays / profile
        overlay.mkdir(parents=True)
        (overlay / "ROLE_CONTRACT.md").write_text(
            "---\n"
            "schema: hermes-role-contract/v2\n"
            f"profile: {profile}\n"
            "version: 1.0.0\n"
            "allowed_toolsets:\n"
            "  - file\n"
            "allowed_tools:\n"
            "  - read_file\n"
            "workspace_only: true\n"
            "---\n"
            "# Test role\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(governance, "LIVE_PROFILES_ROOT", live_root)
    monkeypatch.setattr(governance, "OVERLAYS", overlays)

    manifest = governance._snapshot_profiles(
        runtime,
        credential_auth=credential,
        active_profiles=active,
    )

    builder = runtime / "profiles" / "02-builder"
    assert (builder / "config.yaml").is_file()
    assert (builder / "auth.json").read_text(encoding="utf-8") == "{}"
    assert "credential_files" not in manifest
    assert manifest["profiles"]["02-builder"]["contract_sha256"]
    assert manifest["profiles"]["09-test"]["contract_only"] is True


def test_snapshot_active_test_profile_projects_contract_toolsets_for_real_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_root = tmp_path / "live"
    overlays = tmp_path / "overlays"
    runtime = tmp_path / "runtime"
    active = governance.GOVERNANCE_PROFILES + ("09-test",)
    for profile in active:
        live = live_root / profile
        live.mkdir(parents=True)
        live.joinpath("config.yaml").write_text(
            "agent:\n"
            "  disabled_toolsets:\n"
            "    - file\n"
            "    - web\n"
            "platform_toolsets:\n"
            "  cli:\n"
            "    - terminal\n"
            "    - no_mcp\n",
            encoding="utf-8",
        )
        live.joinpath("profile.yaml").write_text(f"name: {profile}\n", encoding="utf-8")
        overlay = overlays / profile
        overlay.mkdir(parents=True)
        allowed = "  - file\n  - kanban\n" if profile == "09-test" else "  - file\n"
        overlay.joinpath("ROLE_CONTRACT.md").write_text(
            "---\n"
            "schema: hermes-role-contract/v2\n"
            f"profile: {profile}\n"
            "version: 1.0.0\n"
            "allowed_toolsets:\n"
            f"{allowed}"
            "allowed_tools:\n"
            "  - read_file\n"
            "workspace_only: true\n"
            "---\n"
            "# Test role\n",
            encoding="utf-8",
        )
    for profile in set(governance.MANDATORY_CONTRACT_PROFILES) - {"09-test"}:
        overlay = overlays / profile
        overlay.mkdir(parents=True)
        overlay.joinpath("ROLE_CONTRACT.md").write_text(
            "---\n"
            "schema: hermes-role-contract/v2\n"
            f"profile: {profile}\n"
            "version: 1.0.0\n"
            "allowed_toolsets:\n"
            "  - file\n"
            "allowed_tools:\n"
            "  - read_file\n"
            "workspace_only: true\n"
            "---\n"
            "# Test role\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(governance, "LIVE_PROFILES_ROOT", live_root)
    monkeypatch.setattr(governance, "OVERLAYS", overlays)

    governance._snapshot_profiles(runtime, active_profiles=active)
    target = runtime / "profiles" / "09-test"
    projected = yaml.safe_load((target / "config.yaml").read_text(encoding="utf-8"))
    assert "file" in projected["platform_toolsets"]["cli"]
    assert "file" not in projected["agent"]["disabled_toolsets"]
    assert "web" in projected["agent"]["disabled_toolsets"]

    configured = kanban_db._resolve_worker_cli_toolsets(str(target))
    admission = admit_role_contract(
        target,
        "09-test",
        configured or [],
        task_id="t_real_target_profile",
        run_id=1,
        workspace_path=str(tmp_path),
        required=True,
    )
    assert admission is not None
    assert admission.effective_toolsets == ("file", "kanban")
