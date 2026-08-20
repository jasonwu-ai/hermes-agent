from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

from hermes_cli import kanban_db
from plugins.verified_pipeline import execution, release
from tests.plugins.verified_pipeline import test_review as review_tests
from plugins.verified_pipeline import merge_actuator as actuator


class FakeAdapter:
    def __init__(self, *, fail: bool = False, invalid: bool = False):
        self.fail = fail
        self.invalid = invalid
        self.calls: list[dict] = []
        self._lock = threading.Lock()

    def merge(self, scope):
        with self._lock:
            self.calls.append(dict(scope))
        if self.fail:
            raise RuntimeError("simulated lost adapter result")
        result = {
            "schema": actuator.ADAPTER_RESULT_SCHEMA,
            "repository": scope["repository"],
            "base_ref": scope["base_ref"],
            "head_sha": scope["head_sha"],
            "pull_request": scope["pull_request"],
            "merge_method": scope["merge_method"],
            "merge_commit_sha": "4" * 40,
            "result": "MERGED",
        }
        if self.invalid:
            result["head_sha"] = "5" * 40
        return result


def _merge_authorized(tmp_path: Path):
    control_db, kanban_path, _, board, intent, completion = review_tests._completed_execution(
        tmp_path
    )
    execution_key = intent["idempotency_key"]
    ready_authority = review_tests._release_ready_authority(
        control_db, execution_key, completion
    )
    ready = release.record_release_ready(
        execution_key,
        authority_key=ready_authority["authority_key"],
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    merge_authority = review_tests._persist_release_authority(
        control_db,
        execution_key,
        decision=release.MERGE_DECISION,
        schema=release.MERGE_AUTH_SCHEMA,
        fields={
            "release_key": ready["release_key"],
            "release_ready_sha256": execution._digest(
                {key: value for key, value in ready.items() if key != "replayed"}
            ),
            "repository": ready["repository"],
            "base_ref": ready["base_ref"],
            "head_sha": ready["head_sha"],
            "pull_request": 9,
            "merge_method": "squash",
        },
    )
    merge = release.record_merge_authorization(
        execution_key,
        authority_key=merge_authority["authority_key"],
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    scope = actuator._scope_from_receipt(
        merge,
        execution_key=execution_key,
        board=board,
        control_db_path=control_db.resolve(),
        kanban_db_path=kanban_path.resolve(),
    )
    return control_db, kanban_path, board, execution_key, scope


def _consume(control_db, kanban_path, board, execution_key, scope, adapter):
    return actuator._consume_exact_merge(
        execution_key,
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
        expected_scope=scope,
        adapter=adapter,
    )


def _events(kanban_path: Path):
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        return [
            (row["kind"], json.loads(row["payload_json"]))
            for row in conn.execute(
                "SELECT kind, payload_json FROM merge_actuator_events ORDER BY rowid"
            )
        ]
    finally:
        conn.close()


def test_exact_merge_success_is_observation_only_and_replays(tmp_path):
    control_db, kanban_path, board, execution_key, scope = _merge_authorized(tmp_path)
    adapter = FakeAdapter()
    result = _consume(control_db, kanban_path, board, execution_key, scope, adapter)
    assert result["status"] == "MERGE_OBSERVED_PENDING_SIGNED_RESULT_ATTESTATION"
    assert result["merge_commit_sha"] == "4" * 40
    assert result["replayed"] is False
    assert "no deployment or live authority" in result["boundary"]
    assert adapter.calls == [scope]

    replayed = _consume(control_db, kanban_path, board, execution_key, scope, adapter)
    assert replayed == {**{k: v for k, v in result.items() if k != "replayed"}, "replayed": True}
    assert adapter.calls == [scope]
    assert [kind for kind, _ in _events(kanban_path)] == ["DISPATCHED", "SUCCEEDED"]

    conn = review_tests.controller.connect(control_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM merge_result_receipts").fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM deployment_authorization_receipts").fetchone()[0]
            == 0
        )
    finally:
        conn.close()


def test_public_entrypoint_is_disabled_before_actuator_schema_or_adapter(tmp_path, monkeypatch):
    control_db, kanban_path, board, execution_key, _ = _merge_authorized(tmp_path)

    class ForbiddenAdapter:
        def __init__(self):
            raise AssertionError("adapter must not be constructed while disabled")

    monkeypatch.setattr(actuator, "GitHubCLIAdapter", ForbiddenAdapter)
    with pytest.raises(actuator.MergeActuatorError) as exc:
        actuator.consume_exact_merge(
            execution_key,
            board=board,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "MERGE_ACTUATOR_DISABLED"
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' "
                "AND name LIKE 'merge_actuator_%'"
            ).fetchone()[0]
            == 0
        )
    finally:
        conn.close()


def test_runtime_environment_change_cannot_enable_or_construct_adapter(tmp_path, monkeypatch):
    control_db, kanban_path, board, execution_key, _ = _merge_authorized(tmp_path)
    monkeypatch.setenv(actuator.ENABLE_ENV, actuator.ENABLE_TOKEN)
    monkeypatch.setenv(actuator.SCOPE_PIN_ENV, "0" * 64)
    monkeypatch.setenv(actuator.GH_PIN_ENV, "0" * 64)

    class ForbiddenAdapter:
        def __init__(self):
            raise AssertionError("adapter must not be constructed by runtime env mutation")

    monkeypatch.setattr(actuator, "GitHubCLIAdapter", ForbiddenAdapter)
    with pytest.raises(actuator.MergeActuatorError) as exc:
        actuator.consume_exact_merge(
            execution_key,
            board=board,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "MERGE_ACTUATOR_DISABLED"


def test_malformed_startup_scope_pin_rejects_before_adapter(tmp_path, monkeypatch):
    control_db, kanban_path, board, execution_key, _ = _merge_authorized(tmp_path)
    monkeypatch.setattr(actuator, "_STARTUP_ENABLE", actuator.ENABLE_TOKEN)
    monkeypatch.setattr(actuator, "_STARTUP_SCOPE_SHA256", "not-a-digest")

    class ForbiddenAdapter:
        def __init__(self):
            raise AssertionError("adapter must not be constructed with malformed pins")

    monkeypatch.setattr(actuator, "GitHubCLIAdapter", ForbiddenAdapter)
    with pytest.raises(actuator.MergeActuatorError) as exc:
        actuator.consume_exact_merge(
            execution_key,
            board=board,
            db_path=control_db,
            kanban_db_path=kanban_path,
        )
    assert exc.value.code == "MERGE_SCOPE_PIN_REQUIRED"


def test_exact_startup_pins_reach_only_fake_adapter(tmp_path, monkeypatch):
    control_db, kanban_path, board, execution_key, _ = _merge_authorized(tmp_path)
    scope = actuator._read_untrusted_scope(
        execution_key,
        board=board,
        control_db_path=control_db.resolve(),
        kanban_db_path=kanban_path.resolve(),
    )
    fake_gh = tmp_path / "gh"
    fake_gh.write_bytes(b"qualified fake gh bytes")
    adapter = FakeAdapter()
    monkeypatch.setattr(actuator, "GH_BINARY", fake_gh)
    monkeypatch.setattr(actuator, "_STARTUP_ENABLE", actuator.ENABLE_TOKEN)
    monkeypatch.setattr(actuator, "_STARTUP_SCOPE_SHA256", actuator._digest(scope))
    monkeypatch.setattr(
        actuator,
        "_STARTUP_GH_SHA256",
        actuator.hashlib.sha256(fake_gh.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv("GH_TOKEN", "test-only-placeholder")
    monkeypatch.setattr(actuator, "GitHubCLIAdapter", lambda: adapter)

    result = actuator.consume_exact_merge(
        execution_key,
        board=board,
        db_path=control_db,
        kanban_db_path=kanban_path,
    )
    assert result["status"] == "MERGE_OBSERVED_PENDING_SIGNED_RESULT_ATTESTATION"
    assert adapter.calls == [scope]


def test_scope_drift_rejects_before_intent_and_adapter(tmp_path):
    control_db, kanban_path, board, execution_key, scope = _merge_authorized(tmp_path)
    drifted = {**scope, "head_sha": "9" * 40}
    adapter = FakeAdapter()
    with pytest.raises(actuator.MergeActuatorError) as exc:
        _consume(control_db, kanban_path, board, execution_key, drifted, adapter)
    assert exc.value.code == "MERGE_SCOPE_DRIFT"
    assert adapter.calls == []
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'merge_actuator_intents'"
        ).fetchone()
        assert table is None
    finally:
        conn.close()


def test_board_completion_drift_rejects_before_adapter(tmp_path):
    control_db, kanban_path, board, execution_key, scope = _merge_authorized(tmp_path)
    custody = review_tests.controller.connect(control_db)
    try:
        completion = json.loads(
            custody.execute(
                "SELECT payload_json FROM execution_completion_receipts WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()[0]
        )
        task_id = next(iter(completion["task_results"].values()))["task_id"]
    finally:
        custody.close()
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        with kanban_db.write_txn(conn):
            conn.execute("UPDATE tasks SET status = 'blocked' WHERE id = ?", (task_id,))
    finally:
        conn.close()
    adapter = FakeAdapter()
    with pytest.raises(actuator.MergeActuatorError) as exc:
        _consume(control_db, kanban_path, board, execution_key, scope, adapter)
    assert exc.value.code == "MERGE_AUTHORITY_INVALID"
    assert adapter.calls == []


def test_lost_adapter_result_is_never_retried(tmp_path):
    control_db, kanban_path, board, execution_key, scope = _merge_authorized(tmp_path)
    adapter = FakeAdapter(fail=True)
    with pytest.raises(actuator.MergeActuatorError) as exc:
        _consume(control_db, kanban_path, board, execution_key, scope, adapter)
    assert exc.value.code == "MERGE_OUTCOME_UNKNOWN"
    assert len(adapter.calls) == 1

    replacement = FakeAdapter()
    with pytest.raises(actuator.MergeActuatorError) as replay_exc:
        _consume(control_db, kanban_path, board, execution_key, scope, replacement)
    assert replay_exc.value.code == "MERGE_OUTCOME_UNKNOWN"
    assert replacement.calls == []
    assert [kind for kind, _ in _events(kanban_path)] == ["DISPATCHED"]


def test_invalid_adapter_observation_cannot_be_admitted_or_retried(tmp_path):
    control_db, kanban_path, board, execution_key, scope = _merge_authorized(tmp_path)
    adapter = FakeAdapter(invalid=True)
    with pytest.raises(actuator.MergeActuatorError) as exc:
        _consume(control_db, kanban_path, board, execution_key, scope, adapter)
    assert exc.value.code == "ADAPTER_SCOPE_MISMATCH"
    assert [kind for kind, _ in _events(kanban_path)] == ["DISPATCHED"]

    with pytest.raises(actuator.MergeActuatorError) as replay_exc:
        _consume(control_db, kanban_path, board, execution_key, scope, FakeAdapter())
    assert replay_exc.value.code == "MERGE_OUTCOME_UNKNOWN"


def test_concurrent_consumers_call_adapter_at_most_once(tmp_path):
    control_db, kanban_path, board, execution_key, scope = _merge_authorized(tmp_path)
    adapter = FakeAdapter()

    def consume(_):
        try:
            return _consume(control_db, kanban_path, board, execution_key, scope, adapter)
        except actuator.MergeActuatorError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(consume, range(16)))
    assert len(adapter.calls) == 1
    assert any(isinstance(value, dict) and value["status"].startswith("MERGE_OBSERVED") for value in results)
    assert set(value for value in results if isinstance(value, str)) <= {"MERGE_OUTCOME_UNKNOWN"}
    assert [kind for kind, _ in _events(kanban_path)] == ["DISPATCHED", "SUCCEEDED"]


def test_github_adapter_constructs_exact_conditional_commands(monkeypatch):
    scope = {
        "repository": "jasonwu-ai/hermes-agent",
        "base_ref": "main",
        "head_sha": "1" * 40,
        "pull_request": 9,
        "merge_method": "squash",
    }
    calls = []
    responses = iter(
        [
            {
                "number": 9,
                "state": "OPEN",
                "headRefOid": "1" * 40,
                "baseRefName": "main",
                "mergeCommit": None,
            },
            {"merged": True, "sha": "4" * 40},
            {
                "number": 9,
                "state": "MERGED",
                "headRefOid": "1" * 40,
                "baseRefName": "main",
                "mergeCommit": {"oid": "4" * 40},
            },
        ]
    )

    def fake_run(self, args):
        calls.append(args)
        value = next(responses)
        return subprocess.CompletedProcess(args, 0, "" if value is None else json.dumps(value), "")

    monkeypatch.setattr(actuator.GitHubCLIAdapter, "_run", fake_run)
    result = actuator.GitHubCLIAdapter().merge(scope)
    assert calls[1] == [
        "api",
        "--method",
        "PUT",
        "repos/jasonwu-ai/hermes-agent/pulls/9/merge",
        "--raw-field",
        f"sha={'1' * 40}",
        "--raw-field",
        "merge_method=squash",
    ]
    assert result["merge_commit_sha"] == "4" * 40


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("number", 10),
        ("state", "CLOSED"),
        ("headRefOid", "2" * 40),
        ("baseRefName", "release"),
        ("mergeCommit", {"oid": "4" * 40}),
    ],
)
def test_github_preflight_drift_never_reaches_merge_endpoint(monkeypatch, field, value):
    scope = {
        "repository": "jasonwu-ai/hermes-agent",
        "base_ref": "main",
        "head_sha": "1" * 40,
        "pull_request": 9,
        "merge_method": "squash",
    }
    before = {
        "number": 9,
        "state": "OPEN",
        "headRefOid": "1" * 40,
        "baseRefName": "main",
        "mergeCommit": None,
    }
    before[field] = value
    calls = []

    def fake_run(self, args):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps(before), "")

    monkeypatch.setattr(actuator.GitHubCLIAdapter, "_run", fake_run)
    with pytest.raises(actuator.MergeActuatorError) as exc:
        actuator.GitHubCLIAdapter().merge(scope)
    assert exc.value.code == "GITHUB_PR_SCOPE_MISMATCH"
    assert len(calls) == 1
    assert calls[0][:2] == ["pr", "view"]


def test_github_rest_and_postflight_commit_mismatch_fails_closed(monkeypatch):
    scope = {
        "repository": "jasonwu-ai/hermes-agent",
        "base_ref": "main",
        "head_sha": "1" * 40,
        "pull_request": 9,
        "merge_method": "squash",
    }
    responses = iter(
        [
            {
                "number": 9,
                "state": "OPEN",
                "headRefOid": "1" * 40,
                "baseRefName": "main",
                "mergeCommit": None,
            },
            {"merged": True, "sha": "4" * 40},
            {
                "number": 9,
                "state": "MERGED",
                "headRefOid": "1" * 40,
                "baseRefName": "main",
                "mergeCommit": {"oid": "5" * 40},
            },
        ]
    )

    def fake_run(self, args):
        return subprocess.CompletedProcess(args, 0, json.dumps(next(responses)), "")

    monkeypatch.setattr(actuator.GitHubCLIAdapter, "_run", fake_run)
    with pytest.raises(actuator.MergeActuatorError) as exc:
        actuator.GitHubCLIAdapter().merge(scope)
    assert exc.value.code == "GITHUB_MERGE_NOT_OBSERVED"


def test_cli_fails_disabled_without_schema_or_external_call(tmp_path):
    control_db, kanban_path, board, execution_key, _ = _merge_authorized(tmp_path)
    env = {key: value for key, value in review_tests.os.environ.items() if key != actuator.ENABLE_ENV}
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "plugins.verified_pipeline.merge_actuator",
            "--execution-key",
            execution_key,
            "--board",
            board,
            "--control-db",
            str(control_db),
            "--kanban-db",
            str(kanban_path),
        ],
        cwd=Path(__file__).resolve().parents[3],
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["error"] == "MERGE_ACTUATOR_DISABLED"


def test_actuator_custody_is_immutable(tmp_path):
    control_db, kanban_path, board, execution_key, scope = _merge_authorized(tmp_path)
    _consume(control_db, kanban_path, board, execution_key, scope, FakeAdapter())
    conn = kanban_db.connect(db_path=kanban_path)
    try:
        for statement in (
            "UPDATE merge_actuator_identity SET actuator_id = 'forged' WHERE singleton = 1",
            "DELETE FROM merge_actuator_intents",
            "UPDATE merge_actuator_events SET kind = 'FORGED'",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                with kanban_db.write_txn(conn):
                    conn.execute(statement)
    finally:
        conn.close()


def test_module_has_no_production_wiring_or_deployment_executor():
    root = Path(__file__).resolve().parents[3]
    module = root / "plugins" / "verified_pipeline" / "merge_actuator.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert "record_deployment_authorization" not in calls
    assert "record_merge_result" not in calls

    production_imports = []
    for path in root.rglob("*.py"):
        if path == module or "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "merge_actuator" in text:
            production_imports.append(str(path.relative_to(root)))
    assert production_imports == []
