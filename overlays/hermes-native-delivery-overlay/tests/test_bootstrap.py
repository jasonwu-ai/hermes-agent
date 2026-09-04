from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
import ast
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading

import pytest

from hermes_verified_delivery import register
from hermes_verified_delivery.contracts import ContractError, Decision, GraphSpec, canonical_bytes
from hermes_verified_delivery.controller import (
    AuthorityStore, Controller, InjectedCrash, MaterializationConflict,
    NativeKanbanAdapter, ReplayConflict, qualification_paths,
)
from hermes_verified_delivery.review import (
    ReviewEnvelope, handle_submission, load_accepted_authority, render_evidence, render_review,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 3, 5, 0, tzinfo=timezone.utc)
AUTHORITY = load_accepted_authority()
SPEC_SHA = AUTHORITY.spec_sha256


def envelope(*, nonce: str = "nonce-001") -> ReviewEnvelope:
    return ReviewEnvelope(
        spec_id=AUTHORITY.spec_id, revision=AUTHORITY.revision, spec_sha256=SPEC_SHA,
        actor=AUTHORITY.actor, nonce=nonce, issued_at=AUTHORITY.issued_at, expires_at=AUTHORITY.expires_at,
        allowed_actions=AUTHORITY.allowed_actions, exclusions=AUTHORITY.exclusions,
        planner_assignee=AUTHORITY.planner_assignee,
    )


def approval(store: AuthorityStore, *, nonce: str = "nonce-001", failpoint: str | None = None) -> Decision:
    return handle_submission(
        {"action": "APPROVE", "nonce": nonce, "feedback": ""},
        authenticated_actor=AUTHORITY.actor, envelope=envelope(nonce=nonce),
        store=store, now=NOW, failpoint=failpoint,
    )


def two_task_graph(decision: Decision, *, changed: bool = False) -> GraphSpec:
    return GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": f"run:{decision.decision_id}",
        "approval_id": decision.decision_id,
        "tasks": [
            {"key": "plan", "title": "Plan changed" if changed else "Plan", "assignee": "planner", "parents": []},
            {"key": "review", "title": "Review", "assignee": "auditor", "parents": ["plan"]},
        ],
    })


def custom_approval(store: AuthorityStore, nonce: str = "nonce-graph") -> tuple[Decision, GraphSpec]:
    decision = Decision.from_dict({
        "schema": "hvd-decision/v1", "spec_id": "two-gate-v1", "revision": 1,
        "spec_sha256": SPEC_SHA, "actor": "synthetic-user", "action": "APPROVE",
        "nonce": nonce, "replay_key": f"gate1:two-gate-v1:{nonce}",
        "issued_at": "2026-09-03T04:54:58Z", "expires_at": "2026-09-17T04:54:58Z",
        "allowed_actions": ["local source"], "exclusions": ["live effects"], "feedback": None,
    })
    graph = two_task_graph(decision)
    store.record_decision(decision, graph=graph)
    return decision, graph


def adapter(qualification_root: Path) -> NativeKanbanAdapter:
    return NativeKanbanAdapter(qualification_root / "board.db", qualification_root)


def test_accepted_predecessor_is_exact_and_unknown_authority_fields_fail() -> None:
    data = json.loads((ROOT / "authority" / "accepted-predecessor.json").read_text())
    assert set(data) == {
        "schema", "decision", "spec_sha256", "approval_receipt_sha256",
        "accepted_at", "expires_at", "authority", "live_effects",
    }
    assert data["spec_sha256"] == SPEC_SHA
    assert data["approval_receipt_sha256"] == "ffa8912d67189e6971488d39dcdcc26da52a2040c6020b1d9eb6d82eed65fb58"
    assert data["live_effects"] is False
    base = Decision.from_dict({
        "schema": "hvd-decision/v1", "spec_id": "x", "revision": 1,
        "spec_sha256": SPEC_SHA, "actor": "actor", "action": "APPROVE",
        "nonce": "n", "replay_key": "r", "issued_at": "2026-09-03T00:00:00Z",
        "expires_at": "2026-09-04T00:00:00Z", "allowed_actions": ["a"],
        "exclusions": ["b"], "feedback": None,
    })
    hostile = base.to_dict() | {"execution_authority": "DEPLOY"}
    with pytest.raises(ContractError, match="unknown fields"):
        Decision.from_dict(hostile)


def test_submission_is_bound_to_exact_accepted_spec_receipt_actor_scope_and_issuance(tmp_path: Path) -> None:
    authority = load_accepted_authority()
    assert hashlib.sha256((ROOT / "authority" / "accepted-specification.md").read_bytes()).hexdigest() == SPEC_SHA
    assert hashlib.sha256((ROOT / "authority" / "approval-receipt.json").read_bytes()).hexdigest() == (
        "ffa8912d67189e6971488d39dcdcc26da52a2040c6020b1d9eb6d82eed65fb58"
    )
    store = AuthorityStore(tmp_path / "authority.db")
    form = {"action": "APPROVE", "nonce": "nonce-001", "feedback": ""}
    for hostile in (
        replace(envelope(), spec_sha256="f" * 64),
        replace(envelope(), allowed_actions=("deploy production",)),
        replace(envelope(), issued_at="2027-01-01T00:00:00Z", expires_at="2027-01-02T00:00:00Z"),
        replace(envelope(), planner_assignee="attacker"),
    ):
        with pytest.raises(ContractError, match="sealed authority"):
            handle_submission(form, authenticated_actor=authority.actor, envelope=hostile, store=store, now=NOW)
    with pytest.raises(ContractError, match="actor"):
        handle_submission(form, authenticated_actor="any-authenticated-user", envelope=envelope(), store=store, now=NOW)
    assert store.counts() == {"decisions": 0, "outbox": 0, "materializations": 0}


@pytest.mark.parametrize("failpoint", ["after_decision", "after_outbox"])
def test_decision_and_held_outbox_are_atomic(failpoint: str, tmp_path: Path) -> None:
    store = AuthorityStore(tmp_path / "authority.db")
    with pytest.raises(InjectedCrash):
        approval(store, failpoint=failpoint)
    assert store.counts() == {"decisions": 0, "outbox": 0, "materializations": 0}
    decision = approval(store)
    assert store.counts() == {"decisions": 1, "outbox": 1, "materializations": 0}
    assert approval(store).decision_id == decision.decision_id
    assert store.counts()["outbox"] == 1


def test_request_changes_is_immutable_and_projects_nothing(tmp_path: Path) -> None:
    store = AuthorityStore(tmp_path / "authority.db")
    decision = handle_submission(
        {"action": "REQUEST_CHANGES", "nonce": "nonce-revise", "feedback": "Tighten rollback."},
        authenticated_actor=AUTHORITY.actor, envelope=envelope(nonce="nonce-revise"),
        store=store, now=NOW,
    )
    before = store.decision_payload(decision.decision_id)
    assert store.counts() == {"decisions": 1, "outbox": 0, "materializations": 0}
    assert json.loads(before)["feedback"] == "Tighten rollback."
    with pytest.raises(ReplayConflict):
        handle_submission(
            {"action": "REJECT", "nonce": "nonce-revise", "feedback": ""},
            authenticated_actor=AUTHORITY.actor, envelope=envelope(nonce="nonce-revise"),
            store=store, now=NOW,
        )
    assert store.decision_payload(decision.decision_id) == before


def test_handler_authenticates_actor_expires_nonce_and_never_writes_board(tmp_path: Path) -> None:
    store = AuthorityStore(tmp_path / "authority.db")
    with pytest.raises(ContractError, match="fields must be exact"):
        handle_submission(
            {"action": "APPROVE", "nonce": "nonce-001", "feedback": "", "actor": "attacker"},
            authenticated_actor=AUTHORITY.actor, envelope=envelope(), store=store, now=NOW,
        )
    with pytest.raises(ContractError, match="values must be strings"):
        handle_submission(
            {"action": "APPROVE", "nonce": "nonce-001", "feedback": None},
            authenticated_actor=AUTHORITY.actor, envelope=envelope(), store=store, now=NOW,
        )
    with pytest.raises(ContractError, match="nonce mismatch"):
        handle_submission(
            {"action": "APPROVE", "nonce": "wrong", "feedback": ""},
            authenticated_actor=AUTHORITY.actor, envelope=envelope(), store=store, now=NOW,
        )
    with pytest.raises(ContractError, match="outside its admitted interval"):
        handle_submission(
            {"action": "APPROVE", "nonce": "nonce-001", "feedback": ""},
            authenticated_actor=AUTHORITY.actor, envelope=envelope(), store=store,
            now=datetime(2026, 9, 18, tzinfo=timezone.utc),
        )
    approval(store)
    assert not (tmp_path / "board.db").exists()


def test_reconciliation_rejects_expired_held_authority_before_board_write(
    qualification_root: Path, tmp_path: Path,
) -> None:
    store = AuthorityStore(tmp_path / "authority.db")
    decision = Decision.from_dict({
        "schema": "hvd-decision/v1", "spec_id": "expired-spec", "revision": 1,
        "spec_sha256": SPEC_SHA, "actor": AUTHORITY.actor, "action": "APPROVE",
        "nonce": "expired", "replay_key": "gate1:expired-spec:expired",
        "issued_at": "2020-01-01T00:00:00Z", "expires_at": "2020-01-02T00:00:00Z",
        "allowed_actions": ["local source"], "exclusions": ["live effects"], "feedback": None,
    })
    graph = GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": "run:expired",
        "approval_id": decision.decision_id,
        "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
    })
    store.record_decision(decision, graph=graph)
    target = adapter(qualification_root)
    with pytest.raises(ContractError, match="HELD authority"):
        Controller(store, target).reconcile_held(now=NOW)
    assert not target.board_db.exists()
    assert store.counts()["materializations"] == 0


@pytest.mark.parametrize("failpoint", ["after_task_0", "after_task_1"])
def test_native_graph_transaction_rolls_back_every_crashpoint(
    failpoint: str, qualification_root: Path, tmp_path: Path,
) -> None:
    store = AuthorityStore(tmp_path / "authority.db")
    decision, graph = custom_approval(store)
    target = adapter(qualification_root)
    controller = Controller(store, target)
    with pytest.raises(InjectedCrash):
        controller.reconcile_held(failpoint=failpoint)
    assert target.graph_counts(graph.run_id) == {"tasks": 0, "links": 0}
    assert store.counts()["materializations"] == 0
    recovered = Controller(AuthorityStore(store.path), adapter(qualification_root)).reconcile_held()
    assert len(recovered) == 1
    assert target.graph_counts(graph.run_id) == {"tasks": 2, "links": 1}
    assert store.counts()["materializations"] == 1


def test_concurrent_same_key_converges_and_contract_mismatch_fails(
    qualification_root: Path, tmp_path: Path,
) -> None:
    store = AuthorityStore(tmp_path / "authority.db")
    _, graph = custom_approval(store)

    def run() -> tuple[dict[str, str], ...]:
        return Controller(AuthorityStore(store.path), adapter(qualification_root)).reconcile_held()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: run(), range(16)))
    assert all(len(result) == 1 for result in results)
    target = adapter(qualification_root)
    assert target.graph_counts(graph.run_id) == {"tasks": 2, "links": 1}
    assert store.counts() == {"decisions": 1, "outbox": 1, "materializations": 1}
    with pytest.raises(MaterializationConflict, match="contract mismatch"):
        target.materialize(two_task_graph(Decision.from_dict(json.loads(store.decision_payload(graph.approval_id))), changed=True))


def test_same_key_adoption_compares_complete_native_task_contract(qualification_root: Path) -> None:
    from hermes_cli import kanban_db as kb

    target = adapter(qualification_root)
    graph = GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": "run:hostile-precreate",
        "approval_id": "dec_hostile_precreate",
        "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
    })
    key = "hvd:run:hostile-precreate:planner"
    kb.init_db(target.board_db)
    conn = kb.connect(target.board_db)
    try:
        hostile_id = kb.create_task(
            conn, title="Plan", body=target._task_body(graph, graph.tasks[0]), assignee="planner",
            created_by="attacker", workspace_kind="scratch", workspace_path="/outside",
            parents=[], idempotency_key=key, initial_status="blocked", goal_mode=True,
        )
    finally:
        conn.close()
    with pytest.raises(MaterializationConflict, match="created_by.*goal_mode.*workspace_path"):
        target.materialize(graph)
    conn = kb.connect(target.board_db)
    try:
        rows = conn.execute("SELECT id,status FROM tasks WHERE idempotency_key=?", (key,)).fetchall()
    finally:
        conn.close()
    assert [(row["id"], row["status"]) for row in rows] == [(hostile_id, "blocked")]


@pytest.mark.parametrize(("field", "hostile_value"), [
    ("require_role_contract", 1),
    ("expected_role_contract_sha256", "b" * 64),
])
def test_same_key_adoption_rejects_each_role_contract_field(
    qualification_root: Path, field: str, hostile_value: object,
) -> None:
    from hermes_cli import kanban_db as kb

    target = adapter(qualification_root)
    graph = GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": "run:role-contract-precreate",
        "approval_id": "dec_role_contract_precreate",
        "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
    })
    key = "hvd:run:role-contract-precreate:planner"
    kb.init_db(target.board_db)
    conn = kb.connect(target.board_db)
    try:
        task_id = kb.create_task(
            conn, title="Plan", body=target._task_body(graph, graph.tasks[0]), assignee="planner",
            created_by="hermes-verified-delivery", workspace_kind="scratch", parents=[],
            idempotency_key=key, initial_status="blocked", goal_mode=False,
            require_role_contract=False, expected_role_contract_sha256=None, project_id="",
        )
        with kb.write_txn(conn):
            conn.execute(f"UPDATE tasks SET {field}=? WHERE id=?", (hostile_value, task_id))
    finally:
        conn.close()
    with pytest.raises(MaterializationConflict, match=field):
        target.materialize(graph)
    conn = kb.connect(target.board_db)
    try:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    finally:
        conn.close()
    assert row[field] == hostile_value
    assert target.graph_counts(graph.run_id) == {"tasks": 1, "links": 0}


def test_archived_recorded_materialization_replays_without_replacement(
    qualification_root: Path, tmp_path: Path,
) -> None:
    from hermes_cli import kanban_db as kb

    store = AuthorityStore(tmp_path / "authority.db")
    approval(store, nonce="archive")
    graph = store.held_intents()[0][1]
    target = adapter(qualification_root)
    controller = Controller(store, target)
    first = controller.reconcile_held(now=NOW)[0]
    conn = kb.connect(target.board_db)
    try:
        assert kb.archive_task(conn, first["planner"])
    finally:
        conn.close()
    assert controller.reconcile_held(now=NOW) == (first,)
    conn = kb.connect(target.board_db)
    try:
        rows = conn.execute(
            "SELECT id,status FROM tasks WHERE idempotency_key=? ORDER BY id",
            (f"hvd:{graph.run_id}:planner",),
        ).fetchall()
    finally:
        conn.close()
    assert [(row["id"], row["status"]) for row in rows] == [(first["planner"], "archived")]


class CaptureContext:
    def __init__(self, config: dict, *, best_effort: bool = True):
        self.config, self.hooks, self.best_effort = config, {}, best_effort

    def get_config(self, key: str, default=None):
        return self.config.get(key, default)

    def register_hook(self, name: str, callback):
        self.hooks.setdefault(name, []).append(callback)

    def fire(self, name: str):
        errors = []
        for callback in self.hooks.get(name, []):
            try:
                callback(task_id="synthetic")
            except Exception as exc:
                errors.append(exc)
                if not self.best_effort:
                    raise
        return errors


def test_duplicate_missed_hook_and_restart_converge(qualification_root: Path) -> None:
    store = AuthorityStore(qualification_root / "authority.db")
    decision = approval(store)
    cfg = {"verified_delivery": {
        "qualification_enabled": True, "authority_db": str(store.path),
        "board_db": str(qualification_root / "board.db"),
        "qualification_root": str(qualification_root),
    }}
    ctx = CaptureContext(cfg)
    register(ctx)
    assert set(ctx.hooks) == {
        "kanban_task_completed", "kanban_task_blocked", "on_kanban_task_updated", "on_kanban_dispatch_tick",
    }
    # Missed event: nothing projects until a later durable reconciliation signal.
    assert not (qualification_root / "board.db").exists()
    ctx.fire("on_kanban_dispatch_tick")
    ctx.fire("on_kanban_dispatch_tick")
    fresh = Controller(AuthorityStore(store.path), adapter(qualification_root))
    fresh.reconcile_held()
    assert adapter(qualification_root).graph_counts(f"run:{decision.decision_id}") == {"tasks": 1, "links": 0}


def test_registration_uses_pinned_upstream_plugin_context() -> None:
    from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest

    hooks = [
        "kanban_task_completed", "kanban_task_blocked", "on_kanban_task_updated",
        "on_kanban_dispatch_tick",
    ]
    manager = PluginManager(scope_key="hvd-qualification")
    manifest = PluginManifest(
        name="hermes-verified-delivery", version="0.1.0",
        path=str(ROOT / "hermes_verified_delivery"), provides_hooks=hooks,
    )
    register(PluginContext(manifest, manager))
    assert all(manager.has_hook(name) for name in hooks)
    # No plugin config exists in the synthetic home, so the real host invocation is inert.
    assert manager.invoke_hook("on_kanban_dispatch_tick", task_id="synthetic") == []


def test_best_effort_hook_failure_recovers_later(qualification_root: Path, tmp_path: Path) -> None:
    store = AuthorityStore(tmp_path / "authority.db")
    decision = approval(store)
    bad_root = tmp_path / "bad-root"
    bad_root.mkdir()
    ctx = CaptureContext({"verified_delivery": {
        "qualification_enabled": True, "authority_db": str(store.path),
        "board_db": str(bad_root / "board.db"), "qualification_root": str(bad_root),
    }})
    register(ctx)
    errors = ctx.fire("kanban_task_completed")
    assert len(errors) == 1 and store.counts()["materializations"] == 0
    Controller(AuthorityStore(store.path), adapter(qualification_root)).reconcile_held()
    assert adapter(qualification_root).graph_counts(f"run:{decision.decision_id}") == {"tasks": 1, "links": 0}


def test_plugin_validates_all_qualification_paths_before_opening_any_database(
    qualification_root: Path, tmp_path: Path,
) -> None:
    outside = tmp_path / "protected-state.db"
    conn = sqlite3.connect(outside)
    conn.execute("CREATE TABLE sentinel(value TEXT)")
    conn.commit()
    conn.close()
    os.chmod(outside, 0o640)
    before = outside.read_bytes()
    before_mode = outside.stat().st_mode & 0o777

    ctx = CaptureContext({"verified_delivery": {
        "qualification_enabled": True, "authority_db": str(outside),
        "board_db": str(qualification_root / "board.db"),
        "qualification_root": str(qualification_root),
    }})
    register(ctx)
    errors = ctx.fire("on_kanban_dispatch_tick")
    assert len(errors) == 1 and "direct child" in str(errors[0])
    assert outside.read_bytes() == before
    assert outside.stat().st_mode & 0o777 == before_mode
    assert not (qualification_root / "board.db").exists()

    linked = qualification_root / "authority.db"
    linked.symlink_to(outside)
    ctx = CaptureContext({"verified_delivery": {
        "qualification_enabled": True, "authority_db": str(linked),
        "board_db": str(qualification_root / "board.db"),
        "qualification_root": str(qualification_root),
    }})
    register(ctx)
    errors = ctx.fire("on_kanban_dispatch_tick")
    assert len(errors) == 1 and "symlink" in str(errors[0])
    assert outside.read_bytes() == before


@pytest.mark.parametrize("alias_name", [
    "authority.db", "authority.db-wal", "authority.db-shm",
    "board.db", "board.db-wal", "board.db-shm",
])
def test_qualification_rejects_database_and_sidecar_hardlinks_before_mutation(
    qualification_root: Path, tmp_path: Path, alias_name: str,
) -> None:
    outside = tmp_path / "external-inode"
    outside.write_bytes(b"external sentinel\n")
    os.chmod(outside, 0o640)
    before, before_mode = outside.read_bytes(), outside.stat().st_mode & 0o777
    os.link(outside, qualification_root / alias_name)
    with pytest.raises(ContractError, match="hard link"):
        qualification_paths(
            qualification_root / "authority.db", qualification_root / "board.db", qualification_root,
        )
    assert outside.read_bytes() == before
    assert outside.stat().st_mode & 0o777 == before_mode


def test_materialization_rejects_controller_lock_hardlink_before_mutation(
    qualification_root: Path, tmp_path: Path,
) -> None:
    outside = tmp_path / "external-lock-inode"
    outside.write_bytes(b"external lock sentinel\n")
    os.chmod(outside, 0o640)
    before, before_mode = outside.read_bytes(), outside.stat().st_mode & 0o777
    os.link(outside, qualification_root / ".hvd-controller.lock")
    graph = GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": "run:hardlink-lock",
        "approval_id": "dec_hardlink_lock",
        "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
    })
    with pytest.raises(ContractError, match="hard link"):
        adapter(qualification_root).materialize(graph)
    assert outside.read_bytes() == before
    assert outside.stat().st_mode & 0o777 == before_mode
    assert not (qualification_root / "board.db").exists()


def _qualification_decision(nonce: str) -> Decision:
    return Decision.from_dict({
        "schema": "hvd-decision/v1", "spec_id": "qualified-race", "revision": 1,
        "spec_sha256": SPEC_SHA, "actor": AUTHORITY.actor, "action": "APPROVE",
        "nonce": nonce, "replay_key": f"qualified:{nonce}",
        "issued_at": "2026-09-03T04:54:58Z", "expires_at": "2026-09-17T04:54:58Z",
        "allowed_actions": ["scratch"], "exclusions": ["live"], "feedback": None,
    })


def _qualification_graph(item: Decision) -> GraphSpec:
    return GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": f"run:{item.nonce}",
        "approval_id": item.decision_id,
        "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
    })


@pytest.mark.parametrize("database", ["authority.db", "board.db"])
def test_primary_name_substitution_between_probe_and_descriptor_open_is_rejected(
    qualification_root: Path, monkeypatch: pytest.MonkeyPatch, database: str,
) -> None:
    import hermes_verified_delivery.controller as ctl

    target_path, attacker_path = qualification_root / database, qualification_root / f"attacker-{database}"
    good, hostile = _qualification_decision(f"good-{database}"), _qualification_decision(f"hostile-{database}")
    if database == "authority.db":
        target, attacker = (
            AuthorityStore(target_path, qualification_root=qualification_root),
            AuthorityStore(attacker_path, qualification_root=qualification_root),
        )
        attacker.record_decision(hostile, graph=_qualification_graph(hostile))
        operation = target.held_intents
    else:
        target, attacker = adapter(qualification_root), NativeKanbanAdapter(attacker_path, qualification_root)
        target.materialize(_qualification_graph(good))
        attacker.materialize(_qualification_graph(hostile))
        operation = lambda: target.graph_counts(hostile.nonce)
    real, state = ctl._owned_descriptor, {"opens": 0, "swapped": False}

    def racing(path, label, flags, *, bound_to=None):
        if Path(path) == target_path:
            state["opens"] += 1
            if state["opens"] == 2:
                target_path.rename(qualification_root / f"original-{database}")
                attacker_path.rename(target_path)
                state["swapped"] = True
        return real(path, label, flags, bound_to=bound_to)

    monkeypatch.setattr(ctl, "_owned_descriptor", racing)
    with pytest.raises(ContractError, match="replaced while bound"):
        operation()
    assert state["swapped"]


def test_concurrent_qualified_authority_writes_are_serialized(qualification_root: Path) -> None:
    path = qualification_root / "authority.db"
    stores = [AuthorityStore(path, qualification_root=qualification_root) for _ in range(2)]
    items = [_qualification_decision(f"concurrent-{index}") for index in range(2)]
    start = threading.Barrier(2)

    def write(pair):
        store, item = pair
        start.wait(timeout=10)
        return store.record_decision(item, graph=_qualification_graph(item))

    with ThreadPoolExecutor(max_workers=2) as pool:
        returned = list(pool.map(write, zip(stores, items, strict=True)))
    assert set(returned) == {item.decision_id for item in items}
    assert stores[0].counts() == {"decisions": 2, "outbox": 2, "materializations": 0}


def test_qualification_database_operations_are_memory_only_and_descriptor_persisted(
    qualification_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hermes_verified_delivery.controller as ctl

    real_connect, opened = ctl.sqlite3.connect, []

    def guarded_connect(database, *args, **kwargs):
        opened.append(str(database))
        assert database == ":memory:"
        return real_connect(database, *args, **kwargs)

    def forbidden_chmod(*_args, **_kwargs):
        raise AssertionError("qualification persistence must set mode through its descriptor")

    monkeypatch.setattr(ctl.sqlite3, "connect", guarded_connect)
    monkeypatch.setattr(ctl.os, "chmod", forbidden_chmod)
    store = AuthorityStore(qualification_root / "authority.db", qualification_root=qualification_root)
    target = adapter(qualification_root)
    graph = GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": "run:memory-only", "approval_id": "dec_memory_only",
        "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
    })
    target.materialize(graph)
    assert store.counts() == {"decisions": 0, "outbox": 0, "materializations": 0}
    assert target.graph_counts(graph.run_id) == {"tasks": 1, "links": 0}
    assert opened and set(opened) == {":memory:"}
    for name in ("authority.db", "board.db"):
        assert (qualification_root / name).stat().st_mode & 0o777 == 0o600
        assert not any((qualification_root / f"{name}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal"))


@pytest.mark.parametrize("database", ["authority.db", "board.db"])
@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_late_auxiliary_name_substitution_is_rejected_without_outside_change(
    qualification_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    database: str, suffix: str,
) -> None:
    import hermes_verified_delivery.controller as ctl

    outside = tmp_path / f"outside-{database}{suffix}"
    outside.write_bytes(b"external sidecar sentinel\n")
    os.chmod(outside, 0o640)
    before, before_mode = outside.read_bytes(), outside.stat().st_mode & 0o777
    real_replace, state = ctl.os.replace, {"injected": False}

    def racing_replace(source, destination, *args, **kwargs):
        if Path(destination) == qualification_root / database and not state["injected"]:
            os.link(outside, qualification_root / f"{database}{suffix}")
            state["injected"] = True
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(ctl.os, "replace", racing_replace)
    with pytest.raises(ContractError, match="sidecars"):
        if database == "authority.db":
            AuthorityStore(qualification_root / database, qualification_root=qualification_root)
        else:
            target = adapter(qualification_root)
            graph = GraphSpec.from_dict({
                "schema": "hvd-inert-graph/v1", "run_id": f"run:{suffix}", "approval_id": f"dec_{suffix}",
                "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
            })
            target.materialize(graph)
    assert state["injected"]
    assert outside.read_bytes() == before
    assert outside.stat().st_mode & 0o777 == before_mode


def test_board_opens_never_delegate_to_pathname_initialisation(qualification_root: Path, monkeypatch) -> None:
    from hermes_cli import kanban_db as kb

    def forbidden(*_args, **_kwargs):
        raise AssertionError("board must be opened on the verified inode, not re-resolved by pathname")

    monkeypatch.setattr(kb, "init_db", forbidden)
    monkeypatch.setattr(kb, "connect", forbidden)
    target = adapter(qualification_root)
    graph = GraphSpec.from_dict({
        "schema": "hvd-inert-graph/v1", "run_id": "run:bound-only", "approval_id": "dec_bound_only",
        "tasks": [{"key": "planner", "title": "Plan", "assignee": "planner", "parents": []}],
    })
    mapping = target.materialize(graph)
    assert target.graph_counts(graph.run_id) == {"tasks": 1, "links": 0}
    target.verify_recorded_mapping(graph, mapping)


def test_review_html_is_commonmark_safe_responsive_and_truthful() -> None:
    html = render_review(
        "# Spec\n\n<script>alert(1)</script>\n\n![tracking](https://example.invalid/pixel.png)\n\n**Bounded.**",
        envelope(),
    )
    assert "<meta name=\"viewport\"" in html and "@media(max-width:520px)" in html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<img" not in html and "example.invalid" not in html
    assert "Content-Security-Policy" in html and "img-src 'none'" in html
    assert "Approve — record held intent" in html and "Request changes" in html and ">Reject<" in html
    assert "No button launches a worker" in html
    assert "does not execute the intent or launch anything" in html
    assert 'aria-label="Local bootstrap decision"' in html
    assert 'aria-describedby="feedback-help"' in html
    assert "http://" not in html and "https://" not in html

    evidence = render_evidence(
        "# Evidence\n\n<script>bad()</script>\n\nSource-only.",
        status="SELF_TESTED_NOT_INDEPENDENTLY_ACCEPTED", commit="a" * 40,
    )
    assert "VIEW-ONLY EVIDENCE" in evidence and "grants no authority" in evidence
    assert "<form" not in evidence and "<button" not in evidence and "<script>" not in evidence
    assert "@media(max-width:520px)" in evidence and "https://" not in evidence
    assert "h1,h2,h3{line-height:1.2;overflow-wrap:anywhere}" in evidence


def test_workflow_environment_and_declared_platforms_match_executable_contract() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    manifest = (ROOT / "hermes_verified_delivery" / "plugin.yaml").read_text(encoding="utf-8")
    assert "HERMES_UPSTREAM" not in workflow
    assert "HVD_UPSTREAM" in workflow and 'os.environ.get("HVD_UPSTREAM"' in conftest
    assert "  - linux\n" in manifest and "  - macos\n" in manifest
    assert "  - windows\n" not in manifest


def test_qualification_inputs_have_no_secret_or_live_state_dependencies(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "synthetic-home"))
    checked = [ROOT / "hermes_verified_delivery", ROOT / "tests", ROOT / "authority" / "accepted-predecessor.json"]
    forbidden = (
        str(Path("/", "root", ".hermes")),
        str(Path("/", "home", "hermes", "content")),
        "BEGIN " + "PRIVATE KEY",
        "KILO" + "CODE_API_KEY",
        "ANTHROPIC" + "_API_KEY",
    )
    for base in checked:
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".json", ".yaml"}:
                text = path.read_text(encoding="utf-8")
                assert not any(value in text for value in forbidden), path
    receipt = (ROOT / "authority" / "approval-receipt.json").read_text(encoding="utf-8")
    assert "BEGIN " + "PRIVATE KEY" not in receipt
    assert "API_KEY" not in receipt and "raw conversation" not in receipt.lower()
    loader = (ROOT / "hermes_verified_delivery" / "review.py").read_text(encoding="utf-8")
    assert 'Path(receipt_spec["path"])' not in loader


def test_live_board_path_is_rejected(qualification_root: Path) -> None:
    with pytest.raises(ContractError, match="qualification root"):
        NativeKanbanAdapter(Path("/", "root", ".hermes", "kanban.db"), qualification_root)


def test_uninspectable_path_component_fails_closed(
    qualification_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = os.lstat
    denied = Path("/", "permission-denied")

    def guarded(path):
        if Path(path) == denied:
            raise PermissionError("synthetic access denial")
        return original(path)

    monkeypatch.setattr(os, "lstat", guarded)
    with pytest.raises(ContractError, match="cannot be inspected safely"):
        NativeKanbanAdapter(denied / "board.db", qualification_root)


def test_source_has_no_actuator_cron_network_or_second_store() -> None:
    production = sorted((ROOT / "hermes_verified_delivery").glob("*.py"))
    nonblank = sum(1 for p in production for line in p.read_text().splitlines() if line.strip())
    assert nonblank < 800
    imports, sqlite_modules = set(), []
    for path in production:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        if "sqlite3.connect" in path.read_text():
            sqlite_modules.append(path.name)
    assert not ({"subprocess", "socket", "requests", "urllib", "httpx", "asyncio"} & imports)
    assert sqlite_modules == ["controller.py"]
    all_source = "\n".join(p.read_text() for p in production).lower()
    assert "cron" not in all_source and "watchdog" not in all_source
    plugin_source = (ROOT / "hermes_verified_delivery" / "__init__.py").read_text()
    assert 'cfg.get("qualification_enabled") is not True' in plugin_source


def test_canonical_bytes_are_order_independent_and_sha_is_bound() -> None:
    left = canonical_bytes({"b": 2, "a": [1]})
    right = canonical_bytes({"a": [1], "b": 2})
    assert left == right == b'{"a":[1],"b":2}'
    assert hashlib.sha256(left).hexdigest() == "ef251833a4268e6926e8f6e65cc6a85ceab63494ebfbf8995f7ddf66e75355e5"
