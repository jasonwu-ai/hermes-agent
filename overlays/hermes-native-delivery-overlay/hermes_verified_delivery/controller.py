from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
from typing import Any, Iterator

from .contracts import ContractError, Decision, GraphSpec, canonical_bytes, parse_utc, sha256_hex


class ReplayConflict(ContractError):
    pass


class MaterializationConflict(ContractError):
    pass


class InjectedCrash(RuntimeError):
    pass


def _absolute_without_symlinks(path: Path, label: str) -> Path:
    raw = Path(path)
    if not raw.is_absolute() or ".." in raw.parts:
        raise ContractError(f"{label} must be an absolute non-aliased path")
    current = Path(raw.anchor)
    for part in raw.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ContractError(f"{label} cannot be inspected safely within qualification root confinement") from exc
        if stat.S_ISLNK(mode):
            raise ContractError(f"{label} must not traverse a symlink")
    return raw


def _qualification_root(path: Path) -> Path:
    root = _absolute_without_symlinks(path, "qualification root")
    if not root.is_dir():
        raise ContractError("qualification root must already exist")
    marker = root / ".hvd-qualification-root"
    if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="utf-8") != NativeKanbanAdapter.MARKER:
        raise ContractError("qualification marker missing or invalid")
    return root


def _owned_descriptor(path: Path, label: str, flags: int, *, bound_to: int | None = None) -> int | None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ContractError(f"{label} cannot be inspected safely without no-follow support")
    try:
        descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ContractError(f"{label} cannot be inspected safely without following aliases") from exc
    try:
        entry, opened = os.lstat(path), os.fstat(descriptor)
        aliased = (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino)
        if aliased or not stat.S_ISREG(entry.st_mode) or not stat.S_ISREG(opened.st_mode):
            raise ContractError(f"{label} must be one stable regular file")
        if entry.st_nlink != 1 or opened.st_nlink != 1:
            raise ContractError(f"{label} must not be a hard link or inode alias")
        if bound_to is not None and not os.path.sameopenfile(bound_to, descriptor):
            raise ContractError(f"{label} was replaced while bound")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _probe(path: Path, label: str, *, bound_to: int | None = None) -> None:
    descriptor = _owned_descriptor(path, label, os.O_RDONLY, bound_to=bound_to)
    if descriptor is not None:
        os.close(descriptor)


def _confined_database(path: Path, root: Path, label: str, *, bound_to: int | None = None) -> Path:
    candidate = _absolute_without_symlinks(path, label)
    if candidate.parent != root:
        raise ContractError(f"{label} must be a direct child of qualification root")
    _probe(candidate, label, bound_to=bound_to)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{candidate}{suffix}")
        descriptor = _owned_descriptor(sidecar, f"{label} sidecars", os.O_RDONLY)
        if descriptor is not None:
            os.close(descriptor)
            raise ContractError(f"{label} must not retain SQLite sidecars")
    return candidate


def _created_descriptor(path: Path, label: str) -> int:
    descriptor = _owned_descriptor(path, label, os.O_CREAT | os.O_RDWR)
    if descriptor is None:
        raise ContractError(f"{label} could not be created")
    return descriptor


def _persist_image(path: Path, root: Path, label: str, payload: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=root)
    temporary = Path(name)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as handle:
            handle.write(payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        _probe(temporary, label, bound_to=descriptor)
        _confined_database(path, root, label)
        os.replace(temporary, path)
        _probe(path, label, bound_to=descriptor)
        _confined_database(path, root, label)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


@contextmanager
def _confined_image(path: Path, root: Path, label: str, *, write: bool = False) -> Iterator[sqlite3.Connection]:
    path = _absolute_without_symlinks(path, label)
    if path.parent != root:
        raise ContractError(f"{label} must be a direct child of qualification root")
    source = _owned_descriptor(path, label, os.O_RDONLY)
    _confined_database(path, root, label, bound_to=source)
    conn = sqlite3.connect(":memory:", isolation_level=None)
    try:
        if source is not None and os.fstat(source).st_size:
            conn.deserialize(os.pread(source, os.fstat(source).st_size, 0))
        conn.row_factory = sqlite3.Row
        yield conn
        if write:
            if source is not None:
                _probe(path, label, bound_to=source)
            _persist_image(path, root, label, conn.serialize())
    finally:
        conn.close()
        if source is not None:
            os.close(source)


def qualification_paths(authority_db: Path, board_db: Path, root: Path) -> tuple[Path, Path, Path]:
    root = _qualification_root(root)
    authority_db = _confined_database(authority_db, root, "authority DB")
    board_db = _confined_database(board_db, root, "board DB")
    if authority_db == board_db:
        raise ContractError("authority DB and board DB must be distinct")
    _probe(_absolute_without_symlinks(root / ".hvd-controller.lock", "controller lock"), "controller lock")
    return root, authority_db, board_db


class AuthorityStore:
    def __init__(self, path: Path, *, qualification_root: Path | None = None):
        self.qualification_root = _qualification_root(qualification_root) if qualification_root else None
        self.path = _confined_database(path, self.qualification_root, "authority DB") if self.qualification_root else Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection(write=True) as conn:
            conn.executescript(f"""
            PRAGMA journal_mode={'MEMORY' if self.qualification_root else 'WAL'};
            CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, replay_key TEXT NOT NULL UNIQUE, digest TEXT NOT NULL, payload BLOB NOT NULL, action TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox(key TEXT PRIMARY KEY, decision_id TEXT NOT NULL UNIQUE,
              state TEXT NOT NULL CHECK(state='HELD'), payload BLOB NOT NULL, FOREIGN KEY(decision_id) REFERENCES decisions(id));
            CREATE TABLE IF NOT EXISTS materializations(run_id TEXT PRIMARY KEY, graph_digest TEXT NOT NULL,
              mapping_digest TEXT NOT NULL, mapping_payload BLOB NOT NULL);
            """)
        if not self.qualification_root:
            os.chmod(self.path, 0o600)

    @contextmanager
    def _connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        if self.qualification_root:
            with _exclusive(self.qualification_root / ".hvd-controller.lock"), _confined_image(self.path, self.qualification_root, "authority DB", write=write) as conn:
                conn.execute("PRAGMA foreign_keys=ON")
                yield conn
        else:
            with closing(sqlite3.connect(self.path, timeout=30, isolation_level=None)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys=ON")
                yield conn

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._connection(write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def record_decision(self, decision: Decision, *, graph: GraphSpec | None = None,
                        failpoint: str | None = None) -> str:
        if decision.action == "APPROVE":
            if graph is None or graph.approval_id != decision.decision_id:
                raise ContractError("APPROVE requires its exact inert graph")
        elif graph is not None:
            raise ContractError("only APPROVE may carry a graph intent")
        payload = canonical_bytes(decision.to_dict())
        outbox_payload = canonical_bytes(graph.to_dict()) if graph else None
        with self._write() as conn:
            existing = conn.execute("SELECT id,digest FROM decisions WHERE replay_key=?", (decision.replay_key,)).fetchone()
            if existing:
                if existing["id"] != decision.decision_id or existing["digest"] != decision.digest:
                    raise ReplayConflict("replay key already binds different decision bytes")
                if graph:
                    row = conn.execute("SELECT payload FROM outbox WHERE decision_id=?", (decision.decision_id,)).fetchone()
                    if row is None or bytes(row["payload"]) != outbox_payload:
                        raise ReplayConflict("decision replay carries different projection bytes")
                return decision.decision_id
            conn.execute("INSERT INTO decisions(id,replay_key,digest,payload,action) VALUES(?,?,?,?,?)",
                         (decision.decision_id, decision.replay_key, decision.digest, payload, decision.action))
            if failpoint == "after_decision":
                raise InjectedCrash(failpoint)
            if graph:
                conn.execute("INSERT INTO outbox(key,decision_id,state,payload) VALUES(?,?,?,?)",
                             (f"held:{decision.decision_id}", decision.decision_id, "HELD", outbox_payload))
            if failpoint == "after_outbox":
                raise InjectedCrash(failpoint)
        return decision.decision_id

    def held_intents(self) -> tuple[tuple[Decision, GraphSpec], ...]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT decisions.payload AS decision_payload,outbox.payload AS graph_payload "
                "FROM outbox JOIN decisions ON decisions.id=outbox.decision_id "
                "WHERE outbox.state='HELD' ORDER BY outbox.key"
            ).fetchall()
        intents = []
        for row in rows:
            decision = Decision.from_dict(json.loads(bytes(row["decision_payload"])))
            graph = GraphSpec.from_dict(json.loads(bytes(row["graph_payload"])))
            if graph.approval_id != decision.decision_id or decision.action != "APPROVE":
                raise ContractError("HELD intent is not bound to its approval")
            intents.append((decision, graph))
        return tuple(intents)

    def materialization_for(self, graph: GraphSpec) -> dict[str, str] | None:
        with self._connection() as conn:
            row = conn.execute("SELECT graph_digest,mapping_digest,mapping_payload FROM materializations WHERE run_id=?",
                               (graph.run_id,)).fetchone()
        if row is None:
            return None
        payload = bytes(row["mapping_payload"])
        if row["graph_digest"] != graph.digest or row["mapping_digest"] != sha256_hex(payload):
            raise MaterializationConflict("recorded materialization does not match graph or mapping bytes")
        value = json.loads(payload)
        if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
            raise MaterializationConflict("recorded materialization mapping is invalid")
        return dict(sorted(value.items()))

    def record_materialization(self, graph: GraphSpec, mapping: dict[str, str]) -> None:
        body = canonical_bytes(mapping)
        digest = sha256_hex(body)
        with self._write() as conn:
            row = conn.execute("SELECT graph_digest,mapping_digest FROM materializations WHERE run_id=?",
                               (graph.run_id,)).fetchone()
            if row:
                if row["graph_digest"] != graph.digest or row["mapping_digest"] != digest:
                    raise MaterializationConflict("run id already binds different graph or task mapping")
            else:
                conn.execute("INSERT INTO materializations(run_id,graph_digest,mapping_digest,mapping_payload) VALUES(?,?,?,?)",
                             (graph.run_id, graph.digest, digest, body))

    def counts(self) -> dict[str, int]:
        with self._connection() as conn:
            return {name: conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                    for name in ("decisions", "outbox", "materializations")}

    def decision_payload(self, decision_id: str) -> bytes:
        with self._connection() as conn:
            row = conn.execute("SELECT payload FROM decisions WHERE id=?", (decision_id,)).fetchone()
        if row is None:
            raise KeyError(decision_id)
        return bytes(row["payload"])


_LOCAL_LOCKS: dict[str, threading.Lock] = {}
_LOCAL_LOCKS_GUARD = threading.Lock()


@contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    with _LOCAL_LOCKS_GUARD:
        local = _LOCAL_LOCKS.setdefault(str(path), threading.Lock())
    with local:
        path.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(_created_descriptor(path, "controller lock"), "a+b") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)


class NativeKanbanAdapter:
    MARKER = "HVD_QUALIFICATION_ONLY_V1\n"

    def __init__(self, board_db: Path, qualification_root: Path):
        self.root = _qualification_root(qualification_root)
        self.board_db = _confined_database(board_db, self.root, "board DB")
        self.lock_path = self.root / ".hvd-controller.lock"

    @staticmethod
    def _task_body(graph: GraphSpec, task: Any) -> str:
        return canonical_bytes({"schema": "hvd-inert-task/v1", "authority": "DO_NOT_EXECUTE",
                                "run_id": graph.run_id, "approval_id": graph.approval_id,
                                "graph_digest": graph.digest, "task": task.to_dict()}).decode()

    @staticmethod
    def _expected_contract(kb: Any, graph: GraphSpec, task: Any, key: str) -> dict[str, Any]:
        return {
            "title": task.title, "body": NativeKanbanAdapter._task_body(graph, task),
            "assignee": kb._canonical_assignee(task.assignee), "priority": 0,
            "created_by": "hermes-verified-delivery", "workspace_kind": "scratch",
            "workspace_path": None, "branch_name": None, "project_id": None,
            "tenant": None, "idempotency_key": key, "max_runtime_seconds": None,
            "skills": None, "max_retries": None, "model_override": None,
            "provider_override": None, "reasoning_effort": None, "goal_mode": 0,
            "goal_max_turns": None, "require_role_contract": 0, "session_id": None,
            "expected_role_contract_sha256": None,
        }

    @classmethod
    def _assert_task_contract(cls, kb: Any, row: Any, graph: GraphSpec, task: Any, key: str,
                              *, allow_archived: bool = False) -> None:
        expected = cls._expected_contract(kb, graph, task, key)
        mismatched = [name for name, value in expected.items() if row[name] != value]
        allowed_statuses = {"blocked", "archived"} if allow_archived else {"blocked"}
        if row["status"] not in allowed_statuses:
            mismatched.append("status")
        if row["status"] == "blocked":
            inactive = {"started_at": None, "completed_at": None, "claim_lock": None,
                        "claim_expires": None, "worker_pid": None, "last_heartbeat_at": None,
                        "current_run_id": None, "result": None, "consecutive_failures": 0,
                        "last_failure_error": None, "workflow_template_id": None,
                        "current_step_key": None, "block_kind": None, "block_recurrences": 0}
            mismatched.extend(name for name, value in inactive.items() if row[name] != value)
        if mismatched:
            raise MaterializationConflict(f"contract mismatch for {key}: {sorted(set(mismatched))}")

    @contextmanager
    def _board(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        from hermes_cli import kanban_db as kb
        with _confined_image(self.board_db, self.root, "board DB", write=write) as conn:
            conn.executescript(f"PRAGMA journal_mode=MEMORY; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;{kb.SCHEMA_SQL}")
            kb._migrate_add_optional_columns(conn)
            yield conn

    def verify_recorded_mapping(self, graph: GraphSpec, mapping: dict[str, str]) -> None:
        from hermes_cli import kanban_db as kb
        if set(mapping) != {task.key for task in graph.tasks}:
            raise MaterializationConflict("recorded mapping keys do not match graph")
        with _exclusive(self.lock_path), self._board() as conn:
            for task in graph.topological_tasks():
                key = f"hvd:{graph.run_id}:{task.key}"
                row = conn.execute("SELECT * FROM tasks WHERE id=?", (mapping[task.key],)).fetchone()
                if row is None:
                    raise MaterializationConflict(f"recorded task missing for {key}")
                self._assert_task_contract(kb, row, graph, task, key, allow_archived=True)
                if set(kb.parent_ids(conn, row["id"])) != {mapping[parent] for parent in task.parents}:
                    raise MaterializationConflict(f"parent mismatch for {key}")

    def materialize(self, graph: GraphSpec, *, failpoint: str | None = None) -> dict[str, str]:
        from hermes_cli import kanban_db as kb
        mapping: dict[str, str] = {}
        with _exclusive(self.lock_path), self._board(write=True) as conn, kb.write_txn(conn):
            for index, task in enumerate(graph.topological_tasks()):
                key = f"hvd:{graph.run_id}:{task.key}"
                rows = conn.execute("SELECT * FROM tasks WHERE idempotency_key=? ORDER BY id", (key,)).fetchall()
                if len(rows) > 1:
                    raise MaterializationConflict(f"duplicate semantic key {key}")
                parents = [mapping[p] for p in task.parents]
                if rows:
                    self._assert_task_contract(kb, rows[0], graph, task, key)
                    task_id = rows[0]["id"]
                else:
                    task_id = kb.create_task(conn, title=task.title, body=self._task_body(graph, task),
                                             assignee=task.assignee, created_by="hermes-verified-delivery",
                                             workspace_kind="scratch", parents=parents, idempotency_key=key,
                                             initial_status="blocked", goal_mode=False, require_role_contract=False,
                                             expected_role_contract_sha256=None, project_id="")
                mapping[task.key] = task_id
                if set(kb.parent_ids(conn, task_id)) != set(parents):
                    raise MaterializationConflict(f"parent mismatch for {key}")
                if failpoint == f"after_task_{index}":
                    raise InjectedCrash(failpoint)
            return dict(sorted(mapping.items()))

    def graph_counts(self, run_id: str) -> dict[str, int]:
        prefix = (f"hvd:{run_id}:%",)
        with _exclusive(self.lock_path), self._board() as conn:
            tasks = "SELECT COUNT(*) FROM tasks WHERE idempotency_key LIKE ? AND status!='archived'"
            links = "SELECT COUNT(*) FROM task_links WHERE parent_id IN (SELECT id FROM tasks WHERE idempotency_key LIKE ?)"
            return {"tasks": conn.execute(tasks, prefix).fetchone()[0], "links": conn.execute(links, prefix).fetchone()[0]}


class Controller:
    def __init__(self, store: AuthorityStore, adapter: NativeKanbanAdapter):
        self.store, self.adapter = store, adapter

    def reconcile_held(self, *, now: datetime | None = None,
                       failpoint: str | None = None) -> tuple[dict[str, str], ...]:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ContractError("reconciliation time must be timezone-aware")
        results = []
        for decision, graph in self.store.held_intents():
            if not (parse_utc(decision.issued_at) <= now < parse_utc(decision.expires_at)):
                raise ContractError("HELD authority is outside its admitted interval")
            mapping = self.store.materialization_for(graph)
            if mapping is None:
                mapping = self.adapter.materialize(graph, failpoint=failpoint)
                self.store.record_materialization(graph, mapping)
            else:
                self.adapter.verify_recorded_mapping(graph, mapping)
            results.append(mapping)
            failpoint = None
        return tuple(results)
