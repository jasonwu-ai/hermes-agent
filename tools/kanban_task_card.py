"""Transactional insertion of a prevalidated inert Kanban task DAG."""
from __future__ import annotations

import re
import sqlite3
from typing import Any, Mapping, Sequence


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _valid_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _valid_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _has_cycle(ids: set[str], links: list[tuple[str, str]]) -> bool:
    parents = {item: [] for item in ids}
    for parent, child in links:
        parents[child].append(parent)
    active: set[str] = set()
    finished: set[str] = set()

    def visit(item: str) -> bool:
        if item in active:
            return True
        if item in finished:
            return False
        active.add(item)
        cyclic = any(visit(parent) for parent in parents[item])
        active.remove(item)
        finished.add(item)
        return cyclic

    return any(visit(item) for item in ids)


def insert_task_dag_atomic(conn: sqlite3.Connection, task_cards: Sequence[Mapping[str, Any]], links: Sequence[Mapping[str, str]], *, created_at: int, created_by: str) -> tuple[str, ...]:
    """Insert cards and links with one ``BEGIN IMMEDIATE`` or leave no writes."""
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError("conn must be a sqlite3.Connection")
    if conn.in_transaction:
        raise RuntimeError("connection already has an active transaction")
    if not _valid_int(created_at) or not _valid_text(created_by):
        raise ValueError("invalid creation metadata")
    cards = list(task_cards)
    normalized: list[tuple[str, str, str, str, int]] = []
    ids: set[str] = set()
    for card in cards:
        if not isinstance(card, Mapping) or set(card) != {"id", "title", "body", "assignee", "status", "priority"}:
            raise ValueError("invalid task card shape")
        task_id = card["id"]
        if not _valid_text(task_id) or not _ID.fullmatch(task_id) or task_id in ids or not all(_valid_text(card[key]) for key in ("title", "body", "assignee")) or card["status"] != "todo" or not _valid_int(card["priority"]):
            raise ValueError("invalid task card")
        ids.add(task_id)
        normalized.append((task_id, card["title"], card["body"], card["assignee"], card["priority"]))
    normalized_links: list[tuple[str, str]] = []
    link_set: set[tuple[str, str]] = set()
    for link in links:
        if not isinstance(link, Mapping) or set(link) != {"parent_id", "child_id"}:
            raise ValueError("invalid link shape")
        edge = (link["parent_id"], link["child_id"])
        if not all(isinstance(item, str) and _ID.fullmatch(item) for item in edge) or edge[0] not in ids or edge[1] not in ids or edge[0] == edge[1] or edge in link_set:
            raise ValueError("invalid task link")
        link_set.add(edge)
        normalized_links.append(edge)
    if _has_cycle(ids, normalized_links):
        raise ValueError("proposed graph contains a cycle")
    try:
        conn.execute("BEGIN IMMEDIATE")
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('tasks', 'task_links')")}
        if tables != {"tasks", "task_links"}:
            raise RuntimeError("database is not initialized with Kanban task tables")
        existing_ids = {row[0] for row in conn.execute("SELECT id FROM tasks")}
        if ids & existing_ids:
            raise ValueError("task id already exists")
        existing_links = [(row[0], row[1]) for row in conn.execute("SELECT parent_id, child_id FROM task_links")]
        all_ids = ids | existing_ids
        if any(parent not in all_ids or child not in all_ids for parent, child in existing_links) or _has_cycle(all_ids, existing_links + normalized_links):
            raise ValueError("combined graph contains a cycle or missing endpoint")
        conn.executemany("INSERT INTO tasks(id,title,body,assignee,status,priority,created_by,created_at) VALUES(?,?,?,?, 'todo',?,?,?)", [(task_id, title, body, assignee, priority, created_by, created_at) for task_id, title, body, assignee, priority in normalized])
        conn.executemany("INSERT INTO task_links(parent_id,child_id) VALUES(?,?)", normalized_links)
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
    return tuple(item[0] for item in normalized)