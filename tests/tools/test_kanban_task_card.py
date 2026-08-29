import sqlite3

import pytest

from hermes_cli import kanban_db
from tools.kanban_task_card import insert_task_dag_atomic


def _conn():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.executescript(kanban_db.SCHEMA_SQL)
    return conn


def _cards():
    return [{"id": "one", "title": "one", "body": "one", "assignee": "02-builder", "status": "todo", "priority": 0}, {"id": "two", "title": "two", "body": "two", "assignee": "09-test", "status": "todo", "priority": 1}]


def test_atomic_task_dag_inserts_or_rolls_back():
    conn = _conn()
    assert insert_task_dag_atomic(conn, _cards(), [{"parent_id": "one", "child_id": "two"}], created_at=1, created_by="test") == ("one", "two")
    assert conn.execute("SELECT COUNT(*) FROM task_links").fetchone()[0] == 1


def test_atomic_task_dag_rejects_cycles_without_rows():
    conn = _conn()
    with pytest.raises(ValueError):
        insert_task_dag_atomic(conn, _cards(), [{"parent_id": "one", "child_id": "two"}, {"parent_id": "two", "child_id": "one"}], created_at=1, created_by="test")
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0