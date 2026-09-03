from __future__ import annotations

import os
from pathlib import Path
import socket
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
UPSTREAM = Path(os.environ.get("HVD_UPSTREAM", "/tmp/hermes-native-upstream-4dac5f28")).resolve()
if not (UPSTREAM / "hermes_cli" / "kanban_db.py").is_file():
    raise RuntimeError("HVD_UPSTREAM must name the pinned Hermes checkout")
sys.path.insert(0, str(UPSTREAM))


@pytest.fixture(autouse=True)
def deny_ip_network(monkeypatch: pytest.MonkeyPatch):
    original = socket.socket.connect

    def guarded(sock: socket.socket, address):
        if sock.family in {socket.AF_INET, socket.AF_INET6}:
            raise AssertionError(f"IP network forbidden during qualification: {address!r}")
        return original(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture
def qualification_root(tmp_path: Path) -> Path:
    root = tmp_path / "qualification"
    root.mkdir()
    (root / ".hvd-qualification-root").write_text("HVD_QUALIFICATION_ONLY_V1\n", encoding="utf-8")
    return root
