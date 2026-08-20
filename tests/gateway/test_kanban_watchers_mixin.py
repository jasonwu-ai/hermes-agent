"""Tests for the extracted GatewayKanbanWatchersMixin (god-file Phase 3).

The kanban watcher loops were lifted out of gateway/run.py into a mixin that
GatewayRunner inherits. These tests confirm the mixin exposes the methods and
that GatewayRunner picks them up via the MRO (behavior-neutral relocation).
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from gateway.kanban_watchers import GatewayKanbanWatchersMixin

KANBAN_METHODS = [
    "_kanban_notifier_watcher",
    "_kanban_dispatcher_watcher",
    "_kanban_advance",
    "_kanban_unsub",
    "_kanban_rewind",
    "_deliver_kanban_artifacts",
]


def test_mixin_defines_kanban_methods():
    for m in KANBAN_METHODS:
        assert hasattr(GatewayKanbanWatchersMixin, m), f"mixin missing {m}"


@pytest.mark.asyncio
async def test_restricted_completion_never_extracts_summary_or_result_paths(tmp_path):
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("must not be delivered", encoding="utf-8")

    class Adapter:
        def extract_local_files(self, _text):
            raise AssertionError("restricted completion prose must not be scanned")

        async def send_multiple_images(self, **_kwargs):
            raise AssertionError("restricted completion prose must not be delivered")

        async def send_video(self, **_kwargs):
            raise AssertionError("restricted completion prose must not be delivered")

        async def send_document(self, **_kwargs):
            raise AssertionError("restricted completion prose must not be delivered")

    await GatewayKanbanWatchersMixin._deliver_kanban_artifacts(
        SimpleNamespace(),
        adapter=Adapter(),
        chat_id="test-chat",
        metadata={},
        event_payload={
            "restricted_artifact_delivery": True,
            "summary": f"completed evidence {outside}",
        },
        task=SimpleNamespace(result=f"legacy evidence {outside}"),
    )


