"""Hermes plugin registration; inert unless qualification is explicitly configured."""
from pathlib import Path
from typing import Any

from .controller import AuthorityStore, Controller, NativeKanbanAdapter, qualification_paths

__all__ = ["register"]
__version__ = "0.1.0"


def _config(ctx: Any) -> dict[str, Any]:
    try:
        value = ctx.get_config("verified_delivery", {})
    except TypeError:
        value = ctx.get_config("verified_delivery")
    return value if isinstance(value, dict) else {}


def register(ctx: Any) -> None:
    """Register best-effort wake hints; default configuration is a no-op."""
    def wake(**_event: Any) -> None:
        cfg = _config(ctx)
        if cfg.get("qualification_enabled") is not True:
            return
        required = ("authority_db", "board_db", "qualification_root")
        if any(not isinstance(cfg.get(key), str) or not cfg[key] for key in required):
            raise ValueError("qualification configuration is incomplete")
        root, authority_db, board_db = qualification_paths(
            Path(cfg["authority_db"]), Path(cfg["board_db"]), Path(cfg["qualification_root"]),
        )
        controller = Controller(
            AuthorityStore(authority_db, qualification_root=root),
            NativeKanbanAdapter(board_db, root),
        )
        controller.reconcile_held()

    for hook in (
        "kanban_task_completed", "kanban_task_blocked", "on_kanban_task_updated",
        "on_kanban_dispatch_tick",
    ):
        ctx.register_hook(hook, wake)
