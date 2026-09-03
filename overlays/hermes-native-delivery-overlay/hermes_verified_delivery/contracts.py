"""Strict, canonical contracts for the qualification-only overlay."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
_UTC = "%Y-%m-%dT%H:%M:%SZ"


class ContractError(ValueError):
    """The supplied bytes do not satisfy the exact contract."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, _UTC).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"timestamp must use canonical UTC form {_UTC}") from exc
    return parsed


def _exact(data: Mapping[str, Any], fields: set[str], label: str) -> None:
    unknown = set(data) - fields
    missing = fields - set(data)
    if unknown:
        raise ContractError(f"{label} unknown fields: {sorted(unknown)}")
    if missing:
        raise ContractError(f"{label} missing fields: {sorted(missing)}")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ContractError(f"{label} is not a bounded identifier")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(v, str) or not v for v in value):
        raise ContractError(f"{label} must be a non-empty string list")
    if len(value) != len(set(value)):
        raise ContractError(f"{label} contains duplicates")
    return tuple(value)


@dataclass(frozen=True)
class Decision:
    schema: str
    spec_id: str
    revision: int
    spec_sha256: str
    actor: str
    action: str
    nonce: str
    replay_key: str
    issued_at: str
    expires_at: str
    allowed_actions: tuple[str, ...]
    exclusions: tuple[str, ...]
    feedback: str | None

    FIELDS = {
        "schema", "spec_id", "revision", "spec_sha256", "actor", "action",
        "nonce", "replay_key", "issued_at", "expires_at", "allowed_actions",
        "exclusions", "feedback",
    }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Decision":
        if not isinstance(data, Mapping):
            raise ContractError("decision must be an object")
        _exact(data, cls.FIELDS, "decision")
        if data["schema"] != "hvd-decision/v1":
            raise ContractError("unsupported decision schema")
        if not isinstance(data["revision"], int) or isinstance(data["revision"], bool) or data["revision"] < 1:
            raise ContractError("revision must be a positive integer")
        if not isinstance(data["spec_sha256"], str) or not _SHA256.fullmatch(data["spec_sha256"]):
            raise ContractError("spec_sha256 must be lowercase SHA-256")
        action = data["action"]
        if action not in {"APPROVE", "REQUEST_CHANGES", "REJECT"}:
            raise ContractError("unsupported action")
        feedback = data["feedback"]
        if feedback is not None and (not isinstance(feedback, str) or not feedback.strip()):
            raise ContractError("feedback must be null or nonblank text")
        if action == "REQUEST_CHANGES" and feedback is None:
            raise ContractError("REQUEST_CHANGES requires feedback")
        if action == "APPROVE" and feedback is not None:
            raise ContractError("APPROVE must not carry feedback")
        issued, expires = parse_utc(data["issued_at"]), parse_utc(data["expires_at"])
        if expires <= issued:
            raise ContractError("decision must expire after issuance")
        return cls(
            schema=data["schema"], spec_id=_identifier(data["spec_id"], "spec_id"),
            revision=data["revision"], spec_sha256=data["spec_sha256"],
            actor=_identifier(data["actor"], "actor"), action=action,
            nonce=_identifier(data["nonce"], "nonce"),
            replay_key=_identifier(data["replay_key"], "replay_key"),
            issued_at=data["issued_at"], expires_at=data["expires_at"],
            allowed_actions=_strings(data["allowed_actions"], "allowed_actions"),
            exclusions=_strings(data["exclusions"], "exclusions"), feedback=feedback,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "spec_id": self.spec_id, "revision": self.revision,
            "spec_sha256": self.spec_sha256, "actor": self.actor, "action": self.action,
            "nonce": self.nonce, "replay_key": self.replay_key,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "allowed_actions": list(self.allowed_actions), "exclusions": list(self.exclusions),
            "feedback": self.feedback,
        }

    @property
    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self.to_dict()))

    @property
    def decision_id(self) -> str:
        return f"dec_{self.digest[:24]}"


@dataclass(frozen=True)
class GraphTask:
    key: str
    title: str
    assignee: str
    parents: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GraphTask":
        _exact(data, {"key", "title", "assignee", "parents"}, "graph task")
        if not isinstance(data["title"], str) or not data["title"].strip():
            raise ContractError("task title must be nonblank")
        parents = data["parents"]
        if not isinstance(parents, list) or any(not isinstance(p, str) for p in parents):
            raise ContractError("parents must be a string list")
        if len(parents) != len(set(parents)):
            raise ContractError("parents contains duplicates")
        return cls(_identifier(data["key"], "task key"), data["title"].strip(),
                   _identifier(data["assignee"], "assignee"), tuple(parents))

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "title": self.title, "assignee": self.assignee, "parents": list(self.parents)}


@dataclass(frozen=True)
class GraphSpec:
    schema: str
    run_id: str
    approval_id: str
    tasks: tuple[GraphTask, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GraphSpec":
        _exact(data, {"schema", "run_id", "approval_id", "tasks"}, "graph")
        if data["schema"] != "hvd-inert-graph/v1":
            raise ContractError("unsupported graph schema")
        if not isinstance(data["tasks"], list) or not data["tasks"]:
            raise ContractError("graph tasks must be non-empty")
        tasks = tuple(GraphTask.from_dict(v) for v in data["tasks"])
        keys = {task.key for task in tasks}
        if len(keys) != len(tasks):
            raise ContractError("graph task keys must be unique")
        for task in tasks:
            missing = set(task.parents) - keys
            if missing or task.key in task.parents:
                raise ContractError(f"invalid parents for {task.key}: {sorted(missing)}")
        graph = cls(data["schema"], _identifier(data["run_id"], "run_id"),
                    _identifier(data["approval_id"], "approval_id"), tasks)
        graph.topological_tasks()
        return graph

    def to_dict(self) -> dict[str, Any]:
        return {"schema": self.schema, "run_id": self.run_id, "approval_id": self.approval_id,
                "tasks": [task.to_dict() for task in self.tasks]}

    @property
    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self.to_dict()))

    def topological_tasks(self) -> tuple[GraphTask, ...]:
        pending = {task.key: task for task in self.tasks}
        emitted: set[str] = set()
        ordered: list[GraphTask] = []
        while pending:
            ready = sorted((t for t in pending.values() if set(t.parents) <= emitted), key=lambda t: t.key)
            if not ready:
                raise ContractError("graph contains a cycle")
            for task in ready:
                ordered.append(task)
                emitted.add(task.key)
                pending.pop(task.key)
        return tuple(ordered)
