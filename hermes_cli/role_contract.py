"""Profile-bound role-contract admission for dispatcher-spawned workers.

This module is intentionally independent of prompt construction.  Its job is
pre-spawn authority admission: read exact contract bytes, validate their
profile/toolset bounds, and produce a deterministic run-bound receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Optional

import yaml


ROLE_CONTRACT_FILENAME = "ROLE_CONTRACT.md"
ROLE_CONTRACT_SCHEMA = "hermes-role-contract/v2"
MAX_ROLE_CONTRACT_BYTES = 64 * 1024
_MANDATORY_WORKER_TOOLSETS = frozenset({"kanban"})
_FORBIDDEN_TOOLSET_NAMES = frozenset({"all", "no_mcp"})
_SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_TOOLSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_EXPECTED_FRONTMATTER_KEYS = frozenset(
    {"schema", "profile", "version", "allowed_toolsets"}
)
_OPTIONAL_FRONTMATTER_KEYS = frozenset({"allowed_tools", "workspace_only"})


class RoleContractError(RuntimeError):
    """A worker role contract could not be admitted safely."""


@dataclass(frozen=True)
class RoleContract:
    path: Path
    schema: str
    profile: str
    version: str
    allowed_toolsets: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    workspace_only: bool
    body: str
    sha256: str
    raw_size: int


@dataclass(frozen=True)
class RoleContractAdmission:
    contract: RoleContract
    configured_toolsets: tuple[str, ...]
    effective_toolsets: tuple[str, ...]
    mandatory_toolsets: tuple[str, ...]
    task_id: str
    run_id: Optional[int]
    workspace_path: Optional[str]
    branch_name: Optional[str]
    receipt_id: str

    def receipt(self) -> dict[str, Any]:
        return {
            "schema": self.contract.schema,
            "profile": self.contract.profile,
            "version": self.contract.version,
            "contract_sha256": self.contract.sha256,
            "contract_size": self.contract.raw_size,
            "contract_path": str(self.contract.path),
            "configured_toolsets": list(self.configured_toolsets),
            "allowed_toolsets": list(self.contract.allowed_toolsets),
            "allowed_tools": list(self.contract.allowed_tools),
            "workspace_only": self.contract.workspace_only,
            "mandatory_toolsets": list(self.mandatory_toolsets),
            "effective_toolsets": list(self.effective_toolsets),
            "task_id": self.task_id,
            "run_id": self.run_id,
            "workspace_path": self.workspace_path,
            "branch_name": self.branch_name,
            "receipt_id": self.receipt_id,
        }


def _read_exact_regular_file(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        lst = path.lstat()
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(lst.st_mode):
        raise RoleContractError(f"role contract must not be a symlink: {path}")
    if not stat.S_ISREG(lst.st_mode):
        raise RoleContractError(f"role contract must be a regular file: {path}")
    if lst.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RoleContractError(
            f"role contract must not be group/world-writable: {path}"
        )
    if lst.st_size <= 0 or lst.st_size > MAX_ROLE_CONTRACT_BYTES:
        raise RoleContractError(
            f"role contract size must be 1..{MAX_ROLE_CONTRACT_BYTES} bytes: {path}"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RoleContractError(f"cannot open role contract safely: {path}: {exc}") from exc
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise RoleContractError(f"role contract changed type while opening: {path}")
        if fst.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RoleContractError(
                f"role contract became group/world-writable while opening: {path}"
            )
        if (fst.st_dev, fst.st_ino) != (lst.st_dev, lst.st_ino):
            raise RoleContractError(f"role contract changed while opening: {path}")
        chunks: list[bytes] = []
        remaining = MAX_ROLE_CONTRACT_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)

    if len(raw) != fst.st_size or len(raw) > MAX_ROLE_CONTRACT_BYTES:
        raise RoleContractError(f"role contract changed while reading: {path}")
    return raw, fst


def _parse_contract(raw: bytes, path: Path, expected_profile: str) -> RoleContract:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RoleContractError(f"role contract is not strict UTF-8: {path}") from exc
    if "\x00" in text:
        raise RoleContractError(f"role contract contains a NUL byte: {path}")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise RoleContractError(f"role contract must start with YAML front matter: {path}")
    try:
        closing = next(i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration as exc:
        raise RoleContractError(f"role contract front matter is not closed: {path}") from exc
    frontmatter_text = "\n".join(lines[1:closing])
    body = "\n".join(lines[closing + 1 :]).strip()
    if not body:
        raise RoleContractError(f"role contract body must not be empty: {path}")
    try:
        frontmatter = yaml.safe_load(frontmatter_text)
    except yaml.YAMLError as exc:
        raise RoleContractError(f"role contract front matter is invalid YAML: {path}: {exc}") from exc
    if not isinstance(frontmatter, dict):
        raise RoleContractError(f"role contract front matter must be a mapping: {path}")
    keys = frozenset(str(k) for k in frontmatter)
    if not _EXPECTED_FRONTMATTER_KEYS.issubset(keys) or not keys.issubset(
        _EXPECTED_FRONTMATTER_KEYS | _OPTIONAL_FRONTMATTER_KEYS
    ):
        missing = sorted(_EXPECTED_FRONTMATTER_KEYS - keys)
        extra = sorted(keys - _EXPECTED_FRONTMATTER_KEYS - _OPTIONAL_FRONTMATTER_KEYS)
        raise RoleContractError(
            f"role contract front matter keys mismatch: missing={missing}, extra={extra}"
        )

    schema = frontmatter.get("schema")
    profile = frontmatter.get("profile")
    version = frontmatter.get("version")
    allowed = frontmatter.get("allowed_toolsets")
    allowed_tools = frontmatter.get("allowed_tools", [])
    workspace_only = frontmatter.get("workspace_only", False)
    if schema != ROLE_CONTRACT_SCHEMA:
        raise RoleContractError(
            f"unsupported role contract schema {schema!r}; expected {ROLE_CONTRACT_SCHEMA!r}"
        )
    if not isinstance(profile, str) or profile.strip() != expected_profile:
        raise RoleContractError(
            f"role contract profile {profile!r} does not match assignee {expected_profile!r}"
        )
    if not isinstance(version, str) or not _SEMVER_RE.fullmatch(version.strip()):
        raise RoleContractError("role contract version must be a semantic version string")
    if not isinstance(allowed, list) or not allowed:
        raise RoleContractError("role contract allowed_toolsets must be a non-empty list")
    if not isinstance(allowed_tools, list) or any(
        not isinstance(item, str) or not _TOOLSET_RE.fullmatch(item.strip())
        for item in allowed_tools
    ):
        raise RoleContractError("role contract allowed_tools must be a list of tool names")
    normalized_tools = tuple(sorted({item.strip() for item in allowed_tools}))
    if len(normalized_tools) != len(allowed_tools):
        raise RoleContractError("role contract allowed_tools must not contain duplicates")
    if not isinstance(workspace_only, bool):
        raise RoleContractError("role contract workspace_only must be boolean")
    if workspace_only and not normalized_tools:
        raise RoleContractError("workspace_only role contract requires allowed_tools")

    normalized: list[str] = []
    seen: set[str] = set()
    for item in allowed:
        if not isinstance(item, str):
            raise RoleContractError("role contract toolset names must be strings")
        name = item.strip()
        if not _TOOLSET_RE.fullmatch(name):
            raise RoleContractError(f"invalid role contract toolset name: {item!r}")
        if name in _FORBIDDEN_TOOLSET_NAMES:
            raise RoleContractError(f"forbidden role contract toolset: {name}")
        if name in seen:
            raise RoleContractError(f"duplicate role contract toolset: {name}")
        try:
            from toolsets import TOOLSETS

            definition = TOOLSETS.get(name)
        except Exception:
            definition = None
        if isinstance(definition, dict) and (
            definition.get("includes") or definition.get("posture")
        ):
            raise RoleContractError(
                f"role contract must name atomic toolsets, not composite/posture {name!r}"
            )
        seen.add(name)
        normalized.append(name)

    return RoleContract(
        path=path,
        schema=schema,
        profile=profile.strip(),
        version=version.strip(),
        allowed_toolsets=tuple(sorted(normalized)),
        allowed_tools=normalized_tools,
        workspace_only=workspace_only,
        body=body,
        sha256=hashlib.sha256(raw).hexdigest(),
        raw_size=len(raw),
    )


def load_role_contract(
    profile_home: str | os.PathLike[str],
    expected_profile: str,
    *,
    required: bool,
) -> Optional[RoleContract]:
    """Load and validate one profile's exact role-contract bytes.

    Missing is allowed only when the task did not explicitly require admission.
    Any present contract is authoritative and therefore must validate.
    """
    home = Path(profile_home)
    path = home / ROLE_CONTRACT_FILENAME
    try:
        raw, _ = _read_exact_regular_file(path)
    except FileNotFoundError:
        if required:
            raise RoleContractError(f"required role contract is missing: {path}")
        return None
    return _parse_contract(raw, path, expected_profile)


def admit_role_contract(
    profile_home: str | os.PathLike[str],
    expected_profile: str,
    configured_toolsets: Iterable[str],
    *,
    task_id: str,
    run_id: Optional[int],
    workspace_path: Optional[str] = None,
    branch_name: Optional[str] = None,
    required: bool,
) -> Optional[RoleContractAdmission]:
    """Admit a profile contract and derive a non-widening toolset surface."""
    contract = load_role_contract(profile_home, expected_profile, required=required)
    if contract is None:
        return None

    configured = tuple(sorted({str(item).strip() for item in configured_toolsets if str(item).strip()}))
    configured_set = set(configured)
    requested = set(contract.allowed_toolsets)
    unavailable = sorted(requested - configured_set - set(_MANDATORY_WORKER_TOOLSETS))
    if unavailable:
        raise RoleContractError(
            "role contract requests toolsets not enabled by the assignee profile: "
            + ", ".join(unavailable)
        )
    effective = tuple(sorted((configured_set & requested) | set(_MANDATORY_WORKER_TOOLSETS)))
    receipt_basis = {
        "schema": contract.schema,
        "profile": contract.profile,
        "version": contract.version,
        "contract_sha256": contract.sha256,
        "configured_toolsets": list(configured),
        "allowed_toolsets": list(contract.allowed_toolsets),
        "allowed_tools": list(contract.allowed_tools),
        "workspace_only": contract.workspace_only,
        "mandatory_toolsets": sorted(_MANDATORY_WORKER_TOOLSETS),
        "effective_toolsets": list(effective),
        "task_id": task_id,
        "run_id": run_id,
        "workspace_path": workspace_path,
        "branch_name": branch_name,
    }
    receipt_id = hashlib.sha256(
        json.dumps(receipt_basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return RoleContractAdmission(
        contract=contract,
        configured_toolsets=configured,
        effective_toolsets=effective,
        mandatory_toolsets=tuple(sorted(_MANDATORY_WORKER_TOOLSETS)),
        task_id=task_id,
        run_id=run_id,
        workspace_path=workspace_path,
        branch_name=branch_name,
        receipt_id=receipt_id,
    )


def verify_admission_bytes(admission: RoleContractAdmission) -> None:
    """Re-read the exact contract immediately before spawn and detect drift."""
    raw, _ = _read_exact_regular_file(admission.contract.path)
    actual = hashlib.sha256(raw).hexdigest()
    if actual != admission.contract.sha256:
        raise RoleContractError(
            "role contract bytes changed after admission: "
            f"expected {admission.contract.sha256}, got {actual}"
        )
