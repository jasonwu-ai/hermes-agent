"""Signed, release-inert custody for release, merge, and deployment decisions.

This module records authority and evidence only. It performs no GitHub merge,
deployment, installation, release publication, or live enablement action.

Trust boundary: application startup and the caller are trusted; persisted
control/board database contents are adversarial and are revalidated. Arbitrary
same-process Python is outside this module's security boundary because it can
replace any in-process verifier. A future executable adapter must isolate its
trust anchor in a separately privileged controller and atomically revalidate
board custody at consumption time. Receipts from this module are inert custody
and MUST NOT be treated as directly executable merge or deployment authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature

from plugins.verified_pipeline import controller, execution

RELEASE_CONTROLLER_ID = "verified-pipeline/release-boundary-controller/v1"
RELEASE_READY_AUTH_SCHEMA = "verified-pipeline/release-ready-decision/v1"
MERGE_AUTH_SCHEMA = "verified-pipeline/merge-authorization-decision/v1"
MERGE_RESULT_SCHEMA = "verified-pipeline/merge-result-attestation/v1"
DEPLOY_AUTH_SCHEMA = "verified-pipeline/deployment-authorization-decision/v1"

RELEASE_READY_DECISION = "ATTEST_RELEASE_READY"
MERGE_DECISION = "AUTHORIZE_EXACT_MERGE"
MERGE_RESULT_DECISION = "ATTEST_EXACT_MERGE_RESULT"
DEPLOY_DECISION = "AUTHORIZE_EXACT_DEPLOYMENT"

RELEASE_READY_STATUS = "RELEASE_READY_PENDING_MERGE_AUTHORIZATION"
MERGE_AUTH_STATUS = "MERGE_AUTHORIZATION_RECORDED_PENDING_ATOMIC_REVALIDATION"
MERGE_RESULT_STATUS = "MERGED_PENDING_DEPLOYMENT_AUTHORIZATION"
DEPLOY_AUTH_STATUS = "DEPLOYMENT_AUTHORIZATION_RECORDED_PENDING_ATOMIC_REVALIDATION"
EXECUTION_POLICY_KEY = "execution_authority"
AUTHORITY_POLICY_PIN_ENV = "HERMES_VERIFIED_PIPELINE_RELEASE_POLICY_SHA256"
_EXTERNAL_AUTHORITY_POLICY_SHA256 = os.environ.get(AUTHORITY_POLICY_PIN_ENV, "")


class ReleaseBoundaryError(RuntimeError):
    """Stable fail-closed error raised by release-boundary custody."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _external_policy_pin() -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", _EXTERNAL_AUTHORITY_POLICY_SHA256):
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_POLICY_PIN_REQUIRED",
            "an immutable application-startup release authority policy pin is required",
        )
    return _EXTERNAL_AUTHORITY_POLICY_SHA256


def _policy_sha256(policy_json: str) -> str:
    return hashlib.sha256(policy_json.encode("utf-8")).hexdigest()


def _canonical_authority_policy(
    authority_verifiers: Mapping[str, Mapping[str, Any]],
) -> str:
    expected = {
        EXECUTION_POLICY_KEY,
        RELEASE_READY_DECISION,
        MERGE_DECISION,
        MERGE_RESULT_DECISION,
        DEPLOY_DECISION,
    }
    if (
        not isinstance(authority_verifiers, Mapping)
        or set(authority_verifiers) != expected
    ):
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_POLICY_INVALID",
            "release authority policy has missing or unknown stages",
        )
    normalized: dict[str, dict[str, Any]] = {}
    for stage in sorted(expected):
        verifier = authority_verifiers[stage]
        try:
            execution._authority_public_key(verifier)
        except execution.ExecutionError as exc:
            raise ReleaseBoundaryError(
                "RELEASE_AUTHORITY_POLICY_INVALID",
                f"release authority verifier is invalid for {stage}",
            ) from exc
        normalized[stage] = dict(verifier)
    return execution._canonical(normalized)


def init_release_schema(
    db_path: Optional[str | os.PathLike[str]] = None,
    *,
    authority_verifiers: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> os.PathLike[str]:
    external_policy_sha256 = _external_policy_pin()
    path = execution.init_execution_schema(db_path)
    conn = controller.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS release_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                controller_id TEXT NOT NULL,
                authority_policy_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS release_authority_receipts (
                authority_key TEXT PRIMARY KEY,
                execution_key TEXT NOT NULL REFERENCES execution_outbox(idempotency_key),
                decision TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(execution_key, decision)
            );

            CREATE TABLE IF NOT EXISTS release_ready_receipts (
                release_key TEXT PRIMARY KEY,
                execution_key TEXT NOT NULL UNIQUE REFERENCES execution_outbox(idempotency_key),
                authority_key TEXT NOT NULL UNIQUE REFERENCES release_authority_receipts(authority_key),
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS merge_authorization_receipts (
                merge_key TEXT PRIMARY KEY,
                execution_key TEXT NOT NULL UNIQUE REFERENCES execution_outbox(idempotency_key),
                authority_key TEXT NOT NULL UNIQUE REFERENCES release_authority_receipts(authority_key),
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS merge_result_receipts (
                merge_result_key TEXT PRIMARY KEY,
                execution_key TEXT NOT NULL UNIQUE REFERENCES execution_outbox(idempotency_key),
                authority_key TEXT NOT NULL UNIQUE REFERENCES release_authority_receipts(authority_key),
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS deployment_authorization_receipts (
                deployment_key TEXT PRIMARY KEY,
                execution_key TEXT NOT NULL UNIQUE REFERENCES execution_outbox(idempotency_key),
                authority_key TEXT NOT NULL UNIQUE REFERENCES release_authority_receipts(authority_key),
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS release_identity_no_update
            BEFORE UPDATE ON release_identity
            BEGIN SELECT RAISE(ABORT, 'release identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS release_identity_no_delete
            BEFORE DELETE ON release_identity
            BEGIN SELECT RAISE(ABORT, 'release identity is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS release_authority_no_update
            BEFORE UPDATE ON release_authority_receipts
            BEGIN SELECT RAISE(ABORT, 'release authority receipt is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS release_authority_no_delete
            BEFORE DELETE ON release_authority_receipts
            BEGIN SELECT RAISE(ABORT, 'release authority receipt is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS release_ready_no_update
            BEFORE UPDATE ON release_ready_receipts
            BEGIN SELECT RAISE(ABORT, 'release-ready receipt is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS release_ready_no_delete
            BEFORE DELETE ON release_ready_receipts
            BEGIN SELECT RAISE(ABORT, 'release-ready receipt is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS merge_authorization_no_update
            BEFORE UPDATE ON merge_authorization_receipts
            BEGIN SELECT RAISE(ABORT, 'merge authorization receipt is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS merge_authorization_no_delete
            BEFORE DELETE ON merge_authorization_receipts
            BEGIN SELECT RAISE(ABORT, 'merge authorization receipt is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS merge_result_no_update
            BEFORE UPDATE ON merge_result_receipts
            BEGIN SELECT RAISE(ABORT, 'merge result receipt is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS merge_result_no_delete
            BEFORE DELETE ON merge_result_receipts
            BEGIN SELECT RAISE(ABORT, 'merge result receipt is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS deployment_authorization_no_update
            BEFORE UPDATE ON deployment_authorization_receipts
            BEGIN SELECT RAISE(ABORT, 'deployment authorization receipt is immutable'); END;

            CREATE TRIGGER IF NOT EXISTS deployment_authorization_no_delete
            BEFORE DELETE ON deployment_authorization_receipts
            BEGIN SELECT RAISE(ABORT, 'deployment authorization receipt is append-only'); END;
            """
        )
        with controller._write_txn(conn):
            identity = conn.execute(
                "SELECT controller_id, authority_policy_json FROM release_identity "
                "WHERE singleton = 1"
            ).fetchone()
            if identity is None:
                if authority_verifiers is None:
                    raise ReleaseBoundaryError(
                        "RELEASE_AUTHORITY_POLICY_REQUIRED",
                        "trusted authority policy is required for release bootstrap",
                    )
                policy_json = _canonical_authority_policy(authority_verifiers)
                if _policy_sha256(policy_json) != external_policy_sha256:
                    raise ReleaseBoundaryError(
                        "RELEASE_AUTHORITY_POLICY_PIN_MISMATCH",
                        "release authority policy does not match application-startup pin",
                    )
                conn.execute(
                    "INSERT INTO release_identity "
                    "(singleton, controller_id, authority_policy_json, created_at) "
                    "VALUES (1, ?, ?, ?)",
                    (RELEASE_CONTROLLER_ID, policy_json, controller._now()),
                )
            elif authority_verifiers is not None and identity[
                "authority_policy_json"
            ] != _canonical_authority_policy(authority_verifiers):
                raise ReleaseBoundaryError(
                    "RELEASE_AUTHORITY_POLICY_MISMATCH",
                    "release authority policy differs from immutable bootstrap",
                )
        identity = conn.execute(
            "SELECT controller_id, authority_policy_json FROM release_identity "
            "WHERE singleton = 1"
        ).fetchone()
        if identity is None or identity["controller_id"] != RELEASE_CONTROLLER_ID:
            raise ReleaseBoundaryError(
                "RELEASE_IDENTITY_MISMATCH",
                "release database identity does not match this implementation",
            )
        if _policy_sha256(identity["authority_policy_json"]) != external_policy_sha256:
            raise ReleaseBoundaryError(
                "RELEASE_AUTHORITY_POLICY_PIN_MISMATCH",
                "persisted release authority policy does not match application-startup pin",
            )
    finally:
        conn.close()
    return path


def _pinned_verifier(
    stage: str, db_path: Optional[str | os.PathLike[str]]
) -> Mapping[str, Any]:
    conn = controller.connect(db_path)
    try:
        identity = conn.execute(
            "SELECT authority_policy_json FROM release_identity WHERE singleton = 1"
        ).fetchone()
    finally:
        conn.close()
    if identity is None:
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_POLICY_REQUIRED",
            "release authority policy has not been bootstrapped",
        )
    if _policy_sha256(identity["authority_policy_json"]) != _external_policy_pin():
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_POLICY_PIN_MISMATCH",
            "persisted release authority policy does not match application-startup pin",
        )
    try:
        policy = json.loads(identity["authority_policy_json"])
        if _canonical_authority_policy(policy) != identity["authority_policy_json"]:
            raise ValueError("non-canonical authority policy")
        return policy[stage]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_POLICY_INVALID",
            "persisted release authority policy is invalid",
        ) from exc


def _load_signed_authority(
    *,
    authority_key: str,
    execution_key: str,
    decision: str,
    schema: str,
    expected_keys: set[str],
    db_path: Optional[str | os.PathLike[str]],
) -> dict[str, Any]:
    authority_verifier = _pinned_verifier(decision, db_path)
    try:
        public_key = execution._authority_public_key(authority_verifier)
    except execution.ExecutionError as exc:
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_VERIFIER_INVALID",
            "release authority verifier is invalid",
        ) from exc
    conn = controller.connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM release_authority_receipts WHERE authority_key = ?",
            (authority_key,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ReleaseBoundaryError(
            "SIGNED_RELEASE_AUTHORITY_REQUIRED",
            "signed release authority was not found",
        )
    try:
        envelope = json.loads(row["payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_INVALID", "release authority receipt is malformed"
        ) from exc
    common = {
        "schema",
        "authority_key",
        "execution_key",
        "decision",
        "issuer",
        "key_id",
        "signature_b64",
    }
    if not isinstance(envelope, dict) or set(envelope) != common | expected_keys:
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_INVALID",
            "release authority receipt has missing or unknown fields",
        )
    if (
        envelope["schema"] != schema
        or envelope["authority_key"] != authority_key
        or envelope["execution_key"] != execution_key
        or envelope["decision"] != decision
        or envelope["issuer"] != authority_verifier.get("issuer")
        or envelope["key_id"] != authority_verifier.get("key_id")
        or row["execution_key"] != execution_key
        or row["decision"] != decision
        or row["payload_json"] != execution._canonical(envelope)
    ):
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_INVALID",
            "release authority identity or custody is invalid",
        )
    unsigned = {key: value for key, value in envelope.items() if key != "signature_b64"}
    try:
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
        if base64.b64encode(signature).decode("ascii") != envelope["signature_b64"]:
            raise ValueError("non-canonical signature")
        public_key.verify(signature, execution._signed_bytes(unsigned))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ReleaseBoundaryError(
            "RELEASE_AUTHORITY_SIGNATURE_INVALID",
            "release authority signature is invalid",
        ) from exc
    return envelope


def _load_receipt(
    *,
    table: str,
    key_column: str,
    key: str,
    missing_code: str,
    db_path: Optional[str | os.PathLike[str]],
) -> tuple[dict[str, Any], str]:
    allowed = {
        ("release_ready_receipts", "release_key"),
        ("merge_authorization_receipts", "merge_key"),
        ("merge_result_receipts", "merge_result_key"),
    }
    if (table, key_column) not in allowed:
        raise AssertionError("unapproved receipt table")
    conn = controller.connect(db_path)
    try:
        row = conn.execute(
            f"SELECT payload_json, authority_key FROM {table} WHERE {key_column} = ?",
            (key,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ReleaseBoundaryError(
            missing_code, "required predecessor receipt was not found"
        )
    try:
        return json.loads(row["payload_json"]), row["authority_key"]
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReleaseBoundaryError(
            "RELEASE_RECEIPT_INVALID", "predecessor receipt is malformed"
        ) from exc


def _store_receipt(
    *,
    table: str,
    key_column: str,
    key: str,
    execution_key: str,
    authority_key: str,
    receipt: Mapping[str, Any],
    conflict_code: str,
    db_path: Optional[str | os.PathLike[str]],
) -> dict[str, Any]:
    allowed = {
        ("release_ready_receipts", "release_key"),
        ("merge_authorization_receipts", "merge_key"),
        ("merge_result_receipts", "merge_result_key"),
        ("deployment_authorization_receipts", "deployment_key"),
    }
    if (table, key_column) not in allowed:
        raise AssertionError("unapproved receipt table")
    canonical = execution._canonical(receipt)
    conn = controller.connect(db_path)
    try:
        with controller._write_txn(conn):
            existing = conn.execute(
                f"SELECT payload_json FROM {table} WHERE {key_column} = ?", (key,)
            ).fetchone()
            if existing is not None:
                if existing["payload_json"] != canonical:
                    raise ReleaseBoundaryError(
                        conflict_code, "existing receipt has different immutable bytes"
                    )
                return {**receipt, "replayed": True}
            try:
                conn.execute(
                    f"INSERT INTO {table} "
                    f"({key_column}, execution_key, authority_key, payload_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (key, execution_key, authority_key, canonical, controller._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise ReleaseBoundaryError(
                    conflict_code, "receipt conflicts with existing immutable custody"
                ) from exc
        return {**receipt, "replayed": False}
    finally:
        conn.close()


def _is_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is not None
    )


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validated_completion_sha256(
    execution_key: str,
    *,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> tuple[str, dict[str, Any]]:
    try:
        completion = execution.record_execution_completion(
            execution_key,
            board=board,
            authority_verifier=_pinned_verifier(EXECUTION_POLICY_KEY, db_path),
            db_path=db_path,
            kanban_db_path=kanban_db_path,
        )
    except execution.ExecutionError as exc:
        raise ReleaseBoundaryError(
            "EXECUTION_COMPLETION_INVALID",
            "execution completion failed exact custody revalidation",
        ) from exc
    completion.pop("replayed", None)
    return execution._digest(completion), completion


def record_release_ready(
    execution_key: str,
    *,
    authority_key: str,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Record exact release-readiness evidence without granting merge authority."""
    init_release_schema(db_path)
    completion_sha256, completion = _validated_completion_sha256(
        execution_key,
        board=board,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
    )
    authority = _load_signed_authority(
        authority_key=authority_key,
        execution_key=execution_key,
        decision=RELEASE_READY_DECISION,
        schema=RELEASE_READY_AUTH_SCHEMA,
        expected_keys={
            "completion_sha256",
            "repository",
            "base_ref",
            "head_sha",
            "evidence_sha256",
        },
        db_path=db_path,
    )
    source_candidate = completion.get("source_candidate")
    if (
        authority["completion_sha256"] != completion_sha256
        or not isinstance(authority["repository"], str)
        or authority["repository"].count("/") != 1
        or not isinstance(authority["base_ref"], str)
        or not authority["base_ref"]
        or not _is_sha(authority["head_sha"])
        or not _is_digest(authority["evidence_sha256"])
        or not isinstance(source_candidate, dict)
        or authority["repository"].lower() != source_candidate.get("repository")
        or authority["head_sha"].lower() != source_candidate.get("commit_sha")
    ):
        raise ReleaseBoundaryError(
            "RELEASE_READY_EVIDENCE_INVALID",
            "release-ready authority does not bind exact completion and candidate evidence",
        )
    release_key = f"{execution_key}:release-ready"
    receipt = {
        "schema": RELEASE_CONTROLLER_ID,
        "release_key": release_key,
        "execution_key": execution_key,
        "completion_sha256": completion_sha256,
        "repository": authority["repository"],
        "base_ref": authority["base_ref"],
        "head_sha": authority["head_sha"],
        "evidence_sha256": authority["evidence_sha256"],
        "authorization_sha256": execution._digest(authority),
        "status": RELEASE_READY_STATUS,
        "boundary": "release-ready evidence only; no merge, deploy, or live authority",
    }
    return _store_receipt(
        table="release_ready_receipts",
        key_column="release_key",
        key=release_key,
        execution_key=execution_key,
        authority_key=authority_key,
        receipt=receipt,
        conflict_code="RELEASE_READY_CONFLICT",
        db_path=db_path,
    )


def _validated_release_ready(
    execution_key: str,
    *,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    release_key = f"{execution_key}:release-ready"
    ready, authority_key = _load_receipt(
        table="release_ready_receipts",
        key_column="release_key",
        key=release_key,
        missing_code="RELEASE_READY_REQUIRED",
        db_path=db_path,
    )
    authority = _load_signed_authority(
        authority_key=authority_key,
        execution_key=execution_key,
        decision=RELEASE_READY_DECISION,
        schema=RELEASE_READY_AUTH_SCHEMA,
        expected_keys={
            "completion_sha256",
            "repository",
            "base_ref",
            "head_sha",
            "evidence_sha256",
        },
        db_path=db_path,
    )
    completion_sha256, completion = _validated_completion_sha256(
        execution_key,
        board=board,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
    )
    source_candidate = completion.get("source_candidate")
    if (
        authority["completion_sha256"] != completion_sha256
        or not isinstance(authority["repository"], str)
        or authority["repository"].count("/") != 1
        or not isinstance(authority["base_ref"], str)
        or not authority["base_ref"]
        or not _is_sha(authority["head_sha"])
        or not _is_digest(authority["evidence_sha256"])
        or not isinstance(source_candidate, dict)
        or authority["repository"].lower() != source_candidate.get("repository")
        or authority["head_sha"].lower() != source_candidate.get("commit_sha")
    ):
        raise ReleaseBoundaryError(
            "RELEASE_READY_EVIDENCE_INVALID",
            "release-ready authority has invalid candidate evidence",
        )
    expected = {
        "schema": RELEASE_CONTROLLER_ID,
        "release_key": release_key,
        "execution_key": execution_key,
        "completion_sha256": authority["completion_sha256"],
        "repository": authority["repository"],
        "base_ref": authority["base_ref"],
        "head_sha": authority["head_sha"],
        "evidence_sha256": authority["evidence_sha256"],
        "authorization_sha256": execution._digest(authority),
        "status": RELEASE_READY_STATUS,
        "boundary": "release-ready evidence only; no merge, deploy, or live authority",
    }
    if execution._canonical(ready) != execution._canonical(expected):
        raise ReleaseBoundaryError(
            "RELEASE_READY_RECEIPT_INVALID",
            "release-ready receipt does not match signed authority",
        )
    return ready


def _validated_merge_authorization(
    execution_key: str,
    *,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    ready = _validated_release_ready(
        execution_key,
        board=board,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
    )
    merge_key = f"{execution_key}:merge"
    merge, authority_key = _load_receipt(
        table="merge_authorization_receipts",
        key_column="merge_key",
        key=merge_key,
        missing_code="MERGE_AUTHORIZATION_REQUIRED",
        db_path=db_path,
    )
    authority = _load_signed_authority(
        authority_key=authority_key,
        execution_key=execution_key,
        decision=MERGE_DECISION,
        schema=MERGE_AUTH_SCHEMA,
        expected_keys={
            "release_key",
            "release_ready_sha256",
            "repository",
            "base_ref",
            "head_sha",
            "pull_request",
            "merge_method",
        },
        db_path=db_path,
    )
    if (
        authority["release_key"] != ready["release_key"]
        or authority["release_ready_sha256"] != execution._digest(ready)
        or authority["repository"] != ready["repository"]
        or authority["base_ref"] != ready["base_ref"]
        or authority["head_sha"] != ready["head_sha"]
        or not isinstance(authority["pull_request"], int)
        or isinstance(authority["pull_request"], bool)
        or authority["pull_request"] <= 0
        or authority["merge_method"] not in {"merge", "squash", "rebase"}
    ):
        raise ReleaseBoundaryError(
            "MERGE_AUTHORITY_SCOPE_INVALID",
            "merge authority does not bind the exact release-ready candidate",
        )
    expected = {
        "schema": RELEASE_CONTROLLER_ID,
        "merge_key": merge_key,
        "execution_key": execution_key,
        "release_key": ready["release_key"],
        "release_ready_sha256": execution._digest(ready),
        "repository": ready["repository"],
        "base_ref": ready["base_ref"],
        "head_sha": ready["head_sha"],
        "pull_request": authority["pull_request"],
        "merge_method": authority["merge_method"],
        "authorization_sha256": execution._digest(authority),
        "status": MERGE_AUTH_STATUS,
        "boundary": (
            "inert merge-authorization custody only; no executable authority; "
            "future actuator must atomically revalidate board completion"
        ),
    }
    if execution._canonical(merge) != execution._canonical(expected):
        raise ReleaseBoundaryError(
            "MERGE_AUTHORIZATION_RECEIPT_INVALID",
            "merge authorization receipt does not match signed authority",
        )
    return merge


def _validated_merge_result(
    execution_key: str,
    *,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    merge = _validated_merge_authorization(
        execution_key,
        board=board,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
    )
    merge_result_key = f"{execution_key}:merge-result"
    merge_result, authority_key = _load_receipt(
        table="merge_result_receipts",
        key_column="merge_result_key",
        key=merge_result_key,
        missing_code="MERGE_RESULT_REQUIRED",
        db_path=db_path,
    )
    authority = _load_signed_authority(
        authority_key=authority_key,
        execution_key=execution_key,
        decision=MERGE_RESULT_DECISION,
        schema=MERGE_RESULT_SCHEMA,
        expected_keys={
            "merge_key",
            "merge_authorization_sha256",
            "repository",
            "base_ref",
            "head_sha",
            "pull_request",
            "merge_method",
            "merge_commit_sha",
            "result",
        },
        db_path=db_path,
    )
    exact = {
        "repository": merge["repository"],
        "base_ref": merge["base_ref"],
        "head_sha": merge["head_sha"],
        "pull_request": merge["pull_request"],
        "merge_method": merge["merge_method"],
    }
    if (
        authority["merge_key"] != merge["merge_key"]
        or authority["merge_authorization_sha256"] != execution._digest(merge)
        or any(authority[key] != value for key, value in exact.items())
        or not _is_sha(authority["merge_commit_sha"])
        or authority["result"] != "MERGED"
    ):
        raise ReleaseBoundaryError(
            "MERGE_RESULT_INVALID",
            "merge result does not prove the exact authorized merge",
        )
    expected = {
        "schema": RELEASE_CONTROLLER_ID,
        "merge_result_key": merge_result_key,
        "execution_key": execution_key,
        "merge_key": merge["merge_key"],
        "merge_authorization_sha256": execution._digest(merge),
        "repository": merge["repository"],
        "base_ref": merge["base_ref"],
        "head_sha": merge["head_sha"],
        "pull_request": merge["pull_request"],
        "merge_method": merge["merge_method"],
        "merge_commit_sha": authority["merge_commit_sha"],
        "authorization_sha256": execution._digest(authority),
        "status": MERGE_RESULT_STATUS,
        "boundary": "merge result recorded; no deployment or live authority",
    }
    if execution._canonical(merge_result) != execution._canonical(expected):
        raise ReleaseBoundaryError(
            "MERGE_RESULT_RECEIPT_INVALID",
            "merge result receipt does not match signed attestation",
        )
    return merge_result


def record_merge_authorization(
    execution_key: str,
    *,
    authority_key: str,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Record exact merge authority without performing or implying deployment."""
    init_release_schema(db_path)
    release_key = f"{execution_key}:release-ready"
    ready = _validated_release_ready(
        execution_key,
        board=board,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
    )
    authority = _load_signed_authority(
        authority_key=authority_key,
        execution_key=execution_key,
        decision=MERGE_DECISION,
        schema=MERGE_AUTH_SCHEMA,
        expected_keys={
            "release_key",
            "release_ready_sha256",
            "repository",
            "base_ref",
            "head_sha",
            "pull_request",
            "merge_method",
        },
        db_path=db_path,
    )
    if (
        authority["release_key"] != release_key
        or authority["release_ready_sha256"] != execution._digest(ready)
        or authority["repository"] != ready["repository"]
        or authority["base_ref"] != ready["base_ref"]
        or authority["head_sha"] != ready["head_sha"]
        or not isinstance(authority["pull_request"], int)
        or isinstance(authority["pull_request"], bool)
        or authority["pull_request"] <= 0
        or authority["merge_method"] not in {"merge", "squash", "rebase"}
    ):
        raise ReleaseBoundaryError(
            "MERGE_AUTHORITY_SCOPE_INVALID",
            "merge authority does not bind the exact release-ready candidate",
        )
    merge_key = f"{execution_key}:merge"
    receipt = {
        "schema": RELEASE_CONTROLLER_ID,
        "merge_key": merge_key,
        "execution_key": execution_key,
        "release_key": release_key,
        "release_ready_sha256": execution._digest(ready),
        "repository": ready["repository"],
        "base_ref": ready["base_ref"],
        "head_sha": ready["head_sha"],
        "pull_request": authority["pull_request"],
        "merge_method": authority["merge_method"],
        "authorization_sha256": execution._digest(authority),
        "status": MERGE_AUTH_STATUS,
        "boundary": (
            "inert merge-authorization custody only; no executable authority; "
            "future actuator must atomically revalidate board completion"
        ),
    }
    return _store_receipt(
        table="merge_authorization_receipts",
        key_column="merge_key",
        key=merge_key,
        execution_key=execution_key,
        authority_key=authority_key,
        receipt=receipt,
        conflict_code="MERGE_AUTHORIZATION_CONFLICT",
        db_path=db_path,
    )


def record_merge_result(
    execution_key: str,
    *,
    authority_key: str,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Record an external exact-merge result; this function performs no merge."""
    init_release_schema(db_path)
    merge_key = f"{execution_key}:merge"
    merge = _validated_merge_authorization(
        execution_key,
        board=board,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
    )
    authority = _load_signed_authority(
        authority_key=authority_key,
        execution_key=execution_key,
        decision=MERGE_RESULT_DECISION,
        schema=MERGE_RESULT_SCHEMA,
        expected_keys={
            "merge_key",
            "merge_authorization_sha256",
            "repository",
            "base_ref",
            "head_sha",
            "pull_request",
            "merge_method",
            "merge_commit_sha",
            "result",
        },
        db_path=db_path,
    )
    exact = {
        "repository": merge["repository"],
        "base_ref": merge["base_ref"],
        "head_sha": merge["head_sha"],
        "pull_request": merge["pull_request"],
        "merge_method": merge["merge_method"],
    }
    if (
        authority["merge_key"] != merge_key
        or authority["merge_authorization_sha256"] != execution._digest(merge)
        or any(authority[key] != value for key, value in exact.items())
        or not _is_sha(authority["merge_commit_sha"])
        or authority["result"] != "MERGED"
    ):
        raise ReleaseBoundaryError(
            "MERGE_RESULT_INVALID",
            "merge result does not prove the exact authorized merge",
        )
    merge_result_key = f"{execution_key}:merge-result"
    receipt = {
        "schema": RELEASE_CONTROLLER_ID,
        "merge_result_key": merge_result_key,
        "execution_key": execution_key,
        "merge_key": merge_key,
        "merge_authorization_sha256": execution._digest(merge),
        **exact,
        "merge_commit_sha": authority["merge_commit_sha"],
        "authorization_sha256": execution._digest(authority),
        "status": MERGE_RESULT_STATUS,
        "boundary": "merge result recorded; no deployment or live authority",
    }
    return _store_receipt(
        table="merge_result_receipts",
        key_column="merge_result_key",
        key=merge_result_key,
        execution_key=execution_key,
        authority_key=authority_key,
        receipt=receipt,
        conflict_code="MERGE_RESULT_CONFLICT",
        db_path=db_path,
    )


def record_deployment_authorization(
    execution_key: str,
    *,
    authority_key: str,
    board: str,
    db_path: Optional[str | os.PathLike[str]],
    kanban_db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Record exact deployment authority; perform no deployment or live enablement."""
    init_release_schema(db_path)
    merge_result_key = f"{execution_key}:merge-result"
    merge_result = _validated_merge_result(
        execution_key,
        board=board,
        db_path=db_path,
        kanban_db_path=kanban_db_path,
    )
    authority = _load_signed_authority(
        authority_key=authority_key,
        execution_key=execution_key,
        decision=DEPLOY_DECISION,
        schema=DEPLOY_AUTH_SCHEMA,
        expected_keys={
            "merge_result_key",
            "merge_result_sha256",
            "merge_commit_sha",
            "artifact_sha256",
            "environment",
            "deployment_target",
        },
        db_path=db_path,
    )
    if (
        authority["merge_result_key"] != merge_result_key
        or authority["merge_result_sha256"] != execution._digest(merge_result)
        or authority["merge_commit_sha"] != merge_result["merge_commit_sha"]
        or not _is_digest(authority["artifact_sha256"])
        or not isinstance(authority["environment"], str)
        or not authority["environment"]
        or not isinstance(authority["deployment_target"], str)
        or not authority["deployment_target"]
    ):
        raise ReleaseBoundaryError(
            "DEPLOYMENT_AUTHORITY_SCOPE_INVALID",
            "deployment authority does not bind the exact merged artifact and target",
        )
    deployment_key = f"{execution_key}:deployment"
    receipt = {
        "schema": RELEASE_CONTROLLER_ID,
        "deployment_key": deployment_key,
        "execution_key": execution_key,
        "merge_result_key": merge_result_key,
        "merge_result_sha256": execution._digest(merge_result),
        "merge_commit_sha": merge_result["merge_commit_sha"],
        "artifact_sha256": authority["artifact_sha256"],
        "environment": authority["environment"],
        "deployment_target": authority["deployment_target"],
        "authorization_sha256": execution._digest(authority),
        "status": DEPLOY_AUTH_STATUS,
        "boundary": (
            "inert deployment-authorization custody only; no executable or live authority; "
            "future actuator must atomically revalidate board completion"
        ),
    }
    return _store_receipt(
        table="deployment_authorization_receipts",
        key_column="deployment_key",
        key=deployment_key,
        execution_key=execution_key,
        authority_key=authority_key,
        receipt=receipt,
        conflict_code="DEPLOYMENT_AUTHORIZATION_CONFLICT",
        db_path=db_path,
    )
