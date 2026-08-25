"""Authenticated dashboard API for the verified-pipeline decision connector."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from hermes_cli import kanban_db
from hermes_cli.dashboard_auth.base import Session
from hermes_cli.profiles import get_profile_dir
from hermes_cli.role_contract import load_role_contract
from plugins.verified_pipeline import controller, review, validators


router = APIRouter()


class IntakeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    specification_id: str = Field(min_length=1, max_length=128)
    revision: int = Field(ge=1)
    artifact_text: str = Field(min_length=1, max_length=controller.MAX_ARTIFACT_BYTES)
    board: Optional[str] = Field(default=None, max_length=64)


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    action: str
    decision_nonce: str = Field(min_length=16, max_length=256)
    artifact_sha256: str = Field(min_length=64, max_length=64)
    feedback: Optional[str] = Field(default=None, max_length=65536)


def _error_status(code: str) -> int:
    if code in {"INTAKE_NOT_FOUND", "OUTBOX_NOT_FOUND", "DECISION_NOT_FOUND"}:
        return 404
    if code.startswith("INVALID_") or code == "FEEDBACK_REQUIRED":
        return 400
    return 409


def _raise_control(exc: controller.PipelineControlError) -> None:
    raise HTTPException(
        status_code=_error_status(exc.code),
        detail={"code": exc.code, "message": exc.message},
    ) from exc


def _authenticated_actor(request: Request) -> str:
    """Return the verified interactive dashboard principal or fail closed."""
    session = getattr(request.state, "session", None)
    if not isinstance(session, Session):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "AUTHENTICATED_HUMAN_REQUIRED",
                "message": "pipeline decisions require a verified host dashboard session",
            },
        )
    provider = str(getattr(session, "provider", "")).strip()
    user_id = str(getattr(session, "user_id", "")).strip()
    if not provider or not user_id:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "AUTHENTICATED_HUMAN_REQUIRED",
                "message": "pipeline decisions require a verified interactive dashboard session",
            },
        )
    if len(provider) > 128 or len(user_id) > 256:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "AUTHENTICATED_HUMAN_REQUIRED",
                "message": "verified dashboard identity is malformed",
            },
        )
    return f"dashboard-session:{provider}:{user_id}"


def _frozen_profile_inventory() -> dict[str, dict[str, Any]]:
    receipts: dict[str, dict[str, Any]] = {}
    for profile in (
        controller.PLANNER_PROFILE,
        review.DA_PROFILE,
        review.CEO_PROFILE,
        *controller.MANDATORY_IMPLEMENTATION_PROFILES,
    ):
        contract = load_role_contract(get_profile_dir(profile), profile, required=True)
        assert contract is not None
        receipts[profile] = {
            "schema": contract.schema,
            "version": contract.version,
            "sha256": contract.sha256,
            "allowed_toolsets": list(contract.allowed_toolsets),
            "allowed_tools": list(contract.allowed_tools),
            "workspace_only": contract.workspace_only,
        }
    for profile in (
        controller.REVISION_PROFILE,
        *controller.OPTIONAL_IMPLEMENTATION_PROFILES,
    ):
        contract = load_role_contract(get_profile_dir(profile), profile, required=False)
        if contract is None:
            continue
        receipts[profile] = {
            "schema": contract.schema,
            "version": contract.version,
            "sha256": contract.sha256,
            "allowed_toolsets": list(contract.allowed_toolsets),
            "allowed_tools": list(contract.allowed_tools),
            "workspace_only": contract.workspace_only,
        }
    return receipts


def _normalize_board(board: Optional[str]) -> str:
    if not board:
        board = kanban_db.get_current_board()
    try:
        normalized = kanban_db._normalize_board_slug(board)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_BOARD", "message": str(exc)},
        ) from exc
    if normalized != kanban_db.DEFAULT_BOARD and not kanban_db.board_exists(normalized):
        raise HTTPException(
            status_code=404,
            detail={"code": "BOARD_NOT_FOUND", "message": "Kanban board was not found"},
        )
    return normalized


@router.get("/health")
def health() -> dict[str, Any]:
    try:
        path = controller.init_db()
    except controller.PipelineControlError as exc:
        _raise_control(exc)
    return {
        "ok": True,
        "schema": controller.CONTROLLER_ID,
        "db": str(path),
        "planner_profile": controller.PLANNER_PROFILE,
        "revision_profile": controller.REVISION_PROFILE,
        "da_profile": review.DA_PROFILE,
        "ceo_profile": review.CEO_PROFILE,
    }


@router.post("/intakes")
def create_intake(body: IntakeRequest) -> dict[str, Any]:
    normalized_board = _normalize_board(body.board)
    try:
        frozen_profiles = _frozen_profile_inventory()
    except Exception as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "PROFILE_FREEZE_FAILED",
                "message": "required role contracts could not be frozen",
            },
        ) from exc
    try:
        return controller.register_intake(
            specification_id=body.specification_id,
            revision=body.revision,
            artifact_bytes=body.artifact_text.encode("utf-8"),
            frozen_profiles=frozen_profiles,
            authority_ceiling=[
                "plan",
                "adversarial_review",
                "strategic_review",
                *(
                    ["revise_specification"]
                    if controller.REVISION_PROFILE in frozen_profiles
                    else []
                ),
            ],
            board=normalized_board,
        )
    except controller.PipelineControlError as exc:
        _raise_control(exc)


@router.get("/intakes/{run_id}")
def read_intake(run_id: str) -> dict[str, Any]:
    try:
        result = controller.get_intake(run_id, include_artifact=True)
    except controller.PipelineControlError as exc:
        _raise_control(exc)
    artifact_bytes = result.pop("artifact_bytes")
    result["artifact_text"] = artifact_bytes.decode("utf-8", errors="strict")
    return result


@router.post("/intakes/{run_id}/decision")
def decide(run_id: str, body: DecisionRequest, request: Request) -> dict[str, Any]:
    try:
        decision = controller.record_decision(
            run_id=run_id,
            request_id=body.request_id,
            action=body.action,
            actor=_authenticated_actor(request),
            decision_nonce=body.decision_nonce,
            artifact_sha256=body.artifact_sha256,
            feedback=body.feedback,
        )
        projection = controller.project_outbox(decision["idempotency_key"])
        return {"decision": decision, "projection": projection}
    except controller.PipelineControlError as exc:
        _raise_control(exc)


@router.post("/intakes/{run_id}/reconcile")
def reconcile(run_id: str) -> dict[str, Any]:
    """Retry only the outbox projection for an already committed decision."""
    try:
        return {"projection": controller.project_run(run_id)}
    except controller.PipelineControlError as exc:
        _raise_control(exc)


@router.post("/intakes/{run_id}/review/reconcile")
def reconcile_review(run_id: str) -> dict[str, Any]:
    """Advance only admitted terminal Planner, DA, and CEO review stages."""
    try:
        return review.reconcile_review_once(run_id)
    except controller.PipelineControlError as exc:
        _raise_control(exc)
    except review.ReviewCoordinationError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    except validators.ArtifactValidationError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "REVIEW_ARTIFACT_INVALID", "message": str(exc)},
        ) from exc
