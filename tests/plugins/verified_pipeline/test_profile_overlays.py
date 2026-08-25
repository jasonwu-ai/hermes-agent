from __future__ import annotations

from pathlib import Path

import yaml

from hermes_cli.role_contract import load_role_contract
from plugins.verified_pipeline import controller, review, validators


ROOT = Path(__file__).parents[3]
OVERLAYS = ROOT / "plugins" / "verified_pipeline" / "profile_overlays"


def _skill_frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    _, frontmatter, _ = text.split("---", 2)
    payload = yaml.safe_load(frontmatter)
    assert isinstance(payload, dict)
    return payload


def test_planner_overlay_matches_controller_packet_and_validator_schema() -> None:
    profile = controller.PLANNER_PROFILE
    contract = load_role_contract(OVERLAYS / profile, profile, required=True)
    assert contract is not None
    contract_text = contract.path.read_text(encoding="utf-8")
    assert "planner-request/v1" in contract_text
    assert validators.PLAN_SCHEMA in contract_text
    assert controller.PLANNER_SKILL in contract_text
    skill = OVERLAYS / profile / "skills" / controller.PLANNER_SKILL / "SKILL.md"
    assert _skill_frontmatter(skill)["name"] == controller.PLANNER_SKILL
    text = skill.read_text(encoding="utf-8")
    assert "planner-request/v1" in text
    assert validators.PLAN_SCHEMA in text
    assert "deterministic controller validates" in text
    assert "verified_pipeline_validators.py" not in text
    assert "terminal" not in contract.allowed_tools
    assert "execute_code" not in contract.allowed_tools


def test_da_overlay_matches_controller_packet_and_validator_schema() -> None:
    profile = review.DA_PROFILE
    contract = load_role_contract(OVERLAYS / profile, profile, required=True)
    assert contract is not None
    contract_text = contract.path.read_text(encoding="utf-8")
    assert validators.DA_REQUEST_SCHEMA in contract_text
    assert validators.LEGACY_DA_REQUEST_SCHEMA in contract_text
    assert validators.DA_VERDICT_SCHEMA in contract_text
    assert review.DA_SKILL in contract_text
    skill = OVERLAYS / profile / "skills" / review.DA_SKILL / "SKILL.md"
    assert _skill_frontmatter(skill)["name"] == review.DA_SKILL
    text = skill.read_text(encoding="utf-8")
    assert validators.DA_REQUEST_SCHEMA in text
    assert validators.LEGACY_DA_REQUEST_SCHEMA in text
    assert validators.DA_VERDICT_SCHEMA in text
    assert "deterministic controller validates" in text
    assert "score_base" in text
    assert "score_floor" in text
    assert "zero findings score exactly `score_base` for v2" in text
    assert "exactly 100 for legacy v1" in text
    assert "not a residual-risk score" in text
    assert "verified_pipeline_validators.py" not in text
    assert "terminal" not in contract.allowed_tools
    assert "execute_code" not in contract.allowed_tools


def test_ceo_overlay_matches_controller_packet_and_validator_schema() -> None:
    profile = review.CEO_PROFILE
    contract = load_role_contract(OVERLAYS / profile, profile, required=True)
    assert contract is not None
    contract_text = contract.path.read_text(encoding="utf-8")
    assert validators.CEO_REQUEST_SCHEMA in contract_text
    assert validators.CEO_DECISION_SCHEMA in contract_text
    assert review.CEO_SKILL in contract_text
    skill = OVERLAYS / profile / "skills" / review.CEO_SKILL / "SKILL.md"
    assert _skill_frontmatter(skill)["name"] == review.CEO_SKILL
    text = skill.read_text(encoding="utf-8")
    assert validators.CEO_REQUEST_SCHEMA in text
    assert validators.CEO_DECISION_SCHEMA in text
    assert "deterministic controller validates" in text
    assert "verified_pipeline_validators.py" not in text
    assert "terminal" not in contract.allowed_tools
    assert "execute_code" not in contract.allowed_tools


def test_governance_task_bodies_delegate_validation_to_controller() -> None:
    planner_payload = {
        "action": "approve",
        "run_id": "run_" + "a" * 24,
        "decision_id": "decision_" + "b" * 24,
        "specification_id": "spec-1",
        "revision": 1,
        "artifact_sha256": "c" * 64,
        "frozen_profiles": {},
        "authority_ceiling": ["plan"],
        "feedback": None,
    }
    bodies = [
        controller._task_body(planner_payload, Path("/tmp/specification.md")),
        review._task_body({"kind": "planner_revision"}),
        review._task_body({"kind": "da_review"}),
        review._task_body({"kind": "ceo_review"}),
    ]
    for body in bodies:
        assert "deterministic controller validates" in body
        assert "verified_pipeline_validators.py" not in body


def test_mandatory_implementation_inventory_overlays_are_admissible() -> None:
    expected_toolsets = {
        "02-builder": ("file", "kanban"),
        "09-test": ("file", "kanban"),
        "06-integration": ("file", "kanban"),
        "08-release": ("file", "kanban"),
    }
    assert set(expected_toolsets) == set(controller.MANDATORY_IMPLEMENTATION_PROFILES)
    for profile, toolsets in expected_toolsets.items():
        contract = load_role_contract(OVERLAYS / profile, profile, required=True)
        assert contract is not None
        assert contract.allowed_toolsets == toolsets
        assert contract.workspace_only is True
        assert contract.allowed_tools
        assert "terminal" not in contract.allowed_tools
        assert "process" not in contract.allowed_tools
        assert "execute_code" not in contract.allowed_tools
        assert set(contract.allowed_tools) <= {
            "read_file",
            "search_files",
            "write_file",
            "patch",
            "terminal",
            "process",
            "kanban_show",
            "kanban_attachments",
            "kanban_comment",
            "kanban_heartbeat",
            "kanban_complete",
            "kanban_block",
        }
        assert "git" in contract.path.read_text(encoding="utf-8").lower()
