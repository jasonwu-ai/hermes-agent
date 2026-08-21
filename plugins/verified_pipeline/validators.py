"""Self-contained typed validators for bounded plan, DA, and CEO review artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

PLAN_SCHEMA = "verified-plan/v1"
LEGACY_DA_REQUEST_SCHEMA = "da-request/v1"
CURRENT_DA_REQUEST_SCHEMA = "da-request/v2"
DA_REQUEST_SCHEMA = CURRENT_DA_REQUEST_SCHEMA
DA_VERDICT_SCHEMA = "da-verdict/v1"
CEO_REQUEST_SCHEMA = "ceo-request/v1"
CEO_DECISION_SCHEMA = "ceo-decision/v1"
MAX_REVIEW_ROUND = 3
GOVERNANCE_PROFILES = {
    "00-cos",
    "01-ceo",
    "07-planner",
    "11-devils-advocate",
}
WORKSPACE_KINDS = {"scratch", "dir", "worktree"}
CLASSIFICATIONS = {"blocking", "severe", "advisory"}
LINEAGES = {
    "prior_unresolved",
    "regression",
    "newly_discoverable",
    "advisory_improvement",
}
MATERIALITY_BASES = {
    "explicit_specification",
    "authority_invariant",
    "safety_invariant",
    "evidence_integrity",
    "feasibility",
    "lifecycle_custody",
    "advisory_improvement",
}
BLOCKING_BASES = MATERIALITY_BASES - {"lifecycle_custody", "advisory_improvement"}
LEGACY_RISK_POLICY_FIELDS = {
    "severe_risk_threshold",
    "blocking_penalty",
    "severe_penalty",
    "advisory_penalty",
}
DEFAULT_RISK_POLICY = {
    "score_base": 100,
    "score_floor": 0,
    "severe_risk_threshold": 12,
    "blocking_penalty": 35,
    "severe_penalty": 15,
    "advisory_penalty": 2,
}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ArtifactValidationError(ValueError):
    """Raised when a task-local review artifact violates its typed contract."""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ArtifactValidationError(f"{field} must be a non-empty string")
    return value.strip()


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _sha256(value: Any, field: str) -> str:
    value = _text(value, field).lower()
    if not _SHA256_RE.fullmatch(value):
        raise ArtifactValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _round(value: Any, field: str = "plan_revision") -> int:
    if type(value) is not int or not 1 <= value <= MAX_REVIEW_ROUND:
        raise ArtifactValidationError(f"{field} must be an integer in 1..3")
    return value


def _string_list(value: Any, field: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ArtifactValidationError(f"{field} must be an array")
    if nonempty and not value:
        raise ArtifactValidationError(f"{field} must not be empty")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ArtifactValidationError(f"{field} entries must be non-empty strings")
    return value


def validate_plan_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ArtifactValidationError("Planner request must be an object")
    required = {
        "schema",
        "run_id",
        "specification_id",
        "specification_sha256",
        "plan_revision",
        "output_workspace",
        "prior_findings",
    }
    if set(request) != required:
        raise ArtifactValidationError(
            f"Planner request fields must be exactly {sorted(required)}"
        )
    if request["schema"] != "planner-request/v1":
        raise ArtifactValidationError("Planner request schema must be planner-request/v1")
    for field in ("run_id", "specification_id", "output_workspace"):
        _text(request[field], field)
    _sha256(request["specification_sha256"], "specification_sha256")
    _round(request["plan_revision"])
    prior = request["prior_findings"]
    if prior != "none" and not isinstance(prior, list):
        raise ArtifactValidationError("prior_findings must be none or an array")
    return request


def validate_plan(plan: Any, *, request: Mapping[str, Any]) -> dict[str, Any]:
    validate_plan_request(dict(request))
    if not isinstance(plan, dict):
        raise ArtifactValidationError("plan must be an object")
    required = {
        "schema",
        "specification_id",
        "specification_sha256",
        "plan_revision",
        "title",
        "summary",
        "tasks",
        "final_task_id",
        "review_dispositions",
    }
    if set(plan) != required:
        raise ArtifactValidationError(f"plan fields must be exactly {sorted(required)}")
    if plan["schema"] != PLAN_SCHEMA:
        raise ArtifactValidationError(f"plan schema must be {PLAN_SCHEMA}")
    for field in ("specification_id", "title", "summary", "final_task_id"):
        _text(plan[field], field)
    if plan["specification_id"] != request["specification_id"]:
        raise ArtifactValidationError("plan specification_id does not match request")
    digest = _sha256(plan["specification_sha256"], "specification_sha256")
    if digest != request["specification_sha256"]:
        raise ArtifactValidationError("plan specification digest does not match request")
    revision = _round(plan["plan_revision"])
    if revision != request["plan_revision"]:
        raise ArtifactValidationError("plan revision does not match request")
    tasks = plan["tasks"]
    if not isinstance(tasks, list) or not tasks:
        raise ArtifactValidationError("tasks must be a non-empty array")
    task_fields = {
        "id",
        "title",
        "assignee",
        "goal",
        "dependencies",
        "deliverable",
        "acceptance_criteria",
        "workspace",
    }
    ids: list[str] = []
    dependencies: dict[str, list[str]] = {}
    for index, task in enumerate(tasks):
        if not isinstance(task, dict) or set(task) != task_fields:
            raise ArtifactValidationError(
                f"tasks[{index}] fields must be exactly {sorted(task_fields)}"
            )
        for field in ("id", "title", "assignee", "goal", "deliverable"):
            value = _text(task[field], f"tasks[{index}].{field}")
            if field in {"id", "assignee"} and not _ID_RE.fullmatch(value):
                raise ArtifactValidationError(f"tasks[{index}].{field} is malformed")
        if task["assignee"] in GOVERNANCE_PROFILES:
            raise ArtifactValidationError(
                f"tasks[{index}].assignee cannot duplicate a governance stage"
            )
        if task["workspace"] not in WORKSPACE_KINDS:
            raise ArtifactValidationError(
                f"tasks[{index}].workspace must be one of {sorted(WORKSPACE_KINDS)}"
            )
        deps = _string_list(task["dependencies"], f"tasks[{index}].dependencies")
        _string_list(
            task["acceptance_criteria"],
            f"tasks[{index}].acceptance_criteria",
            nonempty=True,
        )
        task_id = task["id"]
        if task_id in dependencies:
            raise ArtifactValidationError(f"duplicate task id: {task_id}")
        ids.append(task_id)
        dependencies[task_id] = deps
    known = set(ids)
    if plan["final_task_id"] not in known:
        raise ArtifactValidationError("final_task_id does not name a task")
    for task_id, deps in dependencies.items():
        if task_id in deps:
            raise ArtifactValidationError(f"task {task_id} depends on itself")
        unknown = sorted(set(deps) - known)
        if unknown:
            raise ArtifactValidationError(
                f"task {task_id} has unknown dependencies: {unknown}"
            )
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise ArtifactValidationError("task dependencies contain a cycle")
        if task_id in visited:
            return
        visiting.add(task_id)
        for parent in dependencies[task_id]:
            visit(parent)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in ids:
        visit(task_id)
    dispositions = plan["review_dispositions"]
    if not isinstance(dispositions, list):
        raise ArtifactValidationError("review_dispositions must be an array")
    for index, item in enumerate(dispositions):
        if not isinstance(item, dict) or set(item) != {"finding_id", "disposition"}:
            raise ArtifactValidationError(
                f"review_dispositions[{index}] must contain finding_id and disposition"
            )
        _text(item["finding_id"], f"review_dispositions[{index}].finding_id")
        _text(item["disposition"], f"review_dispositions[{index}].disposition")
    prior = [] if request["prior_findings"] == "none" else request["prior_findings"]
    prior_ids = {
        finding.get("id")
        for finding in prior
        if isinstance(finding, dict) and _text(finding.get("id"), "prior finding id")
    }
    disposition_ids = {item["finding_id"] for item in dispositions}
    missing = sorted(prior_ids - disposition_ids)
    if revision > 1 and missing:
        raise ArtifactValidationError(
            f"missing dispositions for prior findings: {missing}"
        )
    return plan


def validate_da_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ArtifactValidationError("DA request must be an object")
    required = {
        "schema",
        "run_id",
        "specification_id",
        "specification",
        "specification_path",
        "specification_sha256",
        "plan_md",
        "plan",
        "plan_sha256",
        "plan_revision",
        "review_round",
        "prior_findings",
        "risk_policy",
        "minimum_standard",
        "output_workspace",
    }
    if set(request) != required:
        raise ArtifactValidationError(f"DA request fields must be exactly {sorted(required)}")
    if request["schema"] not in {
        LEGACY_DA_REQUEST_SCHEMA,
        CURRENT_DA_REQUEST_SCHEMA,
    }:
        raise ArtifactValidationError(
            "DA request schema must be "
            f"{LEGACY_DA_REQUEST_SCHEMA} or {CURRENT_DA_REQUEST_SCHEMA}"
        )
    for field in (
        "run_id",
        "specification_id",
        "specification",
        "specification_path",
        "plan_md",
        "minimum_standard",
        "output_workspace",
    ):
        _text(request[field], field)
    _sha256(request["specification_sha256"], "specification_sha256")
    _sha256(request["plan_sha256"], "plan_sha256")
    revision = _round(request["plan_revision"])
    if _round(request["review_round"], "review_round") != revision:
        raise ArtifactValidationError("plan_revision and review_round must match")
    plan_request = {
        "schema": "planner-request/v1",
        "run_id": request["run_id"],
        "specification_id": request["specification_id"],
        "specification_sha256": request["specification_sha256"],
        "plan_revision": revision,
        "output_workspace": str(Path(request["specification_path"]).parent),
        "prior_findings": request["prior_findings"],
    }
    validate_plan(request["plan"], request=plan_request)
    if _digest(_canonical(request["plan"])) != request["plan_sha256"]:
        raise ArtifactValidationError("plan digest does not match DA request")
    if _digest(request["specification"].encode("utf-8")) != request["specification_sha256"]:
        raise ArtifactValidationError("specification bytes do not match DA request")
    policy = request["risk_policy"]
    expected_policy_fields = (
        LEGACY_RISK_POLICY_FIELDS
        if request["schema"] == LEGACY_DA_REQUEST_SCHEMA
        else set(DEFAULT_RISK_POLICY)
    )
    if not isinstance(policy, dict) or set(policy) != expected_policy_fields:
        raise ArtifactValidationError("risk_policy fields are invalid")
    for key in expected_policy_fields:
        if type(policy[key]) is not int or policy[key] < 0:
            raise ArtifactValidationError(f"risk_policy.{key} must be non-negative")
    if (
        request["schema"] == CURRENT_DA_REQUEST_SCHEMA
        and policy["score_floor"] > policy["score_base"]
    ):
        raise ArtifactValidationError(
            "risk_policy.score_floor must not exceed score_base"
        )
    prior = request["prior_findings"]
    if prior != "none" and not isinstance(prior, list):
        raise ArtifactValidationError("prior_findings must be none or an array")
    return request


def calibrated_score(findings: list[dict[str, Any]], policy: Mapping[str, int]) -> int:
    score = policy.get("score_base", 100)
    penalties = {
        "blocking": policy["blocking_penalty"],
        "severe": policy["severe_penalty"],
        "advisory": policy["advisory_penalty"],
    }
    for finding in findings:
        if not finding.get("resolved", False):
            score -= penalties[finding["classification"]]
    return max(policy.get("score_floor", 0), score)


def validate_da_verdict(verdict: Any, *, request: Mapping[str, Any]) -> dict[str, Any]:
    validate_da_request(dict(request))
    if not isinstance(verdict, dict):
        raise ArtifactValidationError("DA verdict must be an object")
    required = {
        "schema",
        "specification_id",
        "plan_revision",
        "review_round",
        "verdict",
        "findings",
        "score",
        "most_likely_failure",
        "most_dangerous_failure",
        "cross_cutting_assumption",
        "escalate_to_jason",
        "decision_question",
    }
    if set(verdict) != required:
        raise ArtifactValidationError(f"DA verdict fields must be exactly {sorted(required)}")
    if verdict["schema"] != DA_VERDICT_SCHEMA:
        raise ArtifactValidationError(f"DA verdict schema must be {DA_VERDICT_SCHEMA}")
    if verdict["specification_id"] != request["specification_id"]:
        raise ArtifactValidationError("DA verdict specification does not match request")
    revision = _round(verdict["plan_revision"])
    if revision != request["plan_revision"] or verdict["review_round"] != revision:
        raise ArtifactValidationError("DA verdict revision does not match request")
    if verdict["verdict"] not in {"PASS", "REVISE"}:
        raise ArtifactValidationError("DA verdict must be PASS or REVISE")
    for field in (
        "most_likely_failure",
        "most_dangerous_failure",
        "cross_cutting_assumption",
    ):
        _text(verdict[field], field)
    findings = verdict["findings"]
    if not isinstance(findings, list):
        raise ArtifactValidationError("findings must be an array")
    finding_fields = {
        "id",
        "affected_task",
        "affected_criterion",
        "causal_sequence",
        "hidden_assumption",
        "early_warning",
        "likelihood",
        "impact",
        "mitigation",
        "classification",
        "exceeds_minimum_standard",
        "resolved",
        "lineage",
        "prior_finding_id",
        "novelty_justification",
        "confidence",
        "materiality_basis",
    }
    blockers = 0
    severe_above = 0
    prior_ids = set()
    if request["prior_findings"] != "none":
        prior_ids = {item.get("id") for item in request["prior_findings"]}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or set(finding) != finding_fields:
            raise ArtifactValidationError(
                f"findings[{index}] fields must be exactly {sorted(finding_fields)}"
            )
        for field in (
            "id",
            "affected_task",
            "affected_criterion",
            "causal_sequence",
            "hidden_assumption",
            "early_warning",
            "mitigation",
        ):
            _text(finding[field], f"findings[{index}].{field}")
        if finding["classification"] not in CLASSIFICATIONS:
            raise ArtifactValidationError(f"findings[{index}] classification is invalid")
        if finding["lineage"] not in LINEAGES:
            raise ArtifactValidationError(f"findings[{index}] lineage is invalid")
        if finding["materiality_basis"] not in MATERIALITY_BASES:
            raise ArtifactValidationError(f"findings[{index}] materiality basis is invalid")
        if (
            finding["classification"] == "blocking"
            and finding["materiality_basis"] not in BLOCKING_BASES
        ):
            raise ArtifactValidationError(
                f"findings[{index}] blocking classification lacks a blocking basis"
            )
        for field in ("likelihood", "impact", "confidence"):
            if type(finding[field]) is not int or not 1 <= finding[field] <= 5:
                raise ArtifactValidationError(f"findings[{index}].{field} must be in 1..5")
        for field in ("exceeds_minimum_standard", "resolved"):
            if type(finding[field]) is not bool:
                raise ArtifactValidationError(f"findings[{index}].{field} must be boolean")
        if finding["lineage"] == "prior_unresolved":
            if finding["prior_finding_id"] not in prior_ids:
                raise ArtifactValidationError(
                    f"findings[{index}] prior finding is not task-bound"
                )
        elif finding["prior_finding_id"] is not None:
            raise ArtifactValidationError(
                f"findings[{index}].prior_finding_id must be null for a new finding"
            )
        if (
            revision > 1
            and finding["classification"] in {"blocking", "severe"}
            and finding["lineage"] in {"regression", "newly_discoverable"}
        ):
            _text(
                finding["novelty_justification"],
                f"findings[{index}].novelty_justification",
            )
        threshold = request["risk_policy"]["severe_risk_threshold"]
        expected_above = (
            finding["classification"] == "severe"
            and finding["likelihood"] * finding["impact"] >= threshold
        )
        if (
            finding["classification"] == "severe"
            and finding["exceeds_minimum_standard"] != expected_above
        ):
            raise ArtifactValidationError(
                f"findings[{index}].exceeds_minimum_standard is inconsistent"
            )
        if not finding["resolved"]:
            blockers += finding["classification"] == "blocking"
            severe_above += expected_above
    must_revise = bool(blockers or severe_above)
    if (verdict["verdict"] == "REVISE") != must_revise:
        raise ArtifactValidationError("DA verdict is inconsistent with material findings")
    expected_score = calibrated_score(findings, request["risk_policy"])
    if verdict["score"] != expected_score:
        raise ArtifactValidationError(f"DA score must equal {expected_score}")
    if type(verdict["escalate_to_jason"]) is not bool:
        raise ArtifactValidationError("escalate_to_jason must be boolean")
    should_escalate = must_revise and revision == MAX_REVIEW_ROUND
    if verdict["escalate_to_jason"] != should_escalate:
        raise ArtifactValidationError("DA escalation must occur exactly on final-round REVISE")
    if should_escalate:
        _text(verdict["decision_question"], "decision_question")
    elif verdict["decision_question"] is not None:
        raise ArtifactValidationError(
            "decision_question must be null unless final-round escalation is required"
        )
    return verdict


def validate_ceo_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ArtifactValidationError("CEO request must be an object")
    required = {
        "schema",
        "run_id",
        "specification_id",
        "plan_revision",
        "specification",
        "specification_path",
        "specification_sha256",
        "plan_md",
        "plan",
        "plan_sha256",
        "premortem_md",
        "da_verdict",
        "da_verdict_sha256",
        "authority_scope",
        "output_workspace",
    }
    if set(request) != required:
        raise ArtifactValidationError(f"CEO request fields must be exactly {sorted(required)}")
    if request["schema"] != CEO_REQUEST_SCHEMA:
        raise ArtifactValidationError(f"CEO request schema must be {CEO_REQUEST_SCHEMA}")
    for field in (
        "run_id",
        "specification_id",
        "specification",
        "specification_path",
        "plan_md",
        "premortem_md",
        "output_workspace",
    ):
        _text(request[field], field)
    _round(request["plan_revision"])
    for field in ("specification_sha256", "plan_sha256", "da_verdict_sha256"):
        _sha256(request[field], field)
    if _digest(request["specification"].encode("utf-8")) != request["specification_sha256"]:
        raise ArtifactValidationError("CEO specification digest is invalid")
    if _digest(_canonical(request["plan"])) != request["plan_sha256"]:
        raise ArtifactValidationError("CEO plan digest is invalid")
    if _digest(_canonical(request["da_verdict"])) != request["da_verdict_sha256"]:
        raise ArtifactValidationError("CEO DA verdict digest is invalid")
    if request["da_verdict"].get("verdict") != "PASS":
        raise ArtifactValidationError("CEO request requires a DA PASS verdict")
    authority = request["authority_scope"]
    expected_authority = {
        "exact_specification_only": True,
        "stops_at": "CEO_APPROVED_PENDING_MATERIALIZATION",
        "material_scope_or_risk_change_requires_jason": True,
    }
    if authority != expected_authority:
        raise ArtifactValidationError("CEO authority_scope is invalid")
    return request


def validate_ceo_decision(decision: Any, *, request: Mapping[str, Any]) -> dict[str, Any]:
    validate_ceo_request(dict(request))
    if not isinstance(decision, dict):
        raise ArtifactValidationError("CEO decision must be an object")
    required = {
        "schema",
        "specification_id",
        "plan_revision",
        "decision",
        "rationale",
        "required_changes",
        "decision_question",
        "material_scope_or_risk_change",
    }
    if set(decision) != required:
        raise ArtifactValidationError(
            f"CEO decision fields must be exactly {sorted(required)}"
        )
    if decision["schema"] != CEO_DECISION_SCHEMA:
        raise ArtifactValidationError(f"CEO decision schema must be {CEO_DECISION_SCHEMA}")
    if (
        decision["specification_id"] != request["specification_id"]
        or decision["plan_revision"] != request["plan_revision"]
    ):
        raise ArtifactValidationError("CEO decision identity does not match request")
    verdict = decision["decision"]
    if verdict not in {"APPROVE", "REJECT_WITH_CHANGES", "NEEDS_JASON_DECISION"}:
        raise ArtifactValidationError("CEO decision value is invalid")
    _text(decision["rationale"], "rationale")
    changes = _string_list(decision["required_changes"], "required_changes")
    question = decision["decision_question"]
    material = decision["material_scope_or_risk_change"]
    if type(material) is not bool:
        raise ArtifactValidationError("material_scope_or_risk_change must be boolean")
    if verdict == "APPROVE":
        if changes or question is not None or material:
            raise ArtifactValidationError(
                "APPROVE requires no changes, no question, and no material change"
            )
    elif verdict == "REJECT_WITH_CHANGES":
        if not changes or question is not None or material:
            raise ArtifactValidationError(
                "REJECT_WITH_CHANGES requires changes and no material change"
            )
    else:
        _text(question, "decision_question")
        if changes or not material:
            raise ArtifactValidationError(
                "NEEDS_JASON_DECISION requires one question and a material change"
            )
    return decision


def _load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("plan", "da", "ceo"))
    parser.add_argument("artifact")
    parser.add_argument("--request", required=True)
    args = parser.parse_args(argv)
    request = _load(args.request)
    artifact = _load(args.artifact)
    if args.stage == "plan":
        validate_plan(artifact, request=request)
    elif args.stage == "da":
        validate_da_verdict(artifact, request=request)
    else:
        validate_ceo_decision(artifact, request=request)
    print(f"VALID: {_digest(_canonical(artifact))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
