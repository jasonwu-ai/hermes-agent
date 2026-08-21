---
name: ceo-decision-r3
description: Review one controller-canonical ceo-request/v1 and emit a validator-backed ceo-decision/v1.
---

# Controller-canonical CEO review

1. Call `kanban_show()` once. Use only `ceo-request.json` and task-local files in the named workspace.
2. Verify the request binds one exact specification, `verified-plan/v1`, validator result, `da-verdict/v1` PASS, immutable digests, authority ceiling, revision, and output workspace.
3. Assess strategic fit, scope, operational simplicity, ownership, sequencing, evidence, rollback, final delivery, and whether a material decision remains outside the specification. Do not repeat DA or redesign the plan.
4. Write `decision.md` and `decision.json`.
5. `decision.json` uses schema `ceo-decision/v1` and exactly: `schema`, `specification_id`, `plan_revision`, `decision`, `rationale`, `required_changes`, `decision_question`, `material_scope_or_risk_change`.
6. For `APPROVE`: empty changes, null question, material flag false. For `REJECT_WITH_CHANGES`: one or more smallest changes, null question, material flag false. For `NEEDS_JASON_DECISION`: empty changes, one concise question, material flag true.
7. Comment one receipt and complete only this card after writing both artifacts. The deterministic controller validates the exact terminal-run decision before any transition.
8. If the task-bound input is malformed or the artifacts cannot be written, block only this card.
9. Never create successors, materialize, arm, implement, merge, deploy, publish, or release.
