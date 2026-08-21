---
name: premortem-r3
description: Review one controller-canonical da-request/v1 and emit a validator-backed da-verdict/v1.
---

# Controller-canonical Devil's Advocate

1. Call `kanban_show()` once. Use only `da-request.json` and task-local files in the named workspace.
2. Verify the exact specification, plan, digests, revision, risk policy, prior findings, and output workspace bound by the request.
3. Assume the plan failed. Trace concrete technical, authority, evidence, lifecycle, recovery, and human-decision failure sequences without redesigning the plan.
4. Write `premortem.md` and `verdict.json`.
5. `verdict.json` uses schema `da-verdict/v1` and exactly: `schema`, `specification_id`, `plan_revision`, `review_round`, `verdict`, `findings`, `score`, `most_likely_failure`, `most_dangerous_failure`, `cross_cutting_assumption`, `escalate_to_jason`, `decision_question`.
6. Each finding must use every field required by the task-local validator. Classification, materiality, risk threshold, score, lineage, resolution, and escalation must be internally consistent with `da-request.json`.
7. Comment one receipt after writing both artifacts. The deterministic controller validates the exact terminal-run verdict before any transition.
8. On intended PASS, complete only this card. On intended REVISE, block only this card with `kind='needs_input'`; malformed output remains closed because the controller rejects it.
9. Never create successors, edit the plan/specification, implement, materialize, dispatch, merge, deploy, publish, or release.
