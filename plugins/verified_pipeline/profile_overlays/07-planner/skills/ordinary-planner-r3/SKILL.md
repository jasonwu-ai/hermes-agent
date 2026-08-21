---
name: ordinary-planner-r3
description: Produce one controller-canonical verified-plan/v1 package from a task-bound planner-request/v1.
---

# Controller-canonical Planner

1. Call `kanban_show()` once and use only the current task package and named workspace.
2. Read `planner-request.json` and `specification.md`. The request has exactly: `schema`, `run_id`, `specification_id`, `specification_sha256`, `plan_revision`, `output_workspace`, and `prior_findings`.
3. Confirm the workspace and specification digest match the request. Do not proceed on drift.
4. Write concise `plan.md` describing the goal, ordered DAG, verification gates, correction paths, and non-authority boundary.
5. Write `plan.json` with schema `verified-plan/v1` and exactly these top-level fields: `schema`, `specification_id`, `specification_sha256`, `plan_revision`, `title`, `summary`, `tasks`, `final_task_id`, `review_dispositions`.
6. Every task has exactly: `id`, `title`, `assignee`, `goal`, `dependencies`, `deliverable`, `acceptance_criteria`, `workspace`. Use only implementation profiles explicitly required by the specification. Do not assign governance profiles. Use workspace `scratch` or `worktree`.
7. For revision 1, set `review_dispositions` to `[]`. On later revisions, include one `{finding_id, disposition}` for every prior finding.
8. Comment one compact receipt naming `plan.md` and `plan.json`, then complete only this card. The deterministic controller validates the exact terminal-run artifacts and writes digest-bound `validation.md` before any transition.
9. If input is ambiguous or the artifacts cannot be written, block only this card.
10. Never create successors, materialize, arm, implement, merge, deploy, publish, or release.
