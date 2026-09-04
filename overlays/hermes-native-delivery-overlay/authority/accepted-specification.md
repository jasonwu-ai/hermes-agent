---
title: Hermes-Native Two-Gate Delivery — Replacement Program Revision 1
Status: Draft
tier: T3
revision: 1
execution_authority: NONE
implementation_started: false
supersedes_on_exact_acceptance: agentic-pipeline-items-2-8.md
created_at: 2026-09-03T14:48:33+10:00
---

# Hermes-Native Two-Gate Delivery — Replacement Program Revision 1

## 1. Decision and desired outcome

Build the smallest upgrade-safe system that gives Jason one relationship—CoS—and two clear human decisions:

```text
Jason ↔ CoS discussion and grill
→ separate adversarial roast
→ one reviewable specification
→ HUMAN GATE 1: approve bounded private engineering or request changes
→ Planner → DA → CEO → native Kanban → build → test → integration → private PR/CI → Release review
→ one final evidence page
→ HUMAN GATE 2: approve only the exact listed release actions or request changes
```

The backend may use specialist profiles in steady state, but Jason does not coordinate them. CoS owns the user relationship, explains decisions, and is accountable for the final result.

This revision changes the **bootstrap method**: the existing pipeline will not orchestrate its own replacement. CoS will build the first local, secret-free candidate directly with ordinary tools in an isolated repository. Other agents may later review exact bytes, but they do not control, mutate, or supervise the bootstrap.

## 2. Governing evidence and status

This Draft is a forward-only revision. It does not modify the accepted North Star bytes.

- Accepted North Star: `/home/hermes/content/specs/programs/canonical-verified-execution/north-star-draft-v3.md`, SHA-256 `e70b45f145ba394e7743b3b5d142ef42845cc876286c32da9978d912f94a0ca6`.
- Earlier Items 2–8 Draft to be superseded only after exact acceptance: `/home/hermes/content/specs/drafts/00-cos/agentic-pipeline-items-2-8.md`, SHA-256 `1bd85d411c3302975a92ce52f754129ab18302aaf6db452df7751b0175284113`.
- Fable 5.1 memo: SHA-256 `071b58c744ad7bf8424f0bb8724574c594b9304e3c814d44b08c4859a2c58277`.
- CoS verification/disposition: SHA-256 `45dc68399efecab4d8fc959ee5b77f17dca1324d3cc27c60ce341fa804567679`.

Fable’s simplification direction is accepted. Its claims that the full M0 candidate is a one-line change and that stock Hermes already provides `workspace_only` plus fleet role-contract enforcement are explicitly corrected by the CoS disposition.

## 3. Resolved architecture decisions

1. **One user-facing CoS.** Grill and roast are distinct activities behind one conversation.
2. **Two human gates.** Gate 1 covers exact specification bytes and a bounded private-engineering envelope. Gate 2 names each optional release action—such as push, merge, install, restart, deploy, or activate—and records only what Jason actually selected.
3. **Native Kanban is execution truth.** Cards, dependencies, claims, workspaces, attachments, review/request-changes, retries, and completion state are not duplicated in another workflow engine.
4. **One deterministic plugin/controller.** Native Kanban lifecycle hooks wake it. Because the hooks are post-commit and best-effort, durable idempotent reconciliation owns correctness and missed-event recovery.
5. **No `13-execution-supervisor`.** No LLM supervisor profile, worker polling fleet, heartbeat scheduler, or repair-loop cron controls the lifecycle.
6. **Clean upstream plus a private overlay.** Custom code, templates, profile distributions, and tests live outside Hermes core. Each release records an exact upstream pin.
7. **Git/GitHub own code identity.** Branches, commits, PRs, CI, merge state, and source rollback are not recreated in bespoke ledgers.
8. **One small authority/outbox ledger is permitted.** It stores authenticated exact-byte decisions and replay-safe pending projections only. It is not a second task/status system.
9. **Legacy machinery is frozen, not immediately deleted.** It becomes retirement-eligible only after dependency census, archive manifest, replacement canary PASS, and separate destructive authority.
10. **Bootstrap ownership is CoS-direct.** Specialist agents may provide read-only exact-head review. They do not write candidate bytes or orchestrate the system being replaced.

## 4. Minimum custom architecture

Target package: `hermes_verified_delivery` in a new local overlay repository. Target: no more than three substantive production modules and 700 nonblank production lines; 800 lines is a hard architecture-review breaker. Tests, templates, and plugin metadata are counted and reported separately.

### A. `contracts.py`

- Typed specification, approval, request-changes, plan, DA, CEO, Git source, materialization, Release, and final-evidence records.
- Canonical serialization and hashes.
- Explicit allowed actions, exclusions, actor, expiry, nonce, replay key, repository/base/head, and rollback fields.
- No credentials or raw conversation content.

### B. `controller.py`

- Pure deterministic state machine plus a thin native-Kanban adapter.
- Reads durable authority/outbox records and native Kanban state.
- Uses semantic idempotency keys and complete-contract comparison.
- Handles duplicate hooks, missed hooks, restart replay, conflicting replay, expiry, and literal blocked states.
- Never treats a hook, model response, task status, or notification as human authority.
- Does not directly deploy or activate; later actuators consume separately admitted Gate 2 actions.

### C. `review.py`

- CommonMark-to-HTML rendering with raw HTML disabled or sanitized.
- Mobile-first specification and final-evidence pages.
- Approve, Request changes, and optional terminal Reject semantics.
- Request changes requires feedback, preserves the old revision, produces no downstream task, and creates a new revision request.
- Approval handlers append authority plus outbox intent atomically; they never launch workers directly.

The plugin registration layer subscribes to native Kanban lifecycle events and invokes the controller’s bounded reconcile function. Startup and explicit reconcile cover missed hooks. No pipeline-owned recurring cron is planned.

## 5. Retain, replace, and retire

### Retain

- CoS, conversational grilling, separate roasting, and the accepted North Star.
- Native Hermes profiles and Kanban where their exact current behavior passes seam tests.
- Native project worktrees, task attachments, same-card review/request-changes, retries/reclaim, and dashboard visibility.
- Planner, DA, CEO, Builder, independent Test, read-only Release, and Integration only when multiple components genuinely require it.
- Fable/Counsel outside the operational loop for bounded architecture review.
- Git/GitHub for source and CI evidence.

### Replace

- Legacy Evidence Gate/webhook with `review.py`.
- Custom supervisors, watchers, worker crons, handoff bridges, and duplicate status stores with `controller.py` plus native events/state.
- Broad receipt trees with the minimum authority record, native task evidence, exact Git commit identity, and final human evidence page.
- The planned Execution Supervisor role with deterministic plugin code.
- The old Items 2–8 Draft with this revision only after exact acceptance.

### Retirement candidates after replacement PASS

- Paused pipeline supervisor/watchdog/worker cron records.
- Legacy CoS pipeline scripts.
- Overlapping lifecycle skills replaced by one short operator skill and stable references.
- Obsolete Validator/Auditor roles only after a role/dependency census proves their responsibilities are covered.
- The current M0 implementation branch as an active delivery route; preserve its commits, tests, and findings as evidence unless separately authorized for deletion.

## 6. Confinement and the M0 decision

The security invariant is retained; the sequencing changes.

- **CoS-direct local bootstrap may begin without M0 admission** only after exact approval of this Draft. It is confined by scope: one new local repository, secret-free fixtures, no specialist-agent execution, no network writes, no live Hermes/profile/board changes, and no credentials.
- **No specialist agent may modify code or operate a real/private repository** until clean-current-upstream tests prove task/run-bound admission, final tool-argument enforcement, workspace confinement, Docker/worktree custody, and secret exclusion.
- The existing M0 branch is not the implementation base. It remains preserved evidence.
- If clean upstream lacks a required confinement seam, CoS may prepare a narrow upstreamable local patch and tests, but cannot install, publish, push, merge, or activate it under this Draft.
- A secret-free deterministic local canary is not evidence of production-grade isolation.

This resolves the immediate bootstrap deadlock without pretending the missing boundary does not matter.

## 7. Authority boundary

### Current authority

This document is a Draft with `execution_authority: NONE`. The user’s instruction to continue authorizes drafting, read-only inspection, local artifact validation, and delivery of this reviewable Draft only.

### Authority created by later exact acceptance

Exact acceptance of this Draft would authorize one **Local Bootstrap v1** envelope, performed directly by CoS:

- create `/root/hermes-native-delivery-overlay` as a new local Git repository with no remote;
- record the then-current clean public Hermes upstream commit as `UPSTREAM_PIN`;
- implement the three-module candidate, tests, templates, plugin metadata, and documentation in that repository;
- use only secret-free fixtures and disposable local/scratch Hermes homes, repositories, and Kanban databases;
- run deterministic tests, static checks, race/replay tests, and headless desktop/mobile rendering checks;
- create local commits on branch `cos/bootstrap-v1`;
- prepare an exact-head independent read-only review package;
- correct implementation defects within the approved modules and line limit for at most two bounded repair rounds; and
- produce a Bootstrap Evidence Packet and stop.

The accepted envelope would expire 14 days after acceptance and would incur no new cash spend.

### Still excluded after acceptance

- use of the legacy pipeline to dispatch or supervise the bootstrap;
- specialist-agent code mutation or genuine operational DAG execution;
- any remote/GitHub write, repository creation, branch push, PR, issue, tag, or publication;
- modifying or installing into the active Hermes checkout or any active profile;
- gateway/service/dashboard restart;
- live plugin registration or activation;
- production or private-repository credentials, credential changes, or secret inspection;
- merge, release, deployment, activation, or cutover;
- destructive cleanup, deletion, archival moves, profile retirement, cron removal, or history rewriting;
- waiver of failed tests, independent review, confinement, or exact-byte gates; and
- unbounded repairs or new modules introduced to work around a failure.

## 8. Local Bootstrap v1 implementation slice

### B0 — Baseline and contracts

- Freeze current public upstream at implementation start and record commit/tree/version.
- Initialize the local overlay repository and branch.
- Implement canonical contracts, serialization, exact hashes, action scopes, expiry, nonce/replay rules, and negative fixtures.

### B1 — Controller kernel and native seam adapter

- Implement the deterministic state machine and scratch-board adapter.
- Exercise native lifecycle-hook events against a disposable board.
- Prove duplicate-hook no-op, missed-hook reconciliation, restart replay, conflicting replay rejection, expiry, and no partial task graph.
- Do not dispatch a model or worker.

### B2 — Inert review surface

- Render a specification and final-evidence page from fixed fixtures.
- Exercise Approve/Request-changes using synthetic authenticated-actor fixtures only.
- Prove request-changes creates no downstream task and approval creates an inert outbox intent rather than launching work.
- Verify desktop and 390-pixel mobile rendering, no horizontal overflow, accessibility labels, and no hidden external dependencies.

### B3 — Evidence and independent review stop

- Run the full local deterministic suite from a clean checkout.
- Record production/test/template line counts and changed paths.
- Seal exact commit/tree and all test evidence.
- Submit an exact-head package to an independent read-only reviewer if a properly confined route is available.
- Stop at `BOOTSTRAP_EVIDENCE_READY`; do not install, connect to the live gateway, invoke specialist agents, or write to GitHub.

## 9. Acceptance tests and required evidence

Bootstrap PASS requires all of the following:

1. Every transition consumes schema-valid exact predecessor bytes and rejects unknown authority-bearing fields.
2. Approval and outbox intent are atomic across injected crash points.
3. Request changes requires feedback, preserves the prior revision, and creates zero tasks.
4. Duplicate/missed hooks and process restarts converge to one state without a polling supervisor.
5. Concurrent same-key reconciliation creates one inert graph; mismatch fails closed.
6. Best-effort hook failure does not lose work because durable reconciliation succeeds later.
7. No test reads credentials, live session data, raw personal conversations, or active profile memory.
8. No test changes the active Hermes checkout, gateway, profile configuration, live board, or network state.
9. Clean-checkout test commands, interpreter, exit codes, stdout/stderr hashes, commit, tree, and working-tree status are recorded.
10. Production code stays below the 800-nonblank-line breaker and introduces no second lifecycle/status store or recurring pipeline cron.
11. Desktop and mobile HTML checks pass with no misleading authority text or direct-launch handler.
12. An independent exact-head reviewer returns a decisive PASS before any proposal to install or run a genuine agent canary. If review is unavailable, status remains `SELF_TESTED_NOT_INDEPENDENTLY_ACCEPTED`.
13. The Bootstrap Evidence Packet states exactly what is source-only, locally tested, independently reviewed, installed, live, and still absent.

## 10. Operations, rollout, and rollback

The implementation works in one-failure/one-proof blocks. CoS reports literal state: source written, tests passed/failed, review pending/passed, or stopped. Activity is not progress unless a named acceptance criterion advances.

Stop immediately if:

- the plugin API cannot support the design without modifying installed Hermes;
- a missing confinement seam would allow an agent to escape its admitted task/workspace;
- production code reaches 800 nonblank lines;
- the same material defect survives two repair rounds;
- any test requires live credentials, network writes, active profiles, or the real board;
- the candidate starts duplicating Kanban task state or Git source state;
- an external, destructive, installation, restart, deployment, or activation action is required; or
- compaction cannot reconstruct the exact Draft, candidate commit, current stage, and next permitted action from persistent artifacts.

Before live installation, rollback means stop, preserve the repository/commit/evidence, and make no active-system change. Nothing legacy is deleted. Later disabled installation, genuine-agent canary, GitHub publication, merge, activation, and retirement each require their own reviewed packet and exact authority.

## 11. Risks and trade-offs

- **CoS has broad host capability.** Contain the bootstrap to the named new repository and disposable test roots; verify no other tracked or live path changed.
- **CoS authors and implements.** Independent exact-head review remains mandatory before installation or genuine agent execution.
- **Native hooks are best-effort.** Treat them only as wake-up signals; reconcile from durable authority and Kanban state.
- **Clean upstream moves.** Freeze an exact pin at implementation start and re-evaluate before any later port or installation.
- **The line limit may be too tight.** Stop for architecture review rather than removing authentication, confinement, replay protection, or evidence integrity.
- **Steady-state agents may still fail.** The controller must stop with literal evidence; it must not spawn a repair supervisor. The first genuine canary will test the complete profile path separately.
- **Legacy dependencies may be hidden.** Archive and dependency census precede any retirement proposal.

## 12. Open decisions and next visible gate

No further design interview is required before reviewing this Draft. The exact acceptance decision is:

- **Accept:** authorize the Local Bootstrap v1 envelope in Section 7 for 14 days, with every exclusion preserved; or
- **Request changes:** provide required changes; CoS creates a new immutable revision and no implementation starts.

Acceptance of this Draft does **not** approve the complete steady-state rollout. It authorizes the smallest source-only bootstrap needed to prove or falsify the simplified design. The next later gate would be a separate exact Bootstrap Evidence Packet for disabled installation and a genuine canary.
