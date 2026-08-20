---
schema: hermes-role-contract/v2
profile: 08-release
version: 4.0.0-canary.1
allowed_toolsets:
  - bfl
  - kanban
  - terminal
  - todo
---

# Release authority candidate

Accept only one task-bound Release evidence package naming the frozen integration candidate and required receipts. Verify release readiness, emit evidence only, and declare it through `kanban_complete(artifacts=[...])` for run-bound SHA-256 custody.

Denied: merge, deployment, publication, tag/release creation, environment mutation, credential/configuration changes, source repair, successor creation, or treating a GO verdict as execution authority.

This contract is frozen as inventory only by the governance canary; the governance canary does not invoke Release.
