# Hermes-Native Two-Gate Delivery Overlay

**State:** target-based, source-only, qualification-only candidate in the controlled Hermes fork. It is not installed, enabled, deployed, or connected to a live Hermes home or Kanban board.

This subtree implements the bounded Local Bootstrap v1 accepted for specification SHA-256 `095ced65676ee3c95f39c992f30b193437eda81acb327e6764c5c64c28388f1a`.

## Integration custody

- Destination: `https://github.com/jasonwu-ai/hermes-agent.git`, branch `fleet/main`.
- Exact integration parent: `772dae7a3db33b635be3d00c7e42feba4e17c7f4`, tree `dffea5701ca15422d8030bed1396a08157eb16c5`.
- Repaired-source provenance: commit `5b60517c7e6a2e7df6b9eee1da0df60122fa9a4d`, tree `140bba967e392c3a793c10bd273d701fbe278686`.
- Production modules and plugin registration started from that repaired source. `controller.py` additionally converts inaccessible path components into a fail-closed contract rejection, covering unprivileged CI/runtime users.
- The repository-level workflow `.github/workflows/hermes-verified-delivery.yml` qualifies this subtree against the exact target checkout and refuses an unexpected parent or out-of-scope path.

## Safety model

- The approval handler commits an immutable decision and a `HELD` outbox intent in one SQLite transaction.
- The approval handler derives specification bytes, actor, time bounds, and scope from the exact checked-in predecessor, accepted specification, and hashed approval receipt; caller-supplied envelope drift fails closed.
- The approval handler never launches a process and never writes Kanban.
- Request Changes stores feedback but creates no outbox intent.
- Reconciliation revalidates issuance and expiry, consults an existing materialization receipt before any board write, and is explicitly invoked; no cron, watchdog, drainer, or second lifecycle store exists.
- Native hook callbacks are wake-up hints only and default to inert.
- Scratch materialization requires `qualification_enabled: true`, a test-owned root containing `.hvd-qualification-root`, and distinct authority/Kanban databases as direct, non-symlink children of that root.
- Every candidate task is `blocked`, uses a scratch workspace, and has its complete native ownership, workspace, dispatch, execution, and provenance contract compared before idempotent reuse.
- Untrusted Markdown images are rendered as inert alt text and both HTML surfaces carry a restrictive Content Security Policy.
- The plugin declares Linux and macOS support only; its locking backend is deliberately POSIX-only.

## Layout

- `hermes_verified_delivery/contracts.py` — strict typed contracts, canonical JSON, hashes, timestamps, replay identity, graph validation.
- `hermes_verified_delivery/controller.py` — single authority/outbox ledger and guarded native Kanban reconciler.
- `hermes_verified_delivery/review.py` — CommonMark review HTML and authenticated synthetic decision handler.
- `authority/` — the exact predecessor, accepted specification bytes, and predecessor-hash-bound approval receipt.
- `tests/` — synthetic negative, crash, replay, concurrency, hook, rendering, path-confinement, and scope tests.

## Qualification command

```bash
PYTHONPATH=".:/path/to/pinned/hermes-agent" python3 -m pytest -o 'addopts=' -q
```

The exact checkout path, command, runtime, hashes, commit/tree identity, and review verdict are recorded in `evidence/` after qualification.

## Explicit non-claims

This candidate does not prove installation, authenticated live-session admission, production confinement, live profile compatibility, worker execution, GitHub behavior, merge, release, deployment, or activation.
