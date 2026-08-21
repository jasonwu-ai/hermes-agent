# Live production delta reconciliation inventory

## Evidence boundary

Read-only source: `/root/hermes-agent` at `119b2eae41ce9dea2391b36ab418dfa56824661e` with the working-tree delta recorded on 2026-08-22. Candidate base: `94d24e6e8302147ccd18f1496e26c9ca0d8e206d`.

The live source predates the candidate's v0.20.5 reconciliation and its verified-pipeline/role-contract implementation. Each dirty path was expanded and SHA256 recorded before reconciliation. No task artifact, configuration, credential, service, or production file was written.

## Preserved behavior

- `hermes_cli/gateway.py` (live SHA256 `05efab41fea3661b5c2bcf4bd62ba161253c6d15b12702c3185097800fa74710`): ported semantically. A systemd-owned gateway now skips user-unit refresh during boot, preventing a system/user scope collision. The current candidate's newer gateway lifecycle behavior is otherwise retained.
- `tests/hermes_cli/test_gateway_systemd_refresh_guard.py` (live SHA256 `abc3250593f16e4d70610c2318eedd251023655393e24e5a39116deef71a71b3): ported as a behavior test.

## Excluded modified paths

These files were reviewed against the candidate's newer equivalents and excluded rather than overwriting post-v0.20.5 behavior. The fleet/context overlay was additionally rejected because it hard-codes a profile path and uses a user-facing behavioral environment variable; the candidate's profile-scoped context and prompt-cache contracts remain authoritative.

- `agent/agent_init.py` `e4e21f579e28c4a5ec60d24d5ed4c418af1728b6376a5e70b930d3976243faf0` — requested-provider support already present in candidate.
- `agent/prompt_builder.py` `ae7ef6b290040969e1bd024afaf9c0c4f8a4c1eae76e161525518e3af2e5798b` — stale fleet/provenance overlay conflicts with newer profile-scoped prompt assembly.
- `agent/system_prompt.py` `629cf923fd56ce2e4ca947934b4447202e4fb57f347d8aa47890429e64e749f3` — stale contract/fleet injection superseded by candidate role-contract and cache tiers.
- `cli.py` `bfff1a8b665db795ec84a75892baf8af95005ad610d6f19f7feb57740c738e80` — trace flag depends on excluded provenance overlay.
- `hermes_cli/config.py` `8211447e47d89951d8f4f485749f0abdb9babcab65dc17c2795f433a351ea8cf` — stale fleet config and validation conflicts with current defaults/config split.
- `hermes_cli/kanban.py` `77a29aae81e8a62211f67e82793b583a4fba22fe68026511212d25dfb0e23c4b` — legacy plan compiler command superseded by verified-pipeline admission.
- `hermes_cli/kanban_db.py` `bba7fe612788a94aeebb6248e3173aa693345c3f87a8ec592e87ba5081a39218` — legacy role-contract dispatch conflicts with current run-bound admission receipts.
- `hermes_cli/profiles.py` `13fb84c895a6cae8e99d7adef4a3135138408623890da60d2b544e235f176770` — older runtime alias resolver; candidate profile isolation is newer.
- `hermes_cli/tools_config.py` `392321ad093e9bdcd384de051e3d5872eedb69500544c88c38efbf5338211d3d` — toolset label for excluded evidence broker.
- `hermes_cli/toolset_validation.py` `484c198158d7df15a3380b1dd79faeae6f6d74d318a9b49504031a04f74d0da7` — legacy sentinel validation superseded by candidate toolset validation.
- `hermes_cli/web_server.py` `23b3842cb01b8386ecc2568069d27f49b9f1da085a28fb4926bedd7ca7182987` — direct spec-pipeline routes conflict with candidate plugin boundary.
- `run_agent.py` `01d4c0ff88b8a191a727e2257ed0b4b4c393421df0b30ec073cc6f34aa60b961` — stale prompt exports/signature.
- `tests/agent/test_prompt_builder.py` `fe5a421d04bd09782a1bef1cf6e49742cbb68ab0de4232cb9d19a85958ff6d08` — tests only excluded fleet/provenance overlay.
- `tests/hermes_cli/test_toolset_validation.py` `e0d78172bf298b74513e94cea39fb1ea58f5e063fd3a70122221a2e963fe671d` — tests only excluded sentinel behavior.
- `tools/delegate_tool.py` `629cf923fd56ce2e4ca947934b4447202e4fb57f347d8aa47890429e64e749f3` — stale child prompt behavior conflicts with candidate admission boundary.
- `tools/kanban_tools.py` `acdaa8f00845a48ad1072beeded045d4b474dd2e731a03a12cfa9268f1db00d5` — legacy worker policy conflicts with candidate role-contract tool executor.
- `toolsets.py` `834c248a23dc4a8bf470da26a9375abe077d6e6a3556349cbde64f17eb0f6d24` — excluded evidence-broker toolset.

## Expanded untracked paths

All untracked implementation and test files below are excluded as an older, parallel plan/spec/role/evidence implementation. Candidate `plugins/verified_pipeline`, `hermes_cli/role_contract.py`, and associated tests provide the reviewed replacements; importing both would duplicate control planes and weaken the narrow-core/plugin boundary.

- `agent/role_contract.py` `55735a2930abe8da79c95a247e88fe56e7dd1a9934c66a7a113ef4fe070359c1`
- `hermes_cli/kanban_worker_tools.py` `d75e5d5f445eefe7bf0210f635986b166bf6f032bc855940407bb24ffd8147ec`
- `hermes_cli/plan_compiler.py` `c4ec7588d520654f3a4147e6b14f2bbb7a72a69a9857ec023cf21474f96c73a1`
- `hermes_cli/spec_pipeline.py` `dfd22fee52a91f0381d01f27dd073c6b676369bcc3673c82a391d221268fe580`
- `hermes_cli/spec_pipeline_web.py` `ca072871ebd7360fe7680b83100814e847c260f5beabef1ff54892bb76bf6be8`
- `hermes_cli/spec_planner_inner.sh` `9ca5f912c47d368466b0d7da94c8e7c40bce82d764bb7396a120cc9047a818c5`
- `hermes_cli/spec_planner_worker.py` `a742317cd57877bfbc5ec350dcffdc9173b4e9f4915f0cbda88fde3f8b0e3f81`
- `hermes_cli/workflow_routing.py` `fe10f6b98cf86f9c6a737aa4ae737858e89cb6435db89cfcb4d516c97cd67e42`
- `tools/cos_evidence_tools.py` `af7f66ce50deeec39d583d3e06a88629532a3a00956c60b60b25d8cf19c2a68d`
- `tests/agent/test_role_contract.py` `f5bc9c2bc83e49529a0a67b692adc3a10deaef94a6ff3c846d0e341d9b55d3e4`
- `tests/agent/test_role_contract_system_prompt.py` `4be80f1a9a48ca44a21327aa05cf4417e090e36cc887ccfe22d645e512a1da92`
- `tests/hermes_cli/test_kanban_cli_plan_compiler.py` `898b76501596ef0cb128adc241135a3d37d6a3331d2bb438499f0d4a230294c6`
- `tests/hermes_cli/test_kanban_worker_role_contract.py` `8be4a3f79f3553ffdecb0d16d9d1f25cccf16e984ea89dc22d1c8897b5d6197f`
- `tests/hermes_cli/test_kanban_worker_tool_policy.py` `4146a9f2bd8f2d519aada00a1f3e970f80cf6b1206a823b9d012a2ca5448228d`
- `tests/hermes_cli/test_plan_compiler.py` `954289fc0afa829e558c3487794bb8c27d6a2a182d8d999e21524d244967d36c`
- `tests/hermes_cli/test_spec_review_v2.py` `cb80bef5ce913a192251b673ce8998eee8447b52c541f663f7f6d6a9fe8df37f`
- `tests/hermes_cli/test_workflow_routing.py` `4e1896ff7c3cc39970114428268f7f2722d00387a10bc268812fc0b356e4a8ff`
- `tests/tools/test_cos_evidence_tools.py` `e7f2624c3cd2bc5482351697b6774810cc42ea762d765691465952ed55fa5c7a`

The expanded documentation/policy directories are also excluded: `docs/wiki/audits/kanban-sqlite-writer-audit.md` (`995072f3a55bcb7c03e8cf41ea9a31204f4bc9de6999742e378b671bed9609f7`) makes stale writer-count claims, and `hermes_cli/policies/verified_plan_admission_v1.json` (`61c9d3c1bba2d23da6bc9d37915ea7ac81782b4a0d934089938f7ce58dbcb254`) encodes a machine-specific authority policy.

The expanded `.task-artifacts/t_cbda5a71/` directory is generated task evidence and is excluded: `delegate-preexisting.py` (`65edd6f3ef84bb9b45246b1570bccc71ac2a679c7ed9f730392cbab247a5ba28`), `delegate-source.patch` (`5c306cc3c016c89344f8e1659acc2175960e646bb6208c9fd6f65cc736df36c5`), `exact-byte-bootstrap.patch` and `exact-byte-bootstrap.rollback.patch` (both `31cda5a48ea0e64f154e658bf266125888e1ea4777b9a965ac2bf961dad45f99`).
