# WorkSpace Project Current State

Status: **authoritative as-built project-state document**  
Audited baseline: `main@7c7290f8e595edafe024083c6fced7c64be3357b`  
Audit date: 2026-09-10  
Scope: repository/runtime/documentation state, not future roadmap

## 1. Purpose and authority

This document exists to prevent documentation drift. It records what is actually present and connected on the audited `main` baseline, distinguishes production runtime from staging and historical material, and names known integration gaps without promoting open pull requests or design proposals to production status.

When sources disagree, use this precedence:

1. exact `main` executable tree and immutable configuration/authority contracts;
2. tests and exact-head CI/evidence for that tree;
3. this current-state document and subsystem documents explicitly marked current;
4. architecture blueprints, roadmaps, migration notes and historical evidence.

A design document does not prove implementation. A file existing in the repository does not prove it is in the production invocation path. An open pull request is not production state.

## 2. Baseline verification

The audited baseline is merge commit:

`7c7290f8e595edafe024083c6fced7c64be3357b`

It merged PR #452, `feat(models): wire authority-bound local AI runtime bridge`.

On this exact head, the post-merge acceptance set observed during the audit completed successfully across the main harness, canonical module, Internet-egress security, installer, portable/Windows deployment, model-candidate and security evidence/PCAP lanes.

This evidence establishes that the baseline is internally testable and accepted by the repository's current gates. It does not imply every historical, staging or one-shot file is a production runtime dependency.

## 3. Production-active core

The following areas have real executable or canonical configuration paths on the audited baseline.

### Application and workflow core

- `src/three_agent/orchestrator.py` — central runtime composition/domain workflow object.
- `src/three_agent/cli.py` — primary `workspace` / `three-agent` CLI.
- `src/three_agent/application_bootstrap.py` — trusted Local AI application composition root introduced by v0.4.
- task/store/evidence/artifact/validator/resource-governance layers used by the workflow runtime.

### Agents and profiles

The research, presentation and daily-report agents are production code. Agent profiles under `profiles/` are loaded by the agent base implementation and are not orphan documentation.

`research_compiled.py` / ranked research layering is intentional composition. It must not be treated as duplicate code solely because multiple implementation layers exist.

### Approved skills

`skills/` is the approved runtime skill surface. The approved-skill loader enforces registry/scope/integrity policy and fails closed when required trust metadata is unavailable or invalid.

`skill_candidates/` is not equivalent to `skills/`; see staging below.

### Security monitoring and diagnostics

The security/network subsystem is implemented and operationally exposed. Current package/script surfaces include:

- `src/three_agent/security_monitoring/`
- `workspace-security-monitor`
- `workspace-security-pcap`
- `workspace-security-report`
- `workspace-security-scheduler`
- `workspace-security-ui`
- diagnostic micro-tool/capability registries and autonomous diagnostic services

The subsystem contains monitoring, evidence normalization, correlation/analysis, reporting, local-console/configuration and approved-asset boundaries. Its existence does not grant free-form shell, arbitrary scan, packet-capture or remediation authority to chat or to model output.

`docs/SECURITY_ANALYST_HACKINGTOOL_DISTILLATION.md` is the original integration blueprint and design provenance. It is not the authoritative indicator of whether the subsystem is still merely planned.

### Configuration and quality infrastructure

`config/` contains active control-plane material such as workspace profiles, execution governance, model approval/candidate policy, Internet-egress policy and security/network dataset policy.

`benchmarks/` and `evaluation/` are quality/evaluation infrastructure. They are not normal runtime hot-path code, but they are structured verification inputs and must not be classified as junk merely because they are not imported by the application server.

## 4. Local AI status

### v0.1 — Runtime Status Plane

Implemented and merged. Provides trusted observation of the local runtime without granting model authority.

### v0.2 — Authority-bound Local Model Gateway

Implemented and merged. Stable WorkSpace bindings are separated from runtime model names; invocation remains bound by immutable task/model authority and fail-closed policy.

### v0.3 — Trusted Local AI Composition

Implemented and merged. Trusted bindings and already-created backends are composed without runtime discovery, install, pull or authority widening.

### v0.4 — Application Bootstrap

Implemented and merged by PR #452. `build_application_runtime()` composes Local AI before constructing the Orchestrator. The primary CLI uses the backward-compatible `build_orchestrator()` facade.

### Packaged chat boundary on the audited baseline

The packaged chat command on `main@7c7290f8...` still points to `three_agent.chat_gateway:main`. That `main()` loads configuration and constructs `Orchestrator(config)` directly before starting the chat service and HTTP server.

Therefore:

- packaged chat has **not** yet converged onto `ApplicationRuntime` on this baseline;
- ordinary direct chat still belongs to the existing orchestrator model path;
- `LocalModelGateway` is not yet the sole model invocation boundary for ordinary direct chat;
- no document may claim v0.5 application/chat convergence is production on this baseline.

PR #505 (`feat(models): route packaged chat through application runtime`) is open at audit time and proposes v0.5a. Its own stated scope deliberately defers direct-chat `LocalModelGateway` convergence to a later v0.5b. Because PR #505 is open and unmerged, it is WIP rather than production state.

## 5. Packaged chat and UI status

The chat gateway is a real production surface with authentication/session handling, conversation continuity, local attachment handling, artifact/workflow routes, security-monitoring context and admin-approved asset/configuration boundaries.

The current file also contains a long compatibility/version inheritance chain reaching the current generation. This is **active technical debt**, not dead code. It should be refactored only with equivalence tests and a canonical replacement path; deleting intermediate layers by name would be unsafe.

The current chat security context is advisory/read-only. It exposes bounded local state to the chat layer and explicitly keeps monitoring execution/remediation authority separate.

## 6. Staging and quarantine — keep separate from production authority

### `skill_candidates/`

Intentional candidate/quarantine area. Candidate material is not approved runtime skill authority until it passes admission/promotion controls.

### `network_skills/`

Intentional network/security knowledge staging area. Its presence in the repository does not make it automatically executable or approved.

These directories must not be deleted merely because runtime code does not import their directory name directly.

## 7. Historical/evidence-only material

The repository retains material that can be valuable for provenance but is not a current production runtime surface:

- consolidation/reconciliation evidence under `artifacts/`;
- promotion/audit records under evidence-record areas;
- campaign-specific `evidence_tools/` such as RTX5090/D7 evaluators;
- branch/SHA-bound closure, reconciliation and other one-shot workflows;
- migration/consolidation/repair scripts used to converge earlier repository states.

Retention value and runtime value are different. These items should be governed by an archive/retention policy, not silently treated as active product architecture.

## 8. High-confidence cleanup candidates

The read-only audit found a small set of documentation sentinel/temporary artifacts with strong evidence of being non-product markers:

- `docs/.ignore-me`
- `docs/.ignore-me-2`
- `docs/.ignore-me-3`
- `docs/.should_not_exist`
- `docs/.ui_compact_answer_actions_placeholder`

These remain untouched in this documentation-convergence change. Deletion requires a separate cleanup change with reference checks and regression evidence.

See `docs/PROJECT_CLEANUP_INVENTORY.md`.

## 9. Known technical debt

### Chat gateway concentration

`chat_gateway.py` and the frontend surface carry substantial compatibility and feature layering. They are working code, but their size/version-chain structure raises maintainability and canonicality risk.

### Local AI convergence gap

The trusted v0.4 bootstrap exists, but packaged chat and ordinary direct-chat invocation are not fully converged onto the new authority-bound gateway on this baseline.

### Historical CI/tooling accumulation

The repository contains many one-shot campaign/reconciliation workflows and repair/consolidation scripts. Their purpose should be recorded and then archived or retired using evidence-driven cleanup rather than continuing to present them as normal CI.

### Test archaeology

A large set of versioned regression tests protects historical contracts. The suite is not automatically junk; retirement requires coverage-equivalence proof so that canonical behavior remains protected.

### Documentation archaeology

Older architecture/phase documents can preserve useful provenance but must not be allowed to override current state. Historical design documents should be clearly labeled when touched.

## 10. Current non-goals / not-yet-production claims

On this audited baseline, do not claim any of the following as complete production behavior unless a later merged `main` is re-audited:

- frontend or chat directly invoking Ollama as an authority source;
- ordinary direct chat fully routed through `LocalModelGateway`;
- request-supplied model names granting authority;
- automatic model pull/install/discovery;
- staging skills automatically promoted into approved runtime;
- autonomous unrestricted network scanning/remediation;
- historical one-shot workflows being required normal production CI.

## 11. Documentation convergence policy

Every change that materially changes production architecture, entrypoints, authority boundaries or subsystem status SHOULD update this document in the same PR.

Use explicit status terms:

- **CURRENT / ACTIVE** — implemented on the referenced `main` baseline with an executable/configuration path and supporting verification.
- **STAGING / QUARANTINE** — present for admission/evaluation but not production authority.
- **WIP / OPEN PR** — proposed code not merged to `main`.
- **HISTORICAL / EVIDENCE-ONLY** — retained for provenance, reproduction or audit, not normal runtime.
- **RETIRE CANDIDATE** — not needed by current runtime, but requires reference/retention review before removal.
- **DELETE CANDIDATE** — strong evidence of no product/provenance role; still requires an explicit cleanup change.

Never use an open PR, stale SHA, old benchmark or design roadmap as proof of current production state. Revalidate `main` before publishing a new project-state snapshot.
