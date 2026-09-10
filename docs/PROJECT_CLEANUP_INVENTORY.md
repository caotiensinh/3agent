# WorkSpace Project Cleanup Inventory

Status: **read-only audit inventory; no deletion authority**  
Audited baseline: `main@7c7290f8e595edafe024083c6fced7c64be3357b`  
Audit date: 2026-09-10

## 1. Purpose

This inventory separates production code from staging, historical provenance and cleanup candidates. It is intentionally conservative: an item is not deleted merely because it is old, not imported by runtime code, or has a versioned name.

Cleanup must be evidence-driven and must preserve a single canonical implementation without destroying audit provenance or admission/evaluation workflows.

## 2. Classification rules

| Class | Meaning | Default action |
| --- | --- | --- |
| KEEP | Current production/control/verification dependency | Preserve |
| REFACTOR | Active code with maintainability/canonicality debt | Change only with equivalence tests |
| STAGING | Candidate/quarantine material outside production authority | Preserve and keep isolated |
| ARCHIVE | Historical/evidence material with provenance value | Move/retain under explicit retention policy |
| RETIRE CANDIDATE | No normal production role; likely campaign/migration tooling | Verify references/reproducibility, then retire in separate PR |
| DELETE CANDIDATE | Strong evidence of temporary/no-op residue | Verify references, then delete in separate PR |
| REVIEW | Insufficient evidence for safe classification | Do not remove |

## 3. KEEP — production/runtime/control plane

### Core runtime

- `src/three_agent/orchestrator.py`
- `src/three_agent/cli.py`
- `src/three_agent/application_bootstrap.py`
- task/store/evidence/artifact/validator/resource-governance modules
- research/presentation/daily-report agents and their active composition layers
- `profiles/`

Reason: real runtime consumers, CLI/application paths and regression/acceptance coverage.

### Local AI v0.1-v0.4

- `src/three_agent/local_ai_runtime.py`
- `src/three_agent/local_ai_gateway.py`
- `src/three_agent/local_ai_composition.py`
- `src/three_agent/application_bootstrap.py`
- corresponding v0.1-v0.4 tests/docs/status script

Reason: merged production architecture from PR #452. Do not confuse the remaining chat convergence gap with dead code.

### Security monitoring and diagnostics

- `src/three_agent/security_monitoring/`
- security monitoring/PCAP/report/scheduler/local-console CLI surfaces
- diagnostic micro-tool/capability registry and autonomous diagnostics

Reason: implemented runtime/operational surfaces with dedicated tests and CI. Compatibility aliases inside this area are technical debt, not automatic deletion targets.

### Approved skills and configuration

- `skills/`
- `config/`

Reason: trusted runtime/control-plane material.

### Verification infrastructure

- `benchmarks/`
- `evaluation/`
- active recurring CI workflows

Reason: not all verification material is runtime code, but it provides current acceptance, promotion and regression evidence.

## 4. REFACTOR — active but structurally risky

### `src/three_agent/chat_gateway.py`

Classification: **REFACTOR, DO NOT DELETE**.

Evidence/issue:

- it is the packaged chat entrypoint on the audited baseline;
- it contains a long compatibility/version inheritance chain through the current chat generation;
- it owns or composes authentication, chat/service behavior, HTTP routing, workflow/artifact surfaces, security-monitoring context and configuration/onboarding APIs;
- current `main()` still constructs `Orchestrator(config)` directly.

Required retirement condition for any old layer: a canonical replacement plus behavior-equivalence regression coverage for every still-used route/contract.

### `src/three_agent/workspace_frontend.py`

Classification: **REFACTOR/REVIEW, DO NOT DELETE**.

Reason: active frontend surface with high concentration of behavior. Split only after route/UI contract coverage exists.

### Security compatibility aliases

Classification: **REFACTOR**.

Reason: compatibility can be removed only after caller/reference migration is proven. The presence of aliases does not mean duplicate authority exists in production.

## 5. STAGING — intentional quarantine

### `skill_candidates/`

Classification: **STAGING**.

Reason: candidate material intentionally outside approved skill authority. Promote through admission controls; do not merge its authority boundary with `skills/`.

### `network_skills/`

Classification: **STAGING**.

Reason: network/security knowledge blueprints/candidates are intentionally not approved runtime execution authority merely because they exist in the repository.

## 6. ARCHIVE — provenance with low/no normal runtime value

### `artifacts/`

Classification: **ARCHIVE candidate** for consolidation/reconciliation evidence.

Reason: current audit found historical before/after pytest, manifest reconciliation and duplicate-audit evidence rather than normal user runtime output. Keep provenance until a retention location/policy is defined.

### Evidence records

Classification: **ARCHIVE/KEEP-AS-EVIDENCE**.

Reason: promotion and audit provenance may be required to explain past acceptance decisions.

### Historical architecture/phase documentation

Classification: **ARCHIVE or label HISTORICAL when touched**.

Reason: useful design provenance but dangerous if presented as the current as-built state. `docs/PROJECT_CURRENT_STATE.md` has precedence for current status.

## 7. RETIRE CANDIDATES — strong but not deletion-ready

### One-shot closure/evidence workflows

Examples/families:

- `*-one-shot.yml`
- RTX5090 closure/evidence workflows
- D7 edge holdout campaign workflow
- branch/SHA-bound evidence collectors

Reason: these workflows are bound to particular evidence branches, candidate SHAs or completed campaigns rather than normal `main` CI.

Retirement gate:

1. confirm no active branch/PR/release process still calls the workflow;
2. preserve required evidence location and reproduction notes;
3. verify recurring CI does not depend on its artifacts;
4. remove in a dedicated cleanup PR.

### Reconciliation/consolidation workflows

Examples/families:

- reconcile-all-branches generations
- consolidation/reconciliation branch workflows

Reason: migration machinery for prior repository convergence, not normal product runtime.

Retirement gate: same as above, plus preserve the final reconciliation provenance.

### `scripts/consolidate_*`

Classification: **RETIRE CANDIDATE**.

Reason: migration/convergence tooling. Verify no active workflow/operator procedure calls each script before removal.

### Historical `repair_*` scripts

Classification: **RETIRE CANDIDATE / REVIEW**.

Reason: many appear incident-specific. Do not retire a repair script if current installer/recovery documentation still references it.

### Campaign-specific `evidence_tools/`

Classification: **RETIRE CANDIDATE or ARCHIVE**.

Reason: RTX5090/D7 and external-holdout evaluators were created for bounded evidence campaigns. Some were intentionally external to the candidate production tree. Preserve reproduction value before removal.

## 8. DELETE CANDIDATES — high confidence

The following documentation markers have strong temporary/no-op signals from audit and commit history:

- `docs/.ignore-me`
- `docs/.ignore-me-2`
- `docs/.ignore-me-3`
- `docs/.should_not_exist`
- `docs/.ui_compact_answer_actions_placeholder`

Classification: **DELETE CANDIDATE**.

No deletion is performed by this inventory.

Deletion gate:

1. exact repository reference search;
2. confirm no installer/update/packaging regression intentionally uses the sentinel;
3. run affected test/installer lanes;
4. delete only in a dedicated cleanup PR with before/after evidence.

## 9. REVIEW — large historical regression suite

Versioned tests such as `v2...v21` and `v001...v029` are **not junk by naming convention**.

Classification: **REVIEW**.

Before retirement, build a coverage-equivalence matrix:

- contract/invariant protected;
- current canonical test covering the same invariant;
- platform coverage;
- negative/fail-closed coverage;
- unique regression history;
- CI lane consuming it.

Only a test whose protected invariant is fully represented by the canonical suite should be considered for retirement.

## 10. Cleanup execution order

When cleanup is authorized, use this order to minimize risk:

1. high-confidence sentinel/delete candidates;
2. completed one-shot workflows with no active references;
3. campaign-specific evidence tooling after archive/retention decisions;
4. consolidation/repair scripts after caller inventory;
5. historical documentation relocation/labels;
6. test-suite equivalence consolidation;
7. active code refactors such as chat gateway decomposition last, with full behavioral acceptance.

Never mix a large runtime refactor with mass historical deletion in one PR.

## 11. Required evidence for every cleanup PR

Every cleanup PR should record:

- base and head SHA;
- exact removed/moved paths;
- reference-search result;
- replacement/canonical path when applicable;
- tests/CI run and outcome;
- production behavior delta: expected `none` for pure cleanup;
- provenance/archive location when historical evidence is moved;
- rollback path.

A successful cleanup reduces repository ambiguity without changing authority, behavior or accepted runtime contracts.
