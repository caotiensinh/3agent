# WorkSpace Agent Runtime Source Convergence Audit

Status: normative implementation audit for the WorkSpace-native agent runtime.

## Baseline

- Repository: `caotiensinh/3agent`
- Original audited `main`: `3a13b9680a57b82cff503633111d0cfd7691c4d2`
- Runtime architecture source: `docs/WORKSPACE_AGENT_RUNTIME_ARCHITECTURE.md`
- Architecture PR: `#363`, merged into the original audited baseline above
- First convergence merge: PR `#365`, authority narrowing, merge commit `37ff9359ac7ebe83c3032bf3f27c9eb35fb7f009`
- Second convergence merge: PR `#366`, canonical `TaskContext`, merge commit `d1e537f9c89673d180740e94e7f46c2f6ba83775`
- Third convergence merge: PR `#367`, canonical `ExecutionPlan` / `ExecutionNode`, merge commit `8fd819eb028acadf881284b919d0aa86c28039f2`
- Current P0-4 candidate: PR `#369`, canonical runtime Observation -> Evidence binding
- P0-4 implementation commit before source synchronization: `690f95af75c6d987fd8b1eaa2f89fb78d65ca953`
- P0-4 synchronization commit carrying the current `main` benchmark contract from PR `#368`: `ff477211bffff8d8da541dfa73b16e73d0798ef5`
- Audit rule: extend canonical source first; do not create parallel runtime abstractions when equivalent primitives already exist.

The architecture is therefore treated as a convergence target over the existing WorkSpace source tree, not as permission to create a second implementation tree.

## Classification

- `KEEP`: implementation already satisfies the core role and should remain canonical.
- `EXTEND`: canonical implementation exists but is narrower than the runtime contract.
- `REFACTOR`: useful implementation exists but responsibilities need normalization before becoming runtime-wide.
- `MISSING`: no runtime-wide implementation matching the required responsibility was found in the audited source.
- `DEPRECATED/DUPLICATE`: parallel implementation that should not become a second source of truth.

## Convergence matrix

| Runtime area | Existing source evidence | Status | Concrete gap | Required action |
| --- | --- | --- | --- | --- |
| `TaskContext` | `src/three_agent/task_context.py` — `TaskContext`, `TaskContextBuilder`, `TaskResourceBudget`; `src/three_agent/task_contract.py` — `TaskContract`, `TaskContractCompiler`; `src/three_agent/harness_task_compiler.py` — `CanonicalTaskSpec`; `src/three_agent/harness_context_manifest.py` — `ContextManifest`; `src/three_agent/trusted_runtime_context.py`; `src/three_agent/execution_observation.py` | `KEEP/EXTEND` | P0-2 provides one immutable runtime binding for task/session/trace/actor identity, purpose, project, risk class, resource budget, inventory scope, contract/canonical-task/authority fingerprints and versioned context/evidence references. P0-3 binds plans to the exact `TaskContext`; P0-4 binds every generic execution observation to the exact task-context identity and fingerprint. Remaining work is scheduler, delegation, checkpoint and aggregation wiring. | Keep `TaskContext` canonical and extend its use at the remaining execution boundaries. Do not introduce another runtime task model or allow context text to become an authority source. |
| `AuthorityEnvelope` | `src/three_agent/capability_authority.py` — `TaskCapabilityAuthority`, `CapabilityDecision`; `src/three_agent/model_authority.py`; `src/three_agent/capability_revocation.py`; `src/three_agent/security_monitoring/operation_invocation.py`; `src/three_agent/execution_plan.py`; `src/three_agent/execution_observation.py` | `KEEP/EXTEND` | Runtime capability/write/network enforcement is deny-by-default; PR `#365` added fail-closed delegation proving `child_authority <= parent_authority`; P0-3 binds every node to a derived child authority; P0-4 rejects observations whose node authority cannot be rebound exactly to the current parent authority fingerprint. Remaining work is scheduler-time monotonic revocation and current-authority revalidation before every dispatch. | Keep `TaskCapabilityAuthority` canonical. Scheduler and delegation must consume/revalidate the node authority fingerprint and revocation state; they must never infer authority from plan text, observation text or model output. |
| Capability registry / `CapabilityDescriptor` | `src/three_agent/security_monitoring/capability_registry.py` — `SecurityCapability`, `SecurityCapabilityRegistry`; `capability_router.py`; `capability_matrix.py`; `src/three_agent/workspace_chat_capabilities.py` | `EXTEND` | Reviewed capability metadata, registry lookup and authority checks exist, but the main registry is security/monitoring-specific rather than a cross-runtime descriptor registry for all tools, programs, agents and providers. | Normalize a runtime descriptor view over existing registries/adapters; preserve existing authority gates and reviewed metadata. |
| `ExecutionPlan` / `ExecutionNode` | `src/three_agent/execution_plan.py` — `ExecutionPlan`, `ExecutionNode`, `ExecutionNodeBinding`, `ExecutionPlanBuilder`; `src/three_agent/workflow_design.py` — bounded node schema, `depends_on`, DAG validation, topological ordering and cycle rejection; `src/three_agent/security_monitoring/operation_plan.py`; `src/three_agent/workflow.py`; `src/three_agent/execution_observation.py` | `KEEP/EXTEND` | P0-3 promotes the existing workflow-design DAG into one deterministic, immutable, non-executing runtime plan bound to canonical `TaskContext`, parent authority, narrowed per-node authority, bounded per-node/aggregate resource budgets, approvals and evidence requirements. P0-4 now binds node outcomes to the exact plan/node fingerprints and evidence requirements. The remaining runtime-wide gap is execution by a separately governed scheduler. | Keep `ExecutionPlan` / `ExecutionNode` canonical. Do not create a second graph format and do not let plan metadata authorize execution. The scheduler must consume this exact plan contract. |
| Scheduler | `src/three_agent/workflow_dispatch.py`; `src/three_agent/worker_pool.py`; `src/three_agent/adaptive_learning_scheduler.py`; `src/three_agent/security_monitoring_scheduler.py`; `src/three_agent/workflow_state_machine.py`; `src/three_agent/execution_budget.py`; `src/three_agent/capability_revocation.py` | `MISSING` | Specialized dispatch, resource routing, persistent budgets, approval checkpoints and revocation exist, but no generic bounded dependency-aware scheduler executes the canonical `ExecutionPlan` and accepts only canonical `ExecutionObservation` results. Existing workflow dispatch/state-machine paths intentionally reject generic joins or remain application-specific. | Add a bounded generic scheduler that reuses persistent task budgets, administrator authorization boundaries, monotonic revocation, existing state/checkpoint primitives and deterministic fan-in. Revalidate plan/task/authority/budget immediately before every dispatch. |
| `Observation` | `src/three_agent/execution_observation.py` — `ExecutionObservation`, `ExecutionObservationBuilder`; `src/three_agent/security_monitoring/contracts.py` — `ObservationRecord`; `src/three_agent/security_monitoring/observation_normalization.py` — `NormalizedObservationEvidence`; `src/three_agent/execution_plan.py` — node evidence requirements | `KEEP/EXTEND` | P0-4 provides one immutable provider-neutral runtime observation contract bound to exact plan/node/task/authority fingerprints, bounded normalized output, timing, status, cost and evidence references. `SUCCEEDED` fails closed until all declared evidence requirements are satisfied; `PARTIAL` remains distinct for incomplete evidence. Remaining work is making the scheduler require this contract for every dispatched node result. | Keep `ExecutionObservation` canonical for generic runtime node outcomes. Domain observation types remain adapters/payloads; scheduler/aggregation must not create a parallel generic result model. |
| `EvidenceRecord` / provenance | `src/three_agent/security_monitoring/normalized_evidence.py`; `src/three_agent/security_monitoring/execution_evidence_adapter.py`; `evidence_lineage.py`; `forensic_evidence.py`; `src/three_agent/benchmark_evidence.py`; `validator_ledger.py`; `evidence_packing.py`; `src/three_agent/execution_observation.py` | `KEEP/EXTEND` | Strong evidence, hashing, lineage and validation primitives already exist. P0-4 adds a narrow adapter that binds existing `NormalizedEvidence` to a canonical execution node only when its task reference equals the `TaskContext` identity fingerprint and its authorization reference equals the node authority fingerprint. Existing DFIR evidence payload/store semantics are not replaced. Remaining work is scheduler/checkpoint/aggregation propagation of stable evidence references. | Reuse existing evidence payloads and custody stores. Normalize only the stable plan/node/observation/evidence linkage; never replace DFIR-specific acquisition, custody or forensic semantics. |
| `Checkpoint` | `src/three_agent/harness_checkpoint.py` — immutable `HarnessCheckpoint`, `HarnessCheckpointStore`; `src/three_agent/security_monitoring/checkpoint.py`; `src/three_agent/workflow_state_machine.py` | `KEEP/EXTEND` | Durable immutable reconstruction anchors and application checkpoint logic already exist. They are not yet bound runtime-wide to canonical `ExecutionPlan` fingerprint, deterministic node state, accepted observation fingerprints and revalidated authority/revocation state on resume. | Keep the harness checkpoint store canonical and extend resume/recovery binding after scheduler normalization. |
| Context / Memory | `src/three_agent/harness_memory.py` — `HarnessEvent`, `MemoryRecord`, `HarnessMemoryStore`; `harness_context_compiler.py`; `harness_context_manifest.py`; `harness_context_rehydration.py`; `context_engine.py`; `knowledge_plane.py` | `KEEP/EXTEND` | Durable event/memory layers, provenance, trust domains and context assembly already exist. `TaskContext` provides versioned references and P0-3/P0-4 bind plan and observation identity to it, but retrieval still needs consistent security-scope-before-semantic-relevance enforcement and stable raw-evidence references. | Preserve immutable memory/evidence semantics; converge retrieval and compression around scoped references and bind resulting manifests into canonical `TaskContext`. |
| Skills / learning / `CandidateSkill` | `src/three_agent/skills.py` — `ApprovedSkillLoader`; `adaptive_learning_contract.py`; `adaptive_learning_admission.py`; `adaptive_learning_promotion.py`; `adaptive_learning_lifecycle.py`; `promotion_gate.py` | `KEEP/EXTEND` | WorkSpace already has instruction-only skill admission, integrity checks, provenance, candidate/experience contracts and promotion gates. Architectural naming and runtime binding are not fully unified. | Keep production self-modification prohibited. Map candidate/promotion contracts to the runtime `CandidateSkill` lifecycle without bypassing security review, tests, benchmark or approval policy. |
| Subagents / `DelegationContract` | `src/three_agent/agents/`; `src/three_agent/handoff_security.py` — `HandoffSecurityMetadata`; evaluator/operator handoff modules; `src/three_agent/capability_authority.py`; `src/three_agent/execution_plan.py`; `src/three_agent/execution_observation.py` | `EXTEND` | Specialist agents, handoff integrity/provenance and canonical child authority derivation exist. P0-3 proves narrowing for execution nodes and P0-4 proves exact node-result/evidence identity, but no single runtime-wide `DelegationContract` binds child `TaskContext`, narrowed authority, budget, evidence requirements and aggregation policy. | Build delegation on canonical `TaskContext`, existing handoff metadata, canonical child authority derivation and canonical observation/evidence output; never allow handoff content or a child model to mint authority. |

## Important non-duplicates

The following source families are complementary and must not be collapsed blindly:

1. `TaskContract` owns immutable task-level policy and budgets.
2. `TaskContext` binds execution identity, purpose, runtime resource projections and versioned context/evidence references; it does not grant authority.
3. `TaskCapabilityAuthority` owns executable capability/resource/effect authorization.
4. `ExecutionPlan` / `ExecutionNode` bind a validated DAG to exact task context, narrowed authority projections, budgets, approvals and evidence requirements; a plan is explicitly non-executing and does not grant permission.
5. `ExecutionObservation` is the canonical generic node-result binding. It records status/timing/output/cost/evidence against exact plan/node/task/authority identity and grants no execution authority.
6. `TrustedRuntimeContext` supplies server-owned runtime facts but grants no authority.
7. `HarnessMemoryStore` and `HarnessCheckpointStore` own durable context/reconstruction state, not execution permission.
8. Security/DFIR evidence modules retain domain-specific acquisition, custody and forensic semantics; `execution_evidence_adapter.py` only binds those existing records to runtime node identity.
9. `ApprovedSkillLoader` admits reviewed procedures only; it is not a general execution capability registry.
10. Workflow design DAG validation, canonical execution planning and canonical observations are not equivalent to an executable scheduler.

## First P0 convergence change — authority narrowing

PR `#365` (`feat(runtime): enforce child authority narrowing`) is the first implementation change produced from this audit.

Exact implementation commit before the audit-document commit:

`42d3c7a289373047f72eb22c18664b3b4da1d6da`

Merge commit on `main`:

`37ff9359ac7ebe83c3032bf3f27c9eb35fb7f009`

It extends the canonical `TaskCapabilityAuthority` rather than creating a second authority abstraction.

### Authority invariant enforcement

`TaskCapabilityAuthority.derive_child(...)` permits a delegated child to preserve or reduce parent authority only:

- child tool set must be a subset of parent tools;
- child source set must be a subset of parent sources;
- child write scope must be equal to or nested inside parent write scope, or `none`;
- child network scope may remain identical or reduce to `deny`;
- sensitivity is inherited exactly and cannot be declassified by delegation;
- transitive delegation cannot regain authority removed by an intermediate child.

Focused tests are in:

`tests/test_runtime_authority_narrowing.py`

## Second P0 convergence change — canonical TaskContext

PR `#366` (`feat(runtime): converge canonical TaskContext`) is the second implementation change from this audit.

Exact implementation commit before its audit-document update:

`b6a618c3b04f806cd76ac689353fe4eff59017e9`

Merge commit on `main`:

`d1e537f9c89673d180740e94e7f46c2f6ba83775`

Implementation:

`src/three_agent/task_context.py`

Focused tests:

`tests/test_task_context.py`

### TaskContext invariants

The canonical binding composes existing primitives instead of replacing them:

- `TaskContract` remains the task-level policy and budget source;
- `CanonicalTaskSpec` remains the canonical compiled-intent binding;
- `TaskCapabilityAuthority` remains the executable authority source;
- `ContextManifest` remains immutable audited context metadata;
- `TaskContext` binds task/session/trace/actor identity, purpose, project, risk class, projected resource budget, inventory scope and fingerprints;
- canonical `TaskContext` metadata stores `intent_sha256`, not another raw prompt copy;
- context/evidence enrichment is append-only through versioned `derive(...)` state;
- derived contexts preserve the same identity fingerprint and retain the previous context fingerprint as parent lineage;
- `ContextManifest` binding fails closed unless project, session, task and authority fingerprint all match;
- `TaskContext` itself grants no tool, filesystem, network, credential, approval or execution authority.

The regression suite covers canonical authority binding, frozen identity, versioned enrichment, successful scoped manifest binding, authority mismatch rejection, deadline validation and malformed reference rejection.

PR `#366` passed all five exact-head PR gates before merge: canonical module, Internet egress security, installer, Windows deployment/runtime smoke and harness CI. Harness Python 3.11 and 3.12 both passed unit tests plus enterprise verification EV-01 through EV-10.

## Third P0 convergence change — canonical ExecutionPlan / ExecutionNode

PR `#367` (`feat(runtime): add canonical ExecutionPlan and ExecutionNode`) is the third implementation change from this audit.

Exact implementation commit before its audit-document update:

`ea6dc0850c23ff7475fbfb605d9b692b599ff9d5`

Final PR head before merge:

`c5a33910218920d04f061433f5c2069b3e566d12`

Merge commit on `main`:

`8fd819eb028acadf881284b919d0aa86c28039f2`

Implementation:

`src/three_agent/execution_plan.py`

Focused tests:

`tests/test_execution_plan.py`

### ExecutionPlan / ExecutionNode invariants

P0-3 extends the existing workflow-design DAG instead of introducing a second graph contract:

- `workflow_design.validate_contract(...)` remains the canonical workflow normalization/validation source;
- `workflow_design._graph(...)` remains the bounded deterministic topology source for dependency validation, topological ordering, execution levels and cycle rejection;
- every plan is bound to the exact canonical `TaskContext` fingerprint and identity fingerprint;
- every plan is bound to the exact parent `TaskCapabilityAuthority` fingerprint;
- every execution node starts from a deny-by-default trusted binding: zero tools, zero sources, `write_scope=none`, `network_scope=deny` and zero resource budget;
- any non-zero node capability is derived only through `TaskCapabilityAuthority.derive_child(...)`, so a node cannot exceed its parent authority;
- each node stores the derived authority projection and fingerprint and can deterministically rebind that authority before future dispatch;
- per-node resource budgets must be subsets of the task budget and aggregate node budgets cannot exceed the task budget;
- workflow risk cannot underclassify the canonical task risk;
- approval semantics are fail-closed: workflow approval, approval node kind, human-approval action or trusted binding may require approval, while no plan input may weaken an existing approval requirement;
- evidence requirements are bounded trusted metadata consumed by P0-4;
- plan and node fingerprints are deterministic canonical SHA-256 bindings;
- `ExecutionPlan.execution_authorized` is immutable `False` and `execution_mode` is immutable `plan_only`; node canonical metadata also records `execution_authorized=false`;
- scheduler/dispatch is intentionally separate from the plan contract.

The focused regression suite covers deterministic fingerprints, exact TaskContext/authority binding, child-authority escalation rejection, reuse of existing cycle validation, per-node and aggregate budget rejection, approval fail-closed behavior, task-risk underclassification rejection and deterministic authority rebinding.

Final PR head `c5a33910218920d04f061433f5c2069b3e566d12` passed all five core PR gates before merge: canonical module, Internet egress security, installer, Windows deployment/runtime smoke and harness CI.

## Fourth P0 convergence change — canonical Observation / Evidence binding

PR `#369` (`feat(runtime): bind execution observations to evidence`) is the fourth implementation change from this audit.

Initial implementation commit:

`690f95af75c6d987fd8b1eaa2f89fb78d65ca953`

The branch was then synchronized with the current `main` through a non-force two-parent merge commit carrying PR `#368`'s benchmark-contract correction:

`ff477211bffff8d8da541dfa73b16e73d0798ef5`

Implementations:

- `src/three_agent/execution_observation.py`
- `src/three_agent/security_monitoring/execution_evidence_adapter.py`

Focused tests:

`tests/test_execution_observation.py`

### Observation / Evidence invariants

P0-4 adds a generic runtime result boundary without replacing domain evidence systems:

- every observation is immutable and bound to the exact `ExecutionPlan` fingerprint, `ExecutionNode` fingerprint, task-context fingerprint/identity and node authority fingerprint;
- normalized output is bounded and canonicalized before hashing, preventing an unbounded provider payload from becoming the runtime contract;
- observation status, timing, normalized output, cost, evidence references and error class are part of the deterministic fingerprint;
- `SUCCEEDED` is fail-closed unless every trusted evidence requirement declared by the execution node has been satisfied;
- `PARTIAL` is a distinct first-class state for an incomplete result/evidence set and is not silently upgraded to success;
- observed resource cost must remain within the execution node's trusted resource budget;
- plan/task/authority identity is revalidated before an observation is accepted, including exact child-authority rebinding to the parent authority;
- an observation, provider payload or evidence record cannot mint, widen or restore authority;
- the security adapter accepts existing `NormalizedEvidence` only when `task_ref_sha256` exactly matches the canonical `TaskContext` identity fingerprint and `authorization_ref_sha256` exactly matches the node authority fingerprint;
- unknown or unsatisfied evidence requirements fail closed;
- existing DFIR evidence acquisition, custody, hashing and storage remain canonical; P0-4 only adds a runtime binding adapter rather than a second evidence store;
- deterministic observation/evidence fingerprints provide stable tamper-detection and future checkpoint/fan-in references.

The implementation-head regression suite covers exact plan/node/task/authority identity, deterministic fingerprints, evidence requirement enforcement, partial/success semantics, budget enforcement and normalized DFIR evidence binding.

Exact synchronized head `ff477211bffff8d8da541dfa73b16e73d0798ef5` passed canonical-module CI, Internet-egress-security CI, installer CI, Windows deployment/runtime smoke CI, harness CI and portable-deploy CI. The push-triggered `canonical-autoheal-safe` workflow also passed its strict canonical census, source compilation and full repository regression suite on that exact head before this documentation update.

## P0 sequence after Observation / Evidence

The convergence order remains dependency-driven:

1. Authority narrowing — implemented and merged in PR `#365`.
2. Canonical `TaskContext` — implemented and merged in PR `#366`.
3. Canonical `ExecutionPlan` / `ExecutionNode` — implemented and merged in PR `#367`.
4. Canonical `ExecutionObservation` / Evidence binding — implemented in PR `#369`; merge only after the resulting documentation-head CI is green.
5. Add a bounded dependency-aware scheduler with deterministic fan-in, cancellation/revocation and authority/budget revalidation.
6. Bind checkpoints/recovery to plan fingerprint, deterministic execution-node state, accepted observation fingerprints and current authority/revocation state.
7. Run integration/security/regression convergence and benchmark the normalized path before expanding into P1/P2/P3 features.

## Security conclusion

The source audit does not support creating a new independent `runtime/`, `security/`, `context/`, `skills/`, or `evidence/` implementation tree as the default strategy. WorkSpace already contains substantial canonical primitives in those areas.

The safe convergence strategy is:

`existing canonical primitive -> normalize/extend contract -> bind at runtime boundary -> regression tests -> CI evidence`

This preserves the central architecture rule: the model may propose reasoning and work, but WorkSpace runtime authority, state, capabilities, evidence and execution policy remain outside model control.
