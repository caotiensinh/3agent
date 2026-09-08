# WorkSpace Agent Runtime Source Convergence Audit

Status: normative implementation audit for the WorkSpace-native agent runtime.

## Baseline

- Repository: `caotiensinh/3agent`
- Original audited `main`: `3a13b9680a57b82cff503633111d0cfd7691c4d2`
- Runtime architecture source: `docs/WORKSPACE_AGENT_RUNTIME_ARCHITECTURE.md`
- Architecture PR: `#363`
- P0-1 authority narrowing: PR `#365`, merge commit `37ff9359ac7ebe83c3032bf3f27c9eb35fb7f009`
- P0-2 canonical `TaskContext`: PR `#366`, merge commit `d1e537f9c89673d180740e94e7f46c2f6ba83775`
- P0-3 canonical `ExecutionPlan` / `ExecutionNode`: PR `#367`, merge commit `8fd819eb028acadf881284b919d0aa86c28039f2`
- P0-4 canonical `ExecutionObservation` / Evidence binding: PR `#369`, merge commit `83602591dba8772abab4fe1ab60924137c755994`
- Current P0-5 candidate: PR `#370`, bounded dependency-aware scheduler
- P0-5 exact code head before this documentation update: `45781d7b97ed1dd3273cc5c6157b98b944436396`
- Audit rule: extend canonical source first; do not create parallel runtime abstractions when equivalent primitives already exist.

The architecture is treated as a convergence target over the existing WorkSpace source tree, not as permission to build a second runtime implementation tree.

## Classification

- `KEEP`: implementation already satisfies the core role and remains canonical.
- `EXTEND`: canonical implementation exists but still has bounded integration gaps.
- `REFACTOR`: useful implementation exists but responsibilities need normalization before runtime-wide use.
- `MISSING`: no runtime-wide implementation matching the required responsibility was found.
- `DEPRECATED/DUPLICATE`: parallel implementation that must not become another source of truth.

## Convergence matrix

| Runtime area | Existing source evidence | Status | Current result / remaining gap | Required action |
| --- | --- | --- | --- | --- |
| `TaskContext` | `src/three_agent/task_context.py`; `task_contract.py`; `harness_task_compiler.py`; `harness_context_manifest.py`; `trusted_runtime_context.py`; `execution_observation.py` | `KEEP/EXTEND` | P0-2 created one immutable runtime identity/context binding. P0-3 binds plans to it; P0-4 binds node observations to it; P0-5 consumes those exact plan/observation bindings instead of creating scheduler-local task metadata. Remaining work is checkpoint/resume and delegation wiring. | Keep `TaskContext` canonical. Context text must never become authority. |
| `AuthorityEnvelope` | `src/three_agent/capability_authority.py`; `model_authority.py`; `capability_revocation.py`; `execution_plan.py`; `execution_observation.py`; `execution_scheduler.py` | `KEEP/EXTEND` | P0-1 proves `child_authority <= parent_authority`. P0-3 binds each node to derived child authority. P0-4 rebinds it when accepting observations. P0-5 revalidates the full plan plus each node's exact child authority immediately before dispatch and checks monotonic capability revocation. | Keep `TaskCapabilityAuthority` and `TaskCapabilityRevocationStore` canonical. Resume and provider adapters must repeat the same current-authority/revocation checks. |
| Capability registry / `CapabilityDescriptor` | `src/three_agent/security_monitoring/capability_registry.py`; `capability_router.py`; `capability_matrix.py`; `workspace_chat_capabilities.py` | `EXTEND` | Reviewed capability metadata and authority-aware routing exist but remain domain-oriented. | Normalize a cross-runtime descriptor view only when required by provider adapters; do not replace reviewed registries. |
| `ExecutionPlan` / `ExecutionNode` | `src/three_agent/execution_plan.py`; `workflow_design.py`; `security_monitoring/operation_plan.py`; `workflow.py` | `KEEP/EXTEND` | P0-3 promotes the existing workflow-design DAG into an immutable, deterministic, non-executing runtime plan bound to `TaskContext`, narrowed authority, bounded budgets, approvals and evidence requirements. P0-5 now consumes this exact graph. | Keep the plan canonical and non-authorizing. Resource-lock/retry policy belongs at governed dispatch/executor boundaries rather than in a second graph format. |
| Scheduler | `src/three_agent/execution_scheduler.py`; `execution_budget.py`; `capability_revocation.py`; `workflow_dispatch.py`; `worker_pool.py`; `workflow_state_machine.py` | `KEEP/EXTEND` | P0-5 adds the missing provider-neutral dependency scheduler control core. It computes a deterministic bounded ready set, issues immutable dispatch tickets only after current plan/authority/budget/revocation/dependency/approval validation, accepts only canonical in-flight observations, preserves declared dependency order for deterministic fan-in, applies backpressure, and stops new dispatch after cancellation. Remaining bounded gaps are provider/resource locks, safe retry/timeout adapters and durable checkpoint/resume binding. | Keep `ExecutionScheduler` as the control core. Reuse existing provider dispatch, worker pool, persistent budget, revocation and checkpoint primitives; do not turn the scheduler into another provider executor. |
| `Observation` | `src/three_agent/execution_observation.py`; `security_monitoring/contracts.py`; `observation_normalization.py`; `execution_scheduler.py` | `KEEP/EXTEND` | P0-4 provides the canonical generic node-result contract. P0-5 requires that exact type for scheduler acceptance; `PARTIAL`, `FAILED` and `CANCELLED` cannot satisfy downstream dependencies. | Keep `ExecutionObservation` canonical and propagate its fingerprints into checkpoints/aggregation. |
| `EvidenceRecord` / provenance | `security_monitoring/normalized_evidence.py`; `security_monitoring/execution_evidence_adapter.py`; `evidence_lineage.py`; `forensic_evidence.py`; `benchmark_evidence.py`; `validator_ledger.py`; `execution_observation.py` | `KEEP/EXTEND` | P0-4 binds existing normalized DFIR evidence to exact task/node authority identity without replacing evidence stores. P0-5 preserves canonical observation fingerprints through deterministic fan-in. | Reuse existing custody/evidence stores and carry stable observation/evidence references into checkpoint/resume. |
| `Checkpoint` | `src/three_agent/harness_checkpoint.py`; `security_monitoring/checkpoint.py`; `workflow_state_machine.py`; `execution_scheduler.py` | `KEEP/EXTEND` | Immutable reconstruction primitives already exist. P0-5 exposes deterministic scheduler control state through `snapshot()`, but no runtime-wide checkpoint contract yet binds plan fingerprint, dispatch sequence, in-flight tickets, accepted observation fingerprints, current authority and revocation state. | P0-6 should bind the scheduler snapshot to canonical checkpoint storage and fail closed on stale authority, revocation, budget or plan state during resume. |
| Context / Memory | `harness_memory.py`; `harness_context_compiler.py`; `harness_context_manifest.py`; `harness_context_rehydration.py`; `context_engine.py`; `knowledge_plane.py` | `KEEP/EXTEND` | Durable event/memory layers already exist; canonical task/plan/observation/scheduler identity is now available for stable references. | Preserve immutable provenance and enforce security scope before semantic relevance. |
| Skills / learning / `CandidateSkill` | `skills.py`; `adaptive_learning_contract.py`; `adaptive_learning_admission.py`; `adaptive_learning_promotion.py`; `adaptive_learning_lifecycle.py`; `promotion_gate.py` | `KEEP/EXTEND` | Instruction-only skill admission, integrity/provenance and promotion gates already exist. | Keep production self-modification prohibited; never bypass review/tests/benchmark/approval. |
| Subagents / `DelegationContract` | `src/three_agent/agents/`; `handoff_security.py`; `capability_authority.py`; `execution_plan.py`; `execution_observation.py`; `execution_scheduler.py` | `EXTEND` | Handoff integrity and child authority primitives exist; scheduler enforces exact node authority/observation identity but there is still no single runtime-wide delegation contract tying child `TaskContext`, narrowed authority, budget and aggregation policy together. | Build future delegation on the canonical contracts; child content must never mint authority. |

## Important non-duplicates

The following source families are complementary and must not be collapsed blindly:

1. `TaskContract` owns immutable task-level policy and budgets.
2. `TaskContext` binds execution identity, purpose, resource projections and versioned context/evidence references; it grants no authority.
3. `TaskCapabilityAuthority` owns executable capability/resource/effect authorization.
4. `ExecutionPlan` / `ExecutionNode` bind a validated DAG to exact task context, narrowed authority projections, budgets, approvals and evidence requirements; the plan itself is non-executing.
5. `ExecutionScheduler` owns bounded dependency-ready scheduling and dispatch receipts; it does not execute a provider and cannot widen node authority.
6. `ExecutionObservation` is the canonical generic node-result binding and grants no execution authority.
7. `TaskExecutionBudgetState` remains the persistent atomic task budget/deadline authority; the scheduler consumes it through its existing interface.
8. `TaskCapabilityRevocationStore` remains the monotonic revocation source; the scheduler consumes it through its existing interface.
9. `WorkflowDispatchController` and worker/provider pools remain specialized execution adapters; they are not replaced by the generic scheduler.
10. `HarnessMemoryStore` and `HarnessCheckpointStore` own durable context/reconstruction state, not execution permission.
11. Security/DFIR evidence modules retain domain acquisition, custody and forensic semantics; runtime adapters only bind them to canonical execution identity.
12. `ApprovedSkillLoader` admits reviewed procedures only; it is not a general execution capability registry.

## P0-1 — authority narrowing

PR `#365` extended the canonical `TaskCapabilityAuthority` instead of creating a second authority abstraction.

Implementation commit:

`42d3c7a289373047f72eb22c18664b3b4da1d6da`

Merge commit:

`37ff9359ac7ebe83c3032bf3f27c9eb35fb7f009`

Core invariant: delegated children may preserve or reduce parent authority only. Tool/source sets must be subsets, write/network scope cannot widen, sensitivity cannot be declassified, and transitive delegation cannot regain removed authority.

Focused tests: `tests/test_runtime_authority_narrowing.py`.

## P0-2 — canonical TaskContext

PR `#366` introduced `src/three_agent/task_context.py` as the canonical runtime identity/context binding over existing task, authority and manifest primitives.

Implementation commit:

`b6a618c3b04f806cd76ac689353fe4eff59017e9`

Merge commit:

`d1e537f9c89673d180740e94e7f46c2f6ba83775`

Core invariants include immutable task/session/trace/actor identity, stable identity fingerprint, versioned append-only context/evidence references, exact authority/manifest binding, bounded resource projections and no tool/filesystem/network/credential/approval/execution authority granted by context itself.

Focused tests: `tests/test_task_context.py`.

## P0-3 — canonical ExecutionPlan / ExecutionNode

PR `#367` introduced `src/three_agent/execution_plan.py` by extending the existing `workflow_design` DAG rather than inventing another graph.

Implementation commit:

`ea6dc0850c23ff7475fbfb605d9b692b599ff9d5`

Final PR head:

`c5a33910218920d04f061433f5c2069b3e566d12`

Merge commit:

`8fd819eb028acadf881284b919d0aa86c28039f2`

Core invariants:

- exact canonical `TaskContext` and parent-authority binding;
- deterministic bounded DAG/topology reuse;
- deny-by-default node bindings;
- node authority derived only by `derive_child(...)`;
- per-node and aggregate resource budgets cannot exceed task budget;
- approval semantics fail closed;
- evidence requirements are trusted bounded metadata;
- deterministic plan/node fingerprints;
- `ExecutionPlan.execution_authorized == False` and `execution_mode == "plan_only"`.

Focused tests: `tests/test_execution_plan.py`.

## P0-4 — canonical Observation / Evidence binding

PR `#369` introduced:

- `src/three_agent/execution_observation.py`
- `src/three_agent/security_monitoring/execution_evidence_adapter.py`
- `tests/test_execution_observation.py`

Initial implementation commit:

`690f95af75c6d987fd8b1eaa2f89fb78d65ca953`

Synchronized pre-documentation head after incorporating PR `#368` benchmark-contract correction:

`ff477211bffff8d8da541dfa73b16e73d0798ef5`

Final documentation head:

`926e00eac899d6c785ffafe95e62b2d8c7684bb4`

Merge commit:

`83602591dba8772abab4fe1ab60924137c755994`

Core invariants:

- every observation is bound to exact plan/node/task/authority fingerprints;
- normalized output and cost are bounded/canonicalized;
- `SUCCEEDED` fails closed until all trusted evidence requirements are satisfied;
- `PARTIAL` remains a distinct first-class state;
- observation acceptance revalidates plan/task/authority identity;
- evidence/provider content cannot mint or widen authority;
- existing `NormalizedEvidence` is accepted only when task and authorization references match the canonical execution identity exactly;
- DFIR evidence acquisition/custody/storage remains canonical and is not replaced.

The final PR head passed all five core gates, portable deployment CI and `canonical-autoheal-safe` before merge.

## P0-5 — bounded dependency-aware scheduler

PR `#370` adds:

- `src/three_agent/execution_scheduler.py`
- `tests/test_execution_scheduler.py`

Exact code head before this documentation update:

`45781d7b97ed1dd3273cc5c6157b98b944436396`

### Scheduler role

`ExecutionScheduler` is a provider-neutral control core. It does not invoke a model, tool, subprocess or provider directly. Instead it issues an immutable `DispatchTicket` only after the current runtime state proves that a canonical node is safe to dispatch. Provider/resource-specific execution remains behind existing adapters such as `WorkflowDispatchController`, worker pools and capability routers.

### Scheduler invariants

- constructor revalidates the exact canonical `ExecutionPlan` against the current parent authority;
- maximum scheduler concurrency is bounded (`1..24`);
- the ready set is deterministic over canonical plan order and bounded by remaining in-flight capacity;
- a node is ready only after every declared dependency has a canonical `SUCCEEDED` observation;
- `PARTIAL`, `FAILED` and `CANCELLED` are never silently treated as dependency success;
- deterministic fan-in follows the node's declared `depends_on` order rather than completion timing;
- approval-required nodes fail closed unless explicit trusted approval is supplied at dispatch;
- immediately before every dispatch, the scheduler revalidates the plan, rebinds the exact child authority fingerprint, checks the persistent task budget/deadline and checks monotonic revocation for every node capability;
- a revoked capability blocks dispatch; the scheduler never silently mutates the node's planned authority to make execution appear valid;
- one persistent task step is reserved through the existing budget interface per issued dispatch;
- `DispatchTicket` binds task, plan, node, authority, dependency-observation fingerprints, dispatch sequence and execution level and is deterministically fingerprinted;
- only an exact canonical `ExecutionObservation` for a currently in-flight node may satisfy that node;
- duplicate or unsolicited observations fail closed;
- backpressure rejects dispatch when the bounded in-flight capacity is exhausted;
- scheduler cancellation stops all new dispatch while still allowing already in-flight observations to be recorded for audit;
- `snapshot()` exposes deterministic control state for the next checkpoint/resume convergence step;
- the scheduler does not restore revoked capabilities, mint authority, bypass approvals or replace provider-specific resource governance.

### Focused regression coverage

`tests/test_execution_scheduler.py` covers:

1. deterministic dependency-aware ready ordering and bounded fan-out;
2. deterministic fan-in independent of completion order;
3. downstream blocking for `PARTIAL`, `FAILED` and `CANCELLED` dependencies;
4. capability revocation after planning but before dispatch;
5. persistent budget/deadline revalidation;
6. approval fail-closed behavior at dispatch;
7. exact in-flight canonical observation binding and duplicate rejection;
8. cancellation with retained in-flight audit result;
9. duplicate dispatch rejection and concurrency backpressure.

Exact code head `45781d7b97ed1dd3273cc5c6157b98b944436396` passed the five core PR gates before this documentation update: canonical-module CI, Internet-egress-security CI, installer CI, Windows deployment/runtime smoke CI and harness CI. Harness passed unit tests plus enterprise verification EV-01 through EV-10 on both Python 3.11 and Python 3.12.

## Remaining P0 sequence

The remaining convergence order is dependency-driven:

1. Authority narrowing — merged in PR `#365`.
2. Canonical `TaskContext` — merged in PR `#366`.
3. Canonical `ExecutionPlan` / `ExecutionNode` — merged in PR `#367`.
4. Canonical `ExecutionObservation` / Evidence binding — merged in PR `#369`.
5. Bounded dependency-aware scheduler — implemented in PR `#370`; merge only after the resulting documentation-head CI and autoheal are green.
6. Bind canonical checkpoint/resume to plan fingerprint, deterministic scheduler snapshot, accepted observation fingerprints, current authority, revocation and budget/deadline state.
7. Close remaining provider/resource-lock, timeout and safe-retry integration gaps without creating a second scheduler or provider framework.
8. Run final integration/security/regression convergence and benchmark the normalized runtime path.

## Security conclusion

The source audit does not support creating a new independent `runtime/`, `security/`, `context/`, `skills/`, or `evidence/` implementation tree as the default strategy. WorkSpace already contains substantial canonical primitives in those areas.

The safe convergence strategy remains:

`existing canonical primitive -> normalize/extend contract -> bind at runtime boundary -> regression tests -> CI evidence`

The central runtime rule remains unchanged: the model may propose reasoning and work, but WorkSpace runtime authority, state, capabilities, scheduling, evidence and execution policy remain outside model control.
