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
- P0-5 bounded dependency-aware scheduling and dispatch: PR `#370`, merge commit `6d8e97ce9dc1382b4d8146884f82deb9ac7ec127`
- Current P0-6 candidate: PR `#378`, dispatch-state checkpoint/recovery binding
- Latest synchronized `main` parent for P0-6: `6d8e97ce9dc1382b4d8146884f82deb9ac7ec127`
- Latest P0-6 code/test head before this documentation update: `08ce86aca704d773b92c0883f7965ade5476e622`
- Audit rule: extend canonical source first; never create parallel runtime abstractions when equivalent primitives already exist.

The architecture is a convergence target over the existing WorkSpace source tree, not permission to build a second runtime implementation tree.

## Classification

- `KEEP`: implementation already satisfies the core role and remains canonical.
- `EXTEND`: canonical implementation exists but still has bounded integration gaps.
- `REFACTOR`: useful implementation exists but responsibilities need normalization before runtime-wide use.
- `MISSING`: no runtime-wide implementation matching the required responsibility was found.
- `DEPRECATED/DUPLICATE`: parallel implementation that must not become another source of truth.

## Convergence matrix

| Runtime area | Existing canonical source | Status | Current result / remaining gap | Required action |
| --- | --- | --- | --- | --- |
| `TaskContext` | `task_context.py`; `task_contract.py`; `harness_task_compiler.py`; `harness_context_manifest.py` | `KEEP/EXTEND` | One immutable task/session/trace/actor runtime binding. Plans, observations, schedulers, canonical runtime checkpoints and P0-6 dispatch-recovery bindings consume exact context fingerprints. Remaining work is runtime-wide delegation wiring. | Keep `TaskContext` canonical; context text never grants authority. |
| Authority | `capability_authority.py`; `capability_revocation.py`; `model_authority.py` | `KEEP/EXTEND` | Child authority narrowing is canonical. Plan nodes bind exact narrowed authority. Dispatch revalidates authority and monotonic revocation immediately before execution admission. Canonical recovery verifies the parent-authority fingerprint, and P0-6 recovery binds/revalidates monotonic revocation state without allowing rollback. | Revalidate executable authority again at provider/action boundaries; a checkpoint never freezes future permission. |
| `ExecutionPlan` / `ExecutionNode` | `execution_plan.py`; `workflow_design.py` | `KEEP/EXTEND` | One deterministic immutable DAG bound to task context, authority, budgets, approvals and evidence requirements. It remains non-executing. Runtime checkpoints and dispatch-recovery bindings preserve the exact plan fingerprint. | Keep plan metadata non-authorizing; do not create another graph format. |
| Scheduler admission | `runtime_scheduler.py` | `KEEP/EXTEND` | `RuntimeScheduler` is the canonical pure deterministic evaluator for DAG readiness, dependency propagation, approval admission and terminal-state projection. It validates task context, plan, authority and canonical observations and returns immutable scheduling decisions without mutating runtime state. `RuntimeRecovery` reconstructs inputs and recomputes this decision instead of persisting hidden readiness logic. | Keep this evaluator side-effect free and reusable by dispatch and recovery. |
| Dispatch coordination | `execution_scheduler.py`; `execution_budget.py`; `capability_revocation.py`; `runtime_dispatch_recovery.py` | `KEEP/EXTEND` | P0-5 `ExecutionScheduler` consumes `RuntimeScheduler` as its readiness/admission source of truth. P0-6 binds its deterministic snapshot to the exact canonical checkpoint together with persistent budget/deadline and monotonic revocation state. Ambiguous in-flight work never auto-replays. | Keep provider execution outside this coordinator. Remaining gaps: resource locks, timeout/safe-retry adapters, and durable persistence wiring for the P0-6 recovery envelope. |
| Observation | `execution_observation.py`; domain observation adapters | `KEEP/EXTEND` | Canonical provider-neutral node outcome with exact task/plan/node/authority binding. Non-success states never silently satisfy dependencies. Stable observation fingerprints are bound into canonical runtime checkpoints and cross-checked against the dispatch-recovery snapshot. | Keep observation fingerprints canonical; do not infer missing in-flight outcomes during recovery. |
| Evidence / provenance | `security_monitoring/normalized_evidence.py`; `security_monitoring/execution_evidence_adapter.py`; evidence/custody modules | `KEEP/EXTEND` | Existing DFIR evidence remains canonical; runtime adapter only binds evidence to exact execution identity. | Reuse custody stores; do not replace domain evidence semantics. |
| Checkpoint / recovery | `runtime_checkpoint.py`; `runtime_dispatch_recovery.py`; `harness_checkpoint.py`; `harness_context_rehydration.py`; `workflow_state_machine.py` | `KEEP/EXTEND` | Canonical `RuntimeCheckpoint` binds exact task/context identity, plan, parent authority, scheduling decision, approvals and accepted observation fingerprints. `RuntimeRecovery` remains the non-executing canonical reconstruction evaluator. P0-6 adds a separate immutable binding for transient scheduler snapshot, persistent budget/deadline and monotonic revocations; budget rollback or revocation rollback fails closed, cancellation stays blocked, and any checkpointed in-flight dispatch forces manual reconciliation. | Preserve `RuntimeCheckpoint` / `RuntimeRecovery` as canonical. Persist/adapt the P0-6 envelope around them; never create a replay scheduler or infer success for ambiguous work. |
| Context / Memory | `harness_memory.py`; context compiler/manifest/rehydration modules | `KEEP/EXTEND` | Durable provenance-aware context primitives exist. | Security scope must be enforced before semantic relevance. |
| Skills / learning | `skills.py`; `candidate_skill.py`; `candidate_skill_validation.py`; adaptive-learning admission/evaluation/promotion modules; `skill_catalog.py` | `KEEP/EXTEND` | Reviewed skill admission, progressive disclosure and controlled CandidateSkill lifecycle primitives exist. | Production self-modification remains prohibited; promotion requires evidence, tests, review and policy approval. |
| Subagents / delegation | agent/handoff modules; authority/plan/observation contracts | `EXTEND` | Handoff integrity and child authority exist, but one runtime-wide delegation contract is still missing. | Future delegation must bind child `TaskContext`, narrowed authority, budget, evidence and aggregation policy. |

## Canonical scheduler split

The repository contains two scheduler-named modules with intentionally different responsibilities. They are complementary, not competing implementations.

### `RuntimeScheduler` — pure admission evaluator

`src/three_agent/runtime_scheduler.py` is the canonical source of truth for pure scheduling decisions:

- validates exact `TaskContext`, `ExecutionPlan` and parent authority;
- validates canonical observations before using them as dependency state;
- deterministically projects READY / WAITING / BLOCKED / terminal node states;
- handles dependency failure propagation and explicit approval admission;
- returns immutable fingerprinted decisions;
- performs no provider call, budget mutation, dispatch mutation, retry, lock acquisition or checkpoint write.

### `ExecutionScheduler` — stateful dispatch coordinator

`src/three_agent/execution_scheduler.py` consumes `RuntimeScheduler.evaluate(...)` instead of independently reimplementing readiness logic. It adds only runtime state/control responsibilities that the pure evaluator deliberately does not own:

- bounded in-flight concurrency and backpressure;
- immutable `DispatchTicket` generation;
- deterministic dependency-observation fan-in;
- persistent budget/deadline revalidation and atomic step reservation;
- live monotonic capability-revocation checks;
- exact node authority rebinding immediately before dispatch;
- cancellation of future dispatch while retaining in-flight audit results;
- admission of only exact canonical observations for currently in-flight nodes;
- deterministic scheduler snapshot for durable transient-state binding.

The scheduler snapshot is reconstruction evidence, not a new authority source and not a replacement for the canonical `RuntimeCheckpoint` contract.

This split prevents a second readiness implementation while preserving separation between pure decision logic and stateful execution control.

## Canonical checkpoint / recovery split

`src/three_agent/runtime_checkpoint.py` provides the canonical provider-neutral runtime checkpoint/recovery contract without becoming another scheduler or execution mechanism.

### `RuntimeCheckpoint`

The canonical checkpoint binds:

- task ID;
- exact `TaskContext` fingerprint and identity fingerprint;
- exact `ExecutionPlan` fingerprint;
- parent-authority fingerprint;
- recomputed `RuntimeScheduler` decision fingerprint;
- normalized approved node IDs;
- validated canonical observation fingerprints;
- normalized capture timestamp;
- deterministic checkpoint identity and SHA-256 integrity envelope.

The builder revalidates `TaskContext`, plan, parent authority and every observation before creating the checkpoint.

### `RuntimeRecovery`

Recovery is fail-closed and non-executing:

- exact task/context/plan/authority identity must still match;
- the supplied observation set must exactly match the checkpointed fingerprints;
- `RuntimeScheduler` is recomputed from canonical inputs and its fingerprint must match the checkpoint;
- `PARTIAL` observations return `MANUAL_RECONCILIATION` and are never auto-replayed;
- completed or blocked scheduling state is preserved explicitly;
- otherwise recovery returns `RECOVERABLE` with no execution performed.

### `RuntimeDispatchRecoveryBinding` / `RuntimeDispatchRecovery`

P0-6 adds `src/three_agent/runtime_dispatch_recovery.py` beside the canonical checkpoint instead of changing `workspace-runtime-checkpoint/v1`.

The binding records deterministic reconstruction evidence for:

- exact canonical runtime-checkpoint fingerprint;
- task-context, plan and parent-authority fingerprints;
- deterministic `ExecutionScheduler.snapshot()` fingerprint;
- bounded scheduler concurrency, cancellation and dispatch sequence;
- approved node IDs;
- in-flight dispatch-ticket fingerprints;
- accepted observation fingerprints;
- persistent task budget limits, deadline and consumed counters;
- monotonic capability-revocation records;
- deterministic integrity-checked envelope identity.

Recovery remains fail-closed and non-executing:

- the underlying `RuntimeRecovery` decision must still validate;
- scheduler/checkpoint task, context, plan, authority, approvals and observations must match exactly;
- immutable budget limits/deadline must not change;
- live budget counters may advance but may never roll back;
- historical capability revocations may never disappear; newly revoked capabilities remain visible to the decision;
- an already cancelled scheduler remains `BLOCKED`;
- any checkpointed in-flight ticket produces `MANUAL_RECONCILIATION` rather than a retry/replay;
- no recovery method issues a dispatch ticket, invokes a provider or grants authority.

A checkpoint proves reconstruction identity; it does not mint execution permission. P0-6 extends reconstruction evidence without weakening that rule.

Focused coverage exists in `tests/test_runtime_checkpoint.py`, `tests/test_runtime_dispatch_recovery.py` and `tests/test_runtime_p0_convergence.py`.

## Important non-duplicates

1. `TaskContract` owns immutable task-level policy and budgets.
2. `TaskContext` binds runtime identity and references; it grants no authority.
3. `TaskCapabilityAuthority` owns executable authority.
4. `ExecutionPlan` / `ExecutionNode` own the validated non-executing DAG and narrowed node bindings.
5. `RuntimeScheduler` owns pure deterministic scheduling/admission evaluation.
6. `ExecutionScheduler` owns stateful dispatch coordination and consumes `RuntimeScheduler` decisions.
7. `ExecutionObservation` owns canonical generic node-result binding and grants no authority.
8. `RuntimeCheckpoint` / `RuntimeRecovery` own canonical runtime reconstruction identity and fail-closed recovery admission; they never execute or replay work.
9. `RuntimeDispatchRecoveryBinding` / `RuntimeDispatchRecovery` bind transient dispatch/budget/revocation reconstruction evidence to the exact canonical checkpoint; they do not replace it and never replay work.
10. `TaskExecutionBudgetState` remains persistent atomic budget/deadline authority.
11. `TaskCapabilityRevocationStore` remains the monotonic revocation source.
12. `WorkflowDispatchController`, worker pools and provider adapters remain specialized execution mechanisms.
13. `HarnessCheckpointStore` and `HarnessMemoryStore` remain durable storage/context primitives; they do not replace runtime recovery identity and do not grant execution permission.
14. Security/DFIR evidence modules retain acquisition, custody and forensic semantics.
15. `ApprovedSkillLoader`, `ApprovedSkillCatalog` and CandidateSkill lifecycle modules expose reviewed procedural knowledge/lifecycle state but never grant runtime capability authority.

## P0-1 — authority narrowing

PR `#365` extended `TaskCapabilityAuthority` with fail-closed child derivation. A child can preserve or reduce parent tools, sources, write/network scope and sensitivity only; transitive delegation cannot regain removed authority.

Implementation commit: `42d3c7a289373047f72eb22c18664b3b4da1d6da`  
Merge commit: `37ff9359ac7ebe83c3032bf3f27c9eb35fb7f009`  
Focused tests: `tests/test_runtime_authority_narrowing.py`.

## P0-2 — canonical TaskContext

PR `#366` introduced `src/three_agent/task_context.py` as the canonical immutable runtime identity/context binding over existing task, authority and manifest primitives. It stores stable fingerprints and versioned context/evidence refs but grants no tool, filesystem, network, credential, approval or execution authority.

Implementation commit: `b6a618c3b04f806cd76ac689353fe4eff59017e9`  
Merge commit: `d1e537f9c89673d180740e94e7f46c2f6ba83775`  
Focused tests: `tests/test_task_context.py`.

## P0-3 — canonical ExecutionPlan / ExecutionNode

PR `#367` extended the existing workflow-design DAG into the canonical non-executing runtime plan. Nodes use deny-by-default bindings and authority derived only through `derive_child(...)`; per-node and aggregate budgets cannot exceed the task budget; approvals and evidence requirements fail closed.

Implementation commit: `ea6dc0850c23ff7475fbfb605d9b692b599ff9d5`  
Final PR head: `c5a33910218920d04f061433f5c2069b3e566d12`  
Merge commit: `8fd819eb028acadf881284b919d0aa86c28039f2`  
Focused tests: `tests/test_execution_plan.py`.

## P0-4 — canonical Observation / Evidence binding

PR `#369` introduced canonical provider-neutral observations and a narrow adapter to existing normalized DFIR evidence. Every observation is bound to exact plan/node/task/authority identity; `SUCCEEDED` fails closed until trusted evidence requirements are met; evidence/provider content cannot mint or widen authority.

Initial implementation commit: `690f95af75c6d987fd8b1eaa2f89fb78d65ca953`  
Final documentation head: `926e00eac899d6c785ffafe95e62b2d8c7684bb4`  
Merge commit: `83602591dba8772abab4fe1ab60924137c755994`  
Focused tests: `tests/test_execution_observation.py`.

## P0-5 — bounded dependency-aware scheduling and dispatch

PR `#370` converged the scheduler path around:

- canonical pure evaluator: `src/three_agent/runtime_scheduler.py`;
- stateful dispatch coordinator: `src/three_agent/execution_scheduler.py`;
- pure evaluator tests: `tests/test_runtime_scheduler.py`;
- dispatch coordinator tests: `tests/test_execution_scheduler.py`.

Previous synchronization merge carrying the first concurrent scheduler baseline into P0-5: `5666c904488b35bd374265521f5999d0a4822248`.

Synchronization with `main=5e4cae128486d29fba43065d9bebb95dffd69b14`: `8b8907763a2283ae91a3664e3513bff09ee68918`.

Final pre-documentation synchronization with `main=bbb2de7c0d31424d953c4476d6231a9352e0625e`: `37cf0f90f35133965fb5f5ce8ab6fc1f586e855c`.

Final PR head: `90dea8d1da9240db709459cb5e8c8fb6afbfe168`.  
Merge commit: `6d8e97ce9dc1382b4d8146884f82deb9ac7ec127`.

### P0-5 invariants

- one canonical source of truth for readiness/dependency/approval admission: `RuntimeScheduler`;
- `ExecutionScheduler.ready_node_ids()` and dispatch admission consume that evaluator rather than maintain a second readiness algorithm;
- maximum in-flight concurrency is bounded (`1..24`);
- `PARTIAL`, `FAILED` and `CANCELLED` never become implicit dependency success;
- deterministic fan-in follows declared `depends_on` order, not completion timing;
- explicit approval is required at the dispatch boundary when the canonical plan requires it;
- plan and exact child authority are revalidated immediately before dispatch;
- persistent task budget/deadline is checked and one step is reserved per dispatch;
- every node capability is checked against current monotonic revocation immediately before dispatch;
- a revoked capability blocks execution rather than mutating planned authority;
- dispatch tickets bind task, plan, node, authority, dependency observations, sequence and execution level;
- only an exact canonical observation for a currently in-flight node can satisfy it;
- cancellation stops future dispatch without discarding already in-flight audit results;
- scheduler snapshots are deterministic and contain task-context, plan, authority, approval, dispatch-sequence, in-flight and observation fingerprints;
- neither scheduler invokes a provider directly or grants new authority.

### P0-5 regression coverage

`tests/test_runtime_scheduler.py` covers pure scheduling admission, deterministic ordering, dependency/approval/terminal propagation and fingerprint stability.

`tests/test_execution_scheduler.py` covers:

1. deterministic dependency-aware bounded ready ordering;
2. source-of-truth delegation to `RuntimeScheduler`;
3. deterministic fan-in independent of completion order;
4. blocking for `PARTIAL`, `FAILED` and `CANCELLED` dependencies;
5. live capability revocation after planning;
6. persistent budget/deadline enforcement;
7. approval fail-closed behavior;
8. exact in-flight observation admission and duplicate rejection;
9. cancellation with retained audit outcome;
10. duplicate dispatch rejection and backpressure.

Exact final PR head `90dea8d1da9240db709459cb5e8c8fb6afbfe168` passed all five core PR gates: canonical-module CI, Internet-egress-security CI, installer CI, Windows deployment/runtime smoke CI and harness CI. Harness passed unit tests plus enterprise verification EV-01 through EV-10 on both Python 3.11 and Python 3.12. `canonical-autoheal-safe` passed its focused regression, canonical census, compilation and full repository regression suite on that same exact head.

Post-merge `main=6d8e97ce9dc1382b4d8146884f82deb9ac7ec127` again passed the five core workflows; harness passed unit tests plus EV-01 through EV-10 on Python 3.11 and Python 3.12.

## P0-6 — dispatch-state checkpoint/recovery binding

PR `#378` adds `src/three_agent/runtime_dispatch_recovery.py` and `tests/test_runtime_dispatch_recovery.py` without changing `workspace-runtime-checkpoint/v1`.

### P0-6 invariants

- bind the exact canonical `RuntimeCheckpoint` fingerprint rather than creating a replacement checkpoint schema;
- bind deterministic `ExecutionScheduler.snapshot()` identity, including cancellation, dispatch sequence, approvals, in-flight tickets and accepted observations;
- bind the persistent `TaskExecutionBudgetState.snapshot()` limits, deadline and consumed counters;
- accept canonical zero-valued tool-call/retry/escalation limits; only the existing task contract owns those policy bounds;
- immutable budget limits/deadline cannot change across recovery;
- consumed budget counters may advance but may never roll back;
- bind monotonic `TaskCapabilityRevocationStore` records; historical revocations may never disappear;
- newly revoked capabilities are preserved in the recovery decision and cannot be used to widen authority;
- any in-flight dispatch fingerprint forces `MANUAL_RECONCILIATION` and is never auto-replayed;
- cancelled scheduler state remains `BLOCKED`;
- canonical `RuntimeRecovery` remains the task/context/plan/authority/observation recovery source of truth;
- no dispatch ticket, provider invocation, retry or authority grant occurs during recovery.

### P0-6 regression coverage

`tests/test_runtime_dispatch_recovery.py` covers:

1. deterministic binding identity and codec round-trip;
2. canonical zero-valued execution-budget dimensions;
3. quiescent recovery with no execution performed;
4. in-flight dispatch forcing manual reconciliation;
5. budget counter rollback rejection;
6. immutable budget/deadline mutation rejection;
7. revocation rollback rejection and preservation of newly revoked capabilities;
8. cancelled scheduler recovery remaining blocked;
9. scheduler/checkpoint identity mismatch rejection.

Exact pre-documentation code/test head `08ce86aca704d773b92c0883f7965ade5476e622` passed all five core PR gates. Harness passed compile, regression A-Z, unit tests and enterprise verification EV-01 through EV-10 on both Python 3.11 and Python 3.12. Windows runtime smoke passed on Python 3.11 and Python 3.12.

That pre-documentation evidence is not the merge gate for PR `#378`. The PR may merge only after all required core CI pass again on the resulting documentation head, followed by a fresh live-`main` / exact-PR-head guard. `canonical-autoheal-safe` should also be checked on the exact final head when that workflow triggers.

## Remaining P0 sequence

1. Authority narrowing — merged in PR `#365`.
2. Canonical `TaskContext` — merged in PR `#366`.
3. Canonical `ExecutionPlan` / `ExecutionNode` — merged in PR `#367`.
4. Canonical `ExecutionObservation` / Evidence binding — merged in PR `#369`.
5. Bounded dependency-aware scheduler — merged in PR `#370`.
6. Dispatch-state checkpoint/recovery binding — P0-6 candidate PR `#378`; merge only after exact resulting-head CI is green. Durable persistence wiring remains an adapter-level follow-up, not a new checkpoint contract.
7. Close provider/resource-lock, timeout and safe-retry integration gaps without creating another scheduler/provider framework.
8. Complete runtime-wide delegation binding for child context/authority/budget/evidence aggregation.
9. Run final integration/security/regression convergence and benchmark the normalized runtime path.

## Security conclusion

The audit does not support creating an independent replacement `runtime/`, `security/`, `context/`, `skills/` or `evidence/` implementation tree. WorkSpace already contains canonical primitives in those areas.

The safe convergence strategy remains:

`existing canonical primitive -> normalize/extend contract -> bind at runtime boundary -> regression tests -> CI evidence`

The central runtime rule remains unchanged: the model may propose reasoning and work, but WorkSpace runtime authority, state, capabilities, scheduling, evidence, recovery and execution policy remain outside model control.