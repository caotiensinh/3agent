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
- Current P0-5 candidate: PR `#370`, bounded dependency-aware scheduling and dispatch convergence
- P0-5 synchronized main baseline: `1d4a8745a6fadfe29a3068e2cf5c6b3fb168f455`
- P0-5 exact converged code head before this documentation update: `edd0b1f724b0499d7fd863c70c3eb2a590b70ef2`
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
| `TaskContext` | `task_context.py`; `task_contract.py`; `harness_task_compiler.py`; `harness_context_manifest.py` | `KEEP/EXTEND` | One immutable task/session/trace/actor runtime binding. Plans, observations and schedulers consume exact context fingerprints. Remaining work is checkpoint/resume and delegation wiring. | Keep `TaskContext` canonical; context text never grants authority. |
| Authority | `capability_authority.py`; `capability_revocation.py`; `model_authority.py` | `KEEP/EXTEND` | Child authority narrowing is canonical. Plan nodes bind exact narrowed authority. Dispatch revalidates authority and monotonic revocation immediately before execution admission. | Revalidate the same authority/revocation state on resume and provider invocation. |
| `ExecutionPlan` / `ExecutionNode` | `execution_plan.py`; `workflow_design.py` | `KEEP/EXTEND` | One deterministic immutable DAG bound to task context, authority, budgets, approvals and evidence requirements. It remains non-executing. | Keep plan metadata non-authorizing; do not create another graph format. |
| Scheduler admission | `runtime_scheduler.py` | `KEEP/EXTEND` | `RuntimeScheduler` is the canonical pure deterministic evaluator for DAG readiness, dependency propagation, approval admission and terminal-state projection. It validates task context, plan, authority and canonical observations and returns immutable scheduling decisions without mutating runtime state. | Keep this evaluator side-effect free. Checkpoint/resume should reconstruct inputs and recompute the decision rather than persist hidden scheduler logic. |
| Dispatch coordination | `execution_scheduler.py`; `execution_budget.py`; `capability_revocation.py` | `KEEP/EXTEND` | P0-5 `ExecutionScheduler` now consumes `RuntimeScheduler` as its readiness/admission source of truth. It owns only stateful dispatch concerns: tickets, in-flight tracking, persistent budget reservation, revocation checks, bounded concurrency/backpressure, cancellation, deterministic fan-in and canonical observation admission. | Keep provider execution outside this coordinator. Remaining gaps: resource locks, timeout/safe retry adapters and durable checkpoint/resume. |
| Observation | `execution_observation.py`; domain observation adapters | `KEEP/EXTEND` | Canonical provider-neutral node outcome with exact task/plan/node/authority binding. Non-success states never silently satisfy dependencies. | Propagate stable observation fingerprints into checkpoints and aggregation. |
| Evidence / provenance | `security_monitoring/normalized_evidence.py`; `security_monitoring/execution_evidence_adapter.py`; evidence/custody modules | `KEEP/EXTEND` | Existing DFIR evidence remains canonical; runtime adapter only binds evidence to exact execution identity. | Reuse custody stores; do not replace domain evidence semantics. |
| Checkpoint | `harness_checkpoint.py`; `harness_context_rehydration.py`; `workflow_state_machine.py`; `execution_scheduler.py` | `KEEP/EXTEND` | Immutable SHA-256 verified SQLite-backed checkpoints and scope-first context rehydration already exist. Scheduler exposes deterministic snapshot state, but runtime resume is not yet bound to plan/authority/revocation/budget/observation identity. | P0-6: bind scheduler reconstruction to existing checkpoint storage and fail closed on stale plan, authority, revocation, budget or evidence state. |
| Context / Memory | `harness_memory.py`; context compiler/manifest/rehydration modules | `KEEP/EXTEND` | Durable provenance-aware context primitives exist. | Security scope must be enforced before semantic relevance. |
| Skills / learning | `skills.py`; adaptive-learning admission/evaluation/promotion modules; `skill_catalog.py` | `KEEP/EXTEND` | Reviewed skill admission, progressive disclosure and controlled learning primitives exist. | Production self-modification remains prohibited; promotion requires evidence, tests, review and policy approval. |
| Subagents / delegation | agent/handoff modules; authority/plan/observation contracts | `EXTEND` | Handoff integrity and child authority exist, but one runtime-wide delegation contract is still missing. | Future delegation must bind child `TaskContext`, narrowed authority, budget, evidence and aggregation policy. |

## Canonical scheduler split

The repository now contains two scheduler-named modules with intentionally different responsibilities. They are complementary, not competing implementations.

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
- deterministic scheduler snapshot for future checkpoint binding.

This split prevents a second readiness implementation while preserving separation between pure decision logic and stateful execution control.

## Important non-duplicates

1. `TaskContract` owns immutable task-level policy and budgets.
2. `TaskContext` binds runtime identity and references; it grants no authority.
3. `TaskCapabilityAuthority` owns executable authority.
4. `ExecutionPlan` / `ExecutionNode` own the validated non-executing DAG and narrowed node bindings.
5. `RuntimeScheduler` owns pure deterministic scheduling/admission evaluation.
6. `ExecutionScheduler` owns stateful dispatch coordination and consumes `RuntimeScheduler` decisions.
7. `ExecutionObservation` owns canonical generic node-result binding and grants no authority.
8. `TaskExecutionBudgetState` remains persistent atomic budget/deadline authority.
9. `TaskCapabilityRevocationStore` remains the monotonic revocation source.
10. `WorkflowDispatchController`, worker pools and provider adapters remain specialized execution mechanisms.
11. `HarnessCheckpointStore` and `HarnessMemoryStore` own durable reconstruction/context state, not execution permission.
12. Security/DFIR evidence modules retain acquisition, custody and forensic semantics.
13. `ApprovedSkillLoader` and `ApprovedSkillCatalog` expose reviewed procedural knowledge but never grant runtime capability authority.

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

PR `#370` converges the scheduler path around:

- canonical pure evaluator: `src/three_agent/runtime_scheduler.py` (already present on synchronized `main`);
- stateful dispatch coordinator: `src/three_agent/execution_scheduler.py`;
- pure evaluator tests: `tests/test_runtime_scheduler.py`;
- dispatch coordinator tests: `tests/test_execution_scheduler.py`.

Synchronization merge commit carrying live `main` into the P0-5 branch: `5666c904488b35bd374265521f5999d0a4822248`.

Exact converged code head before this documentation update: `edd0b1f724b0499d7fd863c70c3eb2a590b70ef2`.

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

Exact code head `edd0b1f724b0499d7fd863c70c3eb2a590b70ef2` passed all five core PR gates: canonical-module CI, Internet-egress-security CI, installer CI, Windows deployment/runtime smoke CI and harness CI. Harness passed unit tests plus enterprise verification EV-01 through EV-10 on both Python 3.11 and Python 3.12. `canonical-autoheal-safe` also passed its focused regression, canonical census, compilation and full repository regression suite on the same exact head.

## Remaining P0 sequence

1. Authority narrowing — merged in PR `#365`.
2. Canonical `TaskContext` — merged in PR `#366`.
3. Canonical `ExecutionPlan` / `ExecutionNode` — merged in PR `#367`.
4. Canonical `ExecutionObservation` / Evidence binding — merged in PR `#369`.
5. Bounded dependency-aware scheduler — P0-5 candidate PR `#370`; merge only after the resulting documentation-head exact CI and autoheal are green.
6. P0-6 checkpoint/resume — bind canonical plan fingerprint, deterministic scheduler reconstruction state, accepted observation fingerprints, current authority, revocation and budget/deadline state to existing immutable checkpoint storage.
7. Close provider/resource-lock, timeout and safe-retry integration gaps without creating another scheduler/provider framework.
8. Run final integration/security/regression convergence and benchmark the normalized runtime path.

## Security conclusion

The audit does not support creating an independent replacement `runtime/`, `security/`, `context/`, `skills/` or `evidence/` implementation tree. WorkSpace already contains canonical primitives in those areas.

The safe convergence strategy remains:

`existing canonical primitive -> normalize/extend contract -> bind at runtime boundary -> regression tests -> CI evidence`

The central runtime rule remains unchanged: the model may propose reasoning and work, but WorkSpace runtime authority, state, capabilities, scheduling, evidence and execution policy remain outside model control.
