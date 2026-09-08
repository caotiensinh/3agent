# WorkSpace Agent Runtime Source Convergence Audit

Status: normative implementation audit for the WorkSpace-native agent runtime.

## Baseline

- Repository: `caotiensinh/3agent`
- Original audited `main`: `3a13b9680a57b82cff503633111d0cfd7691c4d2`
- Runtime architecture source: `docs/WORKSPACE_AGENT_RUNTIME_ARCHITECTURE.md`
- Architecture PR: `#363`, merged into the original audited baseline above
- First convergence merge: PR `#365`, authority narrowing, merge commit `37ff9359ac7ebe83c3032bf3f27c9eb35fb7f009`
- Current P0-2 candidate: PR `#366`, canonical `TaskContext`
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
| `TaskContext` | `src/three_agent/task_context.py` — `TaskContext`, `TaskContextBuilder`, `TaskResourceBudget`; `src/three_agent/task_contract.py` — `TaskContract`, `TaskContractCompiler`; `src/three_agent/harness_task_compiler.py` — `CanonicalTaskSpec`; `src/three_agent/harness_context_manifest.py` — `ContextManifest`; `src/three_agent/trusted_runtime_context.py` | `KEEP/EXTEND` | P0-2 now provides one immutable runtime binding for task/session/trace/actor identity, purpose, project, risk class, resource budget, inventory scope, contract/canonical-task/authority fingerprints, and versioned context/evidence references. It deliberately does not grant authority and does not persist raw intent in canonical metadata. Remaining work is runtime wiring: future `ExecutionPlan`, scheduler, delegation, observation, checkpoint and aggregation paths must consume this canonical context instead of carrying parallel task metadata. | Keep `TaskContext` canonical and extend its use at execution boundaries. Do not introduce another runtime task model or allow context text to become an authority source. |
| `AuthorityEnvelope` | `src/three_agent/capability_authority.py` — `TaskCapabilityAuthority`, `CapabilityDecision`; `src/three_agent/model_authority.py`; `src/three_agent/capability_revocation.py`; `src/three_agent/security_monitoring/operation_invocation.py` | `KEEP/EXTEND` | Runtime capability/write/network enforcement is deny-by-default and PR `#365` added canonical fail-closed delegation proving `child_authority <= parent_authority`. Remaining work is binding that authority projection to generic subtask/subagent and execution-node dispatch. | Keep `TaskCapabilityAuthority` canonical and bind it to future `ExecutionPlan` nodes and `DelegationContract` dispatch. |
| Capability registry / `CapabilityDescriptor` | `src/three_agent/security_monitoring/capability_registry.py` — `SecurityCapability`, `SecurityCapabilityRegistry`; `capability_router.py`; `capability_matrix.py`; `src/three_agent/workspace_chat_capabilities.py` | `EXTEND` | Reviewed capability metadata, registry lookup and authority checks exist, but the main registry is security/monitoring-specific rather than a cross-runtime descriptor registry for all tools, programs, agents and providers. | Normalize a runtime descriptor view over existing registries/adapters; preserve existing authority gates and reviewed metadata. |
| `ExecutionPlan` / `ExecutionNode` | `src/three_agent/workflow_design.py` — bounded node schema, `depends_on`, DAG validation, topological ordering and cycle rejection; `src/three_agent/security_monitoring/operation_plan.py`; `src/three_agent/workflow.py` | `EXTEND` | The DAG contract is currently design-oriented. The production workflow runner is application-specific and linear. Runtime-wide executable nodes do not yet have one canonical contract binding `TaskContext`, node authority, budget, observation and evidence. | Promote/normalize the existing workflow DAG primitives into a runtime execution-plan contract instead of creating a parallel graph format. This is the next P0 implementation target after PR `#366`. |
| Scheduler | `src/three_agent/workflow_dispatch.py`; `src/three_agent/worker_pool.py`; `src/three_agent/adaptive_learning_scheduler.py`; `src/three_agent/security_monitoring_scheduler.py`; `src/three_agent/workflow_state_machine.py` | `MISSING` | Specialized scheduling/resource routing exists, but no generic bounded dependency-aware runtime scheduler executes the canonical DAG. `WorkflowDispatchController` intentionally admits only a low-risk connected linear chain and rejects branch joins/branching/conditions as design-only. | After `ExecutionPlan` normalization, add a bounded generic scheduler that reuses budgets, state machine, cancellation/revocation and deterministic fan-in primitives. |
| `Observation` | `src/three_agent/security_monitoring/contracts.py` — `ObservationRecord`; `src/three_agent/security_monitoring/observation_normalization.py` — `NormalizedObservationEvidence` | `EXTEND` | Security/monitoring already normalizes observations, but the guarantee is not runtime-wide: every generic execution node does not yet produce the same normalized observation contract. | Generalize the proven normalization pattern and bind it at the runtime execution-node boundary. |
| `EvidenceRecord` / provenance | `src/three_agent/security_monitoring/normalized_evidence.py`; `evidence_lineage.py`; `forensic_evidence.py`; `src/three_agent/benchmark_evidence.py`; `validator_ledger.py`; `evidence_packing.py` | `EXTEND` | Strong evidence, hashing, lineage and validation primitives exist in several domains. A single runtime-wide node-to-observation-to-evidence linkage is not yet canonical. | Reuse existing hashing/provenance implementations and normalize stable node/evidence references; do not replace DFIR-specific evidence stores. |
| `Checkpoint` | `src/three_agent/harness_checkpoint.py` — immutable `HarnessCheckpoint`, `HarnessCheckpointStore`; `src/three_agent/security_monitoring/checkpoint.py` | `KEEP/EXTEND` | Durable immutable reconstruction anchors already exist with source references and integrity checks. They are not yet bound to a generic `ExecutionPlan` node state plus revalidated authority/grants on resume. | Keep the harness checkpoint store canonical and extend resume/recovery binding after plan/scheduler normalization. |
| Context / Memory | `src/three_agent/harness_memory.py` — `HarnessEvent`, `MemoryRecord`, `HarnessMemoryStore`; `harness_context_compiler.py`; `harness_context_manifest.py`; `harness_context_rehydration.py`; `context_engine.py`; `knowledge_plane.py` | `KEEP/EXTEND` | Durable event/memory layers, provenance, trust domains and context assembly already exist. `TaskContext` now provides versioned references for runtime enrichment, but retrieval still needs consistent security-scope-before-semantic-relevance enforcement and stable raw-evidence references. | Preserve immutable memory/evidence semantics; converge retrieval and compression around scoped references and bind resulting manifests into canonical `TaskContext`. |
| Skills / learning / `CandidateSkill` | `src/three_agent/skills.py` — `ApprovedSkillLoader`; `adaptive_learning_contract.py`; `adaptive_learning_admission.py`; `adaptive_learning_promotion.py`; `adaptive_learning_lifecycle.py`; `promotion_gate.py` | `KEEP/EXTEND` | WorkSpace already has instruction-only skill admission, integrity checks, provenance, candidate/experience contracts and promotion gates. Architectural naming and runtime binding are not fully unified. | Keep production self-modification prohibited. Map candidate/promotion contracts to the runtime `CandidateSkill` lifecycle without bypassing security review, tests, benchmark or approval policy. |
| Subagents / `DelegationContract` | `src/three_agent/agents/`; `src/three_agent/handoff_security.py` — `HandoffSecurityMetadata`; evaluator/operator handoff modules | `EXTEND` | Specialist agents and handoff integrity/provenance exist. `handoff_security.py` explicitly verifies lineage/integrity and does not grant authority. No single runtime-wide `DelegationContract` currently binds child `TaskContext`, narrowed authority, budget, evidence requirements and aggregation policy. | Build delegation on canonical `TaskContext`, existing handoff metadata and canonical child authority derivation; never allow handoff content or a child model to mint authority. |

## Important non-duplicates

The following source families are complementary and must not be collapsed blindly:

1. `TaskContract` owns immutable task-level policy and budgets.
2. `TaskContext` binds execution identity, purpose, runtime resource projections and versioned context/evidence references; it does not grant authority.
3. `TaskCapabilityAuthority` owns executable capability/resource/effect authorization.
4. `TrustedRuntimeContext` supplies server-owned runtime facts but grants no authority.
5. `HarnessMemoryStore` and `HarnessCheckpointStore` own durable context/reconstruction state, not execution permission.
6. Security/DFIR evidence modules retain domain-specific acquisition and forensic semantics even after a runtime-wide evidence reference contract is normalized.
7. `ApprovedSkillLoader` admits reviewed procedures only; it is not a general execution capability registry.
8. Workflow design DAG validation is not equivalent to an executable scheduler.

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

Exact implementation commit before this audit-document update:

`b6a618c3b04f806cd76ac689353fe4eff59017e9`

Implementation:

`src/three_agent/task_context.py`

Focused tests:

`tests/test_task_context.py`

### TaskContext invariants

The new canonical binding composes existing primitives instead of replacing them:

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

Exact implementation HEAD `b6a618c3b04f806cd76ac689353fe4eff59017e9` passed all five PR gates before this documentation update: canonical module, Internet egress security, installer, Windows deployment/runtime smoke and harness CI. Harness Python 3.11 and 3.12 both passed unit tests plus enterprise verification EV-01 through EV-10.

## P0 sequence after TaskContext

The convergence order remains dependency-driven:

1. Authority narrowing — implemented and merged in PR `#365`.
2. Canonical `TaskContext` — implemented in PR `#366`; merge only after the resulting exact-head CI is green.
3. Normalize `ExecutionPlan` / `ExecutionNode` from the existing workflow-design DAG and bind nodes to canonical `TaskContext` plus authority fingerprints.
4. Bind every executable node to canonical `Observation` -> evidence references.
5. Add a bounded dependency-aware scheduler with deterministic fan-in and authority/budget revalidation.
6. Bind checkpoints/recovery to execution-node state and current authority.
7. Benchmark the normalized path before expanding into P1/P2/P3 features.

## Security conclusion

The source audit does not support creating a new independent `runtime/`, `security/`, `context/`, `skills/`, or `evidence/` implementation tree as the default strategy. WorkSpace already contains substantial canonical primitives in those areas.

The safe convergence strategy is:

`existing canonical primitive -> normalize/extend contract -> bind at runtime boundary -> regression tests -> CI evidence`

This preserves the central architecture rule: the model may propose reasoning and work, but WorkSpace runtime authority, state, capabilities, evidence and execution policy remain outside model control.
