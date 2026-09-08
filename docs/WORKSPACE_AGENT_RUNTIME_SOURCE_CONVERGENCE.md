# WorkSpace Agent Runtime Source Convergence Audit

Status: normative implementation audit for the WorkSpace-native agent runtime.

## Baseline

- Repository: `caotiensinh/3agent`
- Audited `main`: `3a13b9680a57b82cff503633111d0cfd7691c4d2`
- Runtime architecture source: `docs/WORKSPACE_AGENT_RUNTIME_ARCHITECTURE.md`
- Architecture PR: `#363`, merged into the baseline above
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
| `TaskContext` | `src/three_agent/task_contract.py` — `TaskContract`, `TaskContractCompiler`; `src/three_agent/harness_task_compiler.py`; `src/three_agent/trusted_runtime_context.py`; application task state in `src/three_agent/models.py` | `EXTEND` | `TaskContract` already carries immutable task authority, budgets, tool/source scope, network scope, model policy, evidence requirements and validators, but there is no single runtime-wide `TaskContext` joining project/session/actor/request outcome, context references, evidence references and current execution identity. | Extend/compose the canonical task contract and harness context primitives. Do not introduce an unrelated second task model. |
| `AuthorityEnvelope` | `src/three_agent/capability_authority.py` — `TaskCapabilityAuthority`, `CapabilityDecision`; `src/three_agent/model_authority.py`; `src/three_agent/capability_revocation.py`; `src/three_agent/security_monitoring/operation_invocation.py` | `EXTEND` | Runtime capability/write/network enforcement exists and is deny-by-default. The audited baseline lacked a canonical delegation primitive proving `child_authority <= parent_authority`. | Keep `TaskCapabilityAuthority` canonical. PR `#365` adds fail-closed child authority derivation; bind it to future subtask/subagent dispatch. |
| Capability registry / `CapabilityDescriptor` | `src/three_agent/security_monitoring/capability_registry.py` — `SecurityCapability`, `SecurityCapabilityRegistry`; `capability_router.py`; `capability_matrix.py`; `src/three_agent/workspace_chat_capabilities.py` | `EXTEND` | Reviewed capability metadata, registry lookup and authority checks exist, but the main registry is security/monitoring-specific rather than a cross-runtime descriptor registry for all tools, programs, agents and providers. | Normalize a runtime descriptor view over existing registries/adapters; preserve existing authority gates and reviewed metadata. |
| `ExecutionPlan` / `ExecutionNode` | `src/three_agent/workflow_design.py` — bounded node schema, `depends_on`, DAG validation, topological ordering and cycle rejection; `src/three_agent/security_monitoring/operation_plan.py`; `src/three_agent/workflow.py` | `EXTEND` | The DAG contract is currently design-oriented. The production workflow runner is application-specific and linear. Runtime-wide executable nodes do not yet have one canonical contract binding node authority, budget, observation and evidence. | Promote/normalize the existing workflow DAG primitives into a runtime execution-plan contract instead of creating a parallel graph format. |
| Scheduler | `src/three_agent/workflow_dispatch.py`; `src/three_agent/worker_pool.py`; `src/three_agent/adaptive_learning_scheduler.py`; `src/three_agent/security_monitoring_scheduler.py`; `src/three_agent/workflow_state_machine.py` | `MISSING` | Specialized scheduling/resource routing exists, but no generic bounded dependency-aware runtime scheduler executes the canonical DAG. `WorkflowDispatchController` intentionally admits only a low-risk connected linear chain and rejects branch joins/branching/conditions as design-only. | After `ExecutionPlan` normalization, add a bounded generic scheduler that reuses budgets, state machine, cancellation/revocation and deterministic fan-in primitives. |
| `Observation` | `src/three_agent/security_monitoring/contracts.py` — `ObservationRecord`; `src/three_agent/security_monitoring/observation_normalization.py` — `NormalizedObservationEvidence` | `EXTEND` | Security/monitoring already normalizes observations, but the guarantee is not runtime-wide: every generic execution node does not yet produce the same normalized observation contract. | Generalize the proven normalization pattern and bind it at the runtime execution-node boundary. |
| `EvidenceRecord` / provenance | `src/three_agent/security_monitoring/normalized_evidence.py`; `evidence_lineage.py`; `forensic_evidence.py`; `src/three_agent/benchmark_evidence.py`; `validator_ledger.py`; `evidence_packing.py` | `EXTEND` | Strong evidence, hashing, lineage and validation primitives exist in several domains. A single runtime-wide node-to-observation-to-evidence linkage is not yet canonical. | Reuse existing hashing/provenance implementations and normalize stable node/evidence references; do not replace DFIR-specific evidence stores. |
| `Checkpoint` | `src/three_agent/harness_checkpoint.py` — immutable `HarnessCheckpoint`, `HarnessCheckpointStore`; `src/three_agent/security_monitoring/checkpoint.py` | `KEEP/EXTEND` | Durable immutable reconstruction anchors already exist with source references and integrity checks. They are not yet bound to a generic `ExecutionPlan` node state plus revalidated authority/grants on resume. | Keep the harness checkpoint store canonical and extend resume/recovery binding after plan/scheduler normalization. |
| Context / Memory | `src/three_agent/harness_memory.py` — `HarnessEvent`, `MemoryRecord`, `HarnessMemoryStore`; `harness_context_compiler.py`; `harness_context_manifest.py`; `harness_context_rehydration.py`; `context_engine.py`; `knowledge_plane.py` | `KEEP/EXTEND` | Durable event/memory layers, provenance, trust domains and context assembly already exist. Runtime-wide retrieval still needs consistent security-scope-before-semantic-relevance enforcement and stable raw-evidence references. | Preserve immutable memory/evidence semantics; converge retrieval and compression around scoped references rather than copying raw evidence into model context. |
| Skills / learning / `CandidateSkill` | `src/three_agent/skills.py` — `ApprovedSkillLoader`; `adaptive_learning_contract.py`; `adaptive_learning_admission.py`; `adaptive_learning_promotion.py`; `adaptive_learning_lifecycle.py`; `promotion_gate.py` | `KEEP/EXTEND` | WorkSpace already has instruction-only skill admission, integrity checks, provenance, candidate/experience contracts and promotion gates. Architectural naming and runtime binding are not fully unified. | Keep production self-modification prohibited. Map candidate/promotion contracts to the runtime `CandidateSkill` lifecycle without bypassing security review, tests, benchmark or approval policy. |
| Subagents / `DelegationContract` | `src/three_agent/agents/`; `src/three_agent/handoff_security.py` — `HandoffSecurityMetadata`; evaluator/operator handoff modules | `EXTEND` | Specialist agents and handoff integrity/provenance exist. `handoff_security.py` explicitly verifies lineage/integrity and does not grant authority. No single runtime-wide `DelegationContract` currently binds child task scope, narrowed authority, budget, evidence requirements and aggregation policy. | Build delegation on existing handoff metadata plus canonical child authority derivation; never allow handoff content or a child model to mint authority. |

## Important non-duplicates

The following source families are complementary and must not be collapsed blindly:

1. `TaskContract` owns immutable task-level policy and budgets.
2. `TaskCapabilityAuthority` owns executable capability/resource/effect authorization.
3. `TrustedRuntimeContext` supplies server-owned runtime facts but grants no authority.
4. `HarnessMemoryStore` and `HarnessCheckpointStore` own durable context/reconstruction state, not execution permission.
5. Security/DFIR evidence modules retain domain-specific acquisition and forensic semantics even after a runtime-wide evidence reference contract is normalized.
6. `ApprovedSkillLoader` admits reviewed procedures only; it is not a general execution capability registry.
7. Workflow design DAG validation is not equivalent to an executable scheduler.

## First P0 convergence change

PR `#365` (`feat(runtime): enforce child authority narrowing`) is the first implementation change produced from this audit.

Exact implementation commit before this audit document:

`42d3c7a289373047f72eb22c18664b3b4da1d6da`

It extends the canonical `TaskCapabilityAuthority` rather than creating a second authority abstraction.

### New invariant enforcement

`TaskCapabilityAuthority.derive_child(...)` permits a delegated child to preserve or reduce parent authority only:

- child tool set must be a subset of parent tools;
- child source set must be a subset of parent sources;
- child write scope must be equal to or nested inside parent write scope, or `none`;
- child network scope may remain identical or reduce to `deny`;
- sensitivity is inherited exactly and cannot be declassified by delegation;
- transitive delegation cannot regain authority removed by an intermediate child.

Focused tests are in:

`tests/test_runtime_authority_narrowing.py`

The tests cover successful narrowing, capability escalation rejection, write-scope escalation/path traversal rejection, network-scope escalation rejection, transitive privilege regain rejection and a zero-tool fail-closed child.

## P0 sequence after authority narrowing

The next convergence order is intentionally dependency-driven:

1. Merge authority narrowing only after exact-head CI is green.
2. Normalize `TaskContext` as an extension/composition of `TaskContract` plus existing harness context references.
3. Normalize `ExecutionPlan` / `ExecutionNode` from the existing workflow-design DAG.
4. Bind every executable node to canonical `Observation` -> evidence references.
5. Add a bounded dependency-aware scheduler with deterministic fan-in and authority/budget revalidation.
6. Bind checkpoints/recovery to execution-node state and current authority.
7. Benchmark the normalized path before expanding into P1/P2/P3 features.

## Security conclusion

The source audit does not support creating a new independent `runtime/`, `security/`, `context/`, `skills/`, or `evidence/` implementation tree as the default strategy. WorkSpace already contains substantial canonical primitives in those areas.

The safe convergence strategy is:

`existing canonical primitive -> normalize/extend contract -> bind at runtime boundary -> regression tests -> CI evidence`

This preserves the central architecture rule: the model may propose reasoning and work, but WorkSpace runtime authority, state, capabilities, evidence and execution policy remain outside model control.
