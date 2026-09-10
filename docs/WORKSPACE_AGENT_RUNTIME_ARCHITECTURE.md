# WorkSpace Agent Runtime Architecture

Status: Normative target architecture  
Scope: agent runtime, orchestration, authority, context, memory, execution, evidence, skill evolution, integrations, and cost governance  
Audience: WorkSpace developers, security reviewers, operators, and future agent/module authors

## 1. Purpose

WorkSpace is an enterprise agent runtime, not a chat wrapper around an LLM.

The reasoning model is a replaceable component inside a governed runtime. Durable product capability must live in explicit runtime contracts, capability discovery, authority enforcement, deterministic execution, evidence, memory, procedural skills, recovery, and auditability.

The central product objective is:

> Turn natural-language intent into bounded, observable, evidence-producing execution without allowing the model to become the source of authority.

This document defines WorkSpace behavior as its own architecture. It is intentionally provider-neutral and implementation-flexible. Components may be implemented with local services, databases, queues, MCP servers, plugins, cloud APIs, or other mechanisms as long as the runtime invariants in this document remain true.

## 2. Architectural principles

1. **Runtime intelligence, not prompt-only intelligence.** Useful agent behavior is distributed across system policy, capability metadata, skills, memory, state, orchestration, execution, evidence, and model reasoning.
2. **Model-provider neutrality.** Local or remote models may be replaced without redesigning the control, execution, evidence, or authority planes.
3. **Capability discovery instead of hard-coded tool prompts.** The runtime discovers capabilities, filters them by policy, and exposes only the task-appropriate subset.
4. **Plan -> execute -> observe -> validate.** A model may propose actions, but runtime components validate and enforce them before execution.
5. **Authority is monotonic.** Delegation may preserve or reduce authority; it must never silently widen authority.
6. **Read-only by default.** Writes, privileged operations, remote changes, destructive actions, and paid services require progressively stronger policy checks.
7. **Evidence first.** Executed work produces traceable observations and evidence records before conclusions are promoted as facts.
8. **Determinism where possible.** Validation, permission checks, merge rules, schemas, budgets, retries, and artifact assembly should be deterministic code rather than model judgment.
9. **Bounded concurrency.** Parallelism is dependency-aware, resource-bounded, cancellable, and auditable.
10. **Learning is staged.** Runtime experience may produce candidate procedures or candidate skills, but never silently mutate production behavior.
11. **Free-first, paid-when-justified.** Paid capability is optional, purpose-bound, budgeted, metered, and fail-closed.
12. **Secrets stay outside model context.** Models and plans use credential references, never raw secrets.
13. **Outcome over implementation similarity.** Technology choices may change; safety, capability, determinism, and measurable outcomes define success.
14. **Recovery is designed, not improvised.** Multi-step execution has durable checkpoints, idempotency rules, and explicit compensation where true rollback is impossible.
15. **No capability claim without evidence.** A module is not considered implemented merely because a model can describe it.

## 3. Runtime planes

WorkSpace is divided into six logical planes.

### 3.1 Control Plane

Responsible for:

- task intake and normalization;
- intent classification;
- task risk classification;
- planner invocation;
- execution-plan lifecycle;
- scheduler decisions;
- cancellation;
- checkpoint/recovery coordination;
- final result aggregation.

### 3.2 Execution Plane

Responsible for:

- capability adapters;
- local tools;
- network/device tools;
- file and shell execution;
- programmatic tool execution;
- subagent execution;
- MCP/plugin adapters;
- external APIs;
- background/long-running jobs.

### 3.3 Context and Knowledge Plane

Responsible for:

- session state;
- working context;
- retrieval;
- factual/evidence memory;
- procedural memory;
- context compression;
- knowledge graph/index integration where useful;
- selective context reconstruction.

### 3.4 Governance and Security Plane

Responsible for:

- identity;
- authority envelopes;
- inventory/resource scope;
- capability policy;
- network policy;
- approval gates;
- credential references;
- paid-capability grants;
- quota and budget enforcement;
- retention and privacy rules.

### 3.5 Evidence and Observability Plane

Responsible for:

- trace IDs;
- observations;
- evidence records;
- provenance;
- audit events;
- metrics;
- token/cost telemetry;
- error classification;
- redaction;
- artifacts and hashes.

### 3.6 Integration Plane

Responsible for controlled interfaces to:

- local model runtimes;
- remote model providers;
- MCP servers;
- plugins;
- GitHub and other developer systems;
- monitoring systems;
- network/security systems;
- camera/edge systems;
- external search/intelligence providers;
- enterprise SaaS systems.

## 4. End-to-end runtime loop

```text
USER / SYSTEM / EVENT
        |
        v
+---------------------+
| Task Intake         |
+---------------------+
        |
        v
+---------------------+
| TaskContext         |
| intent / purpose    |
| risk / budget       |
| actor / project     |
+---------------------+
        |
        v
+---------------------+
| Context Assembly    |
| session / memory    |
| evidence / skills   |
+---------------------+
        |
        v
+---------------------+
| Capability Discovery|
+---------------------+
        |
        v
+---------------------+
| Authority + Policy  |
| Filter              |
+---------------------+
        |
        v
+---------------------+
| Planner             |
+---------------------+
        |
        v
+---------------------+
| ExecutionPlan / DAG |
+---------------------+
        |
        v
+---------------------+
| Scheduler           |
+---------------------+
    /       |       \
   v        v        v
 Tool    ToolProgram Subagent
 Calls    / Batch     Lane
   \        |        /
    \       |       /
        v
+---------------------+
| Observation         |
| Normalization       |
+---------------------+
        |
        v
+---------------------+
| Evidence Ledger     |
+---------------------+
        |
        v
+---------------------+
| Validation +        |
| Aggregation         |
+---------------------+
        |
        v
+---------------------+
| Response / Artifact |
+---------------------+
        |
        v
+---------------------+
| Post-Task Review    |
+---------------------+
   /       |       \
Memory   Lesson   Candidate Skill
```

The model participates at selected reasoning boundaries. It does not need to be called between every tool action.

## 5. Runtime state machine

A task SHOULD move through explicit states:

```text
RECEIVED
  -> CONTEXTUALIZED
  -> AUTHORIZED
  -> PLANNED
  -> READY
  -> RUNNING
  -> PARTIAL | SUCCEEDED | FAILED | CANCELLED
  -> VALIDATED
  -> REPORTED
  -> REVIEWED
  -> CLOSED
```

A task MUST NOT enter `RUNNING` unless its executable nodes have passed authority and policy validation.

`PARTIAL` is a first-class result. It is preferable to pretending full success when some lanes or evidence are missing.

## 6. Core runtime contracts

The contracts below are logical schemas. Exact serialization may use typed Python models, JSON Schema, Protocol Buffers, database records, or another strongly validated representation.

### 6.1 TaskContext

```yaml
task_id: string
session_id: string
trace_id: string
actor_id: string
intent: string
purpose: string
project: string | null
risk_class: R0 | R1 | R2 | R3 | R4
created_at: timestamp
deadline: timestamp | null
resource_budget:
  wall_time_s: integer | null
  model_tokens: integer | null
  tool_calls: integer | null
  cost_usd: number | null
inventory_scope: [resource_ref]
```

`TaskContext` is immutable in identity. Runtime enrichment creates versioned derived context rather than silently rewriting the original request.

### 6.2 AuthorityEnvelope

```yaml
authority_id: string
actor_id: string
allowed_capabilities: [capability_pattern]
inventory_scope: [resource_ref]
resource_scope: [resource_ref]
side_effect_limit: READ_ONLY | LOCAL_WRITE | REMOTE_WRITE | PRIVILEGED | DESTRUCTIVE
network_policy_ref: string | null
credential_refs: [credential_ref]
max_cost_usd: number | null
expires_at: timestamp | null
required_approvals: [approval_policy_ref]
```

Invariant:

```text
child_authority <= parent_authority
```

A planner, subagent, plugin, skill, or model MUST NOT create a wider envelope than it received.

### 6.3 CapabilityDescriptor

```yaml
capability_id: string
version: string
provider: string
input_schema_ref: string
output_schema_ref: string
side_effect_class: READ_ONLY | LOCAL_WRITE | REMOTE_WRITE | PRIVILEGED | DESTRUCTIVE
risk_class: R0 | R1 | R2 | R3 | R4
authority_requirements: [string]
credential_ref: string | null
cost_class: FREE_NATIVE | FREE_OPTIONAL | PAID_EXTERNAL | API_KEY_REQUIRED | LICENSE_RESTRICTED
approval_required: boolean
timeout_s: integer
retry_policy_ref: string
idempotency: IDEMPOTENT | CONDITIONAL | NON_IDEMPOTENT
concurrency_group: string | null
trust_tier: CORE | REVIEWED | EXTERNAL | UNTRUSTED
health_state: HEALTHY | DEGRADED | UNAVAILABLE
```

The registry owns this metadata. The model does not invent it.

### 6.4 ExecutionPlan

```yaml
plan_id: string
task_id: string
plan_version: integer
nodes: [ExecutionNode]
created_by: planner_ref
validated_by: policy_engine_ref
```

### 6.5 ExecutionNode

```yaml
node_id: string
capability_id: string
depends_on: [node_id]
args: object
timeout_s: integer
retry_policy_ref: string
budget: object
required_evidence: [evidence_requirement]
on_failure: STOP | CONTINUE | FALLBACK | COMPENSATE
compensation_node: node_id | null
```

All tool arguments MUST pass schema validation and policy validation before dispatch.

### 6.6 Observation

```yaml
observation_id: string
node_id: string
status: SUCCEEDED | FAILED | PARTIAL | CANCELLED
started_at: timestamp
finished_at: timestamp
normalized_output: object | null
error_class: string | null
evidence_refs: [evidence_ref]
cost: object | null
```

Raw provider output may be stored separately. Downstream orchestration should consume normalized output whenever possible.

### 6.7 EvidenceRecord

```yaml
evidence_id: string
trace_id: string
task_id: string
plan_id: string
node_id: string | null
source_type: TOOL | FILE | NETWORK | DEVICE | USER | MODEL | EXTERNAL_API | ARTIFACT
source_ref: string
content_hash: string | null
collected_at: timestamp
actor_ref: string
redaction_state: string
provenance: object
```

Evidence provenance MUST survive aggregation and subagent boundaries.

### 6.8 Checkpoint

```yaml
checkpoint_id: string
task_id: string
plan_id: string
plan_version: integer
completed_nodes: [node_id]
pending_nodes: [node_id]
failed_nodes: [node_id]
context_snapshot_ref: string
evidence_refs: [evidence_ref]
created_at: timestamp
```

A checkpoint records execution state. It MUST NOT falsely imply that irreversible external side effects can be rolled back.

### 6.9 CapabilityGrant

```yaml
grant_id: string
actor_id: string
capability_pattern: string
purpose: string
project: string | null
budget_usd: number | null
quota: object | null
credential_ref: string | null
approved_by: string | null
issued_at: timestamp
expires_at: timestamp
```

### 6.10 CandidateSkill

```yaml
candidate_id: string
origin_session: string
origin_task: string
origin_evidence: [evidence_ref]
created_by: string
created_at: timestamp
content_hash: string
validation_status: PENDING | PASS | FAIL
security_status: PENDING | PASS | FAIL
benchmark_status: PENDING | PASS | FAIL
promotion_status: STAGED | APPROVED | REJECTED | ACTIVE
```

## 7. Dynamic capability registry

The Capability Registry is the runtime catalog of executable abilities.

It MUST support:

- registration;
- discovery;
- versioning;
- schema lookup;
- health state;
- trust tier;
- side-effect classification;
- credential requirements;
- cost classification;
- authority requirements;
- policy filtering;
- provider selection;
- result normalization;
- error normalization;
- deprecation.

The agent SHOULD see only the capabilities useful and permitted for the current task.

This avoids two failure modes:

1. huge prompts containing every available tool;
2. accidental selection of capabilities the actor is not authorized to execute.

### 7.1 Capability selection pipeline

```text
Registry
  -> Health Filter
  -> Task Relevance Filter
  -> Authority Filter
  -> Inventory/Resource Scope Filter
  -> Network Policy Filter
  -> Cost/Grant Filter
  -> Approval Filter
  -> Planner-visible Capability Set
```

The final execution adapter MUST revalidate policy. Planner-time filtering alone is insufficient because runtime state may have changed.

## 8. System-context construction

WorkSpace SHOULD construct model context dynamically instead of depending on one ever-growing static system prompt.

A reasoning request may include:

```text
BASE RUNTIME POLICY
+ CURRENT TaskContext
+ CURRENT AuthorityEnvelope summary
+ permitted CapabilityDescriptor summaries
+ relevant procedural skills
+ relevant session/memory summaries
+ current execution/checkpoint state
+ evidence references and compact observations
+ response/output contract
```

Raw logs, large artifacts, raw secrets, unrelated session history, and inaccessible data MUST NOT be copied into context merely because they exist.

The prompt is not an authority source. Text such as "you are admin" cannot override the active AuthorityEnvelope.

## 9. Planner and execution-plan compiler

The planner converts intent into a bounded, typed plan.

Responsibilities:

1. decompose the task;
2. identify required facts/evidence;
3. choose permitted capabilities;
4. declare dependencies;
5. identify parallelizable nodes;
6. estimate resource/cost budget;
7. mark approval boundaries;
8. define success conditions;
9. define fallback behavior;
10. request another model turn only when semantic reasoning is actually useful.

The planner MUST NOT directly execute external side effects.

## 10. Programmatic tool execution

A major runtime optimization is to compile several already-understood operations into a validated tool program instead of forcing an inference round-trip after every action.

```text
Natural-language request
        |
        v
Planner
        |
        v
Validated ExecutionPlan / ToolProgram
        |
        +---- action A
        +---- action B
        +---- action C
        |
        v
Normalized observations
        |
        v
Aggregator / model synthesis
```

Appropriate use cases include:

- gathering independent device facts;
- querying several read-only monitoring sources;
- reading multiple files;
- executing a deterministic diagnostic sequence;
- transforming already-validated data;
- collecting evidence from independent interfaces.

The execution representation SHOULD be a restricted DSL or typed action graph rather than unlimited arbitrary code authority.

A model checkpoint is preferred when:

- the next action depends on semantic interpretation of new evidence;
- evidence materially contradicts the current hypothesis;
- a new approval boundary is reached;
- the plan would exceed budget;
- an unexpected non-idempotent failure occurs;
- ambiguity cannot be resolved deterministically.

## 11. Dependency-aware scheduler and bounded concurrency

Parallelism is a runtime optimization, not a goal by itself.

The scheduler MUST provide:

- DAG dependency resolution;
- bounded worker pools;
- concurrency-group limits;
- resource locks;
- per-node timeouts;
- whole-task deadline handling;
- cancellation propagation;
- backpressure;
- deterministic fan-in rules;
- failure isolation;
- safe retries;
- budget enforcement.

Example:

```text
                 +--> ping ----------+
                 +--> ARP/neighbor ---+
Device target ---+--> SNMP read ------+--> aggregate evidence --> diagnose
                 +--> HTTP health ----+
                 +--> camera probe ---+
```

These reads may run concurrently when policy permits. A firmware write, switch-port change, or credential rotation must not be placed in the same blind fan-out.

## 12. Subagent runtime

Subagents are isolated execution lanes for specialized reasoning or investigation. They are not independent principals with unrestricted authority.

Every subagent receives a `DelegationContract` containing:

- parent task/trace;
- narrow objective;
- input context references;
- explicit output schema;
- AuthorityEnvelope subset;
- time budget;
- token budget;
- tool-call budget;
- cost budget;
- cancellation token;
- evidence/provenance requirements.

### 12.1 Required invariants

- child authority is a subset of parent authority;
- child cannot issue itself credentials;
- child cannot silently create another paid grant;
- child evidence keeps origin attribution;
- child result is not automatically accepted as fact;
- parent/runtime validates output before aggregation;
- child failure is isolated unless declared critical.

### 12.2 Specialist examples

WorkSpace may use specialist profiles for:

- network topology;
- network diagnostics;
- cybersecurity/DFIR;
- camera and ONVIF/RTSP diagnostics;
- monitoring correlation;
- source-code analysis;
- test/release verification;
- research;
- artifact generation.

Specialization is a context and capability restriction mechanism, not merely a different role prompt.

## 13. Session, context, and memory architecture

WorkSpace SHOULD distinguish at least five forms of memory.

### 13.1 Event history

Append-oriented record of important task/session events.

### 13.2 Working memory

Small, task-local state needed for the current plan.

### 13.3 Session memory

Compact summaries and unresolved state needed to continue a conversation or operation.

### 13.4 Evidence memory

Verified or provenance-bearing facts linked to raw evidence outside the active model context.

### 13.5 Procedural memory

Reviewed skills, runbooks, diagnostic procedures, policies, and reusable execution knowledge.

Memory retrieval MUST respect actor, project, tenant, inventory, privacy, and authority boundaries before relevance ranking.

A semantically relevant record that is outside the actor's scope is not retrievable context.

## 14. Context compression

Context compression is required for long-running agents.

WorkSpace SHOULD use:

- observation normalization;
- structured summaries;
- stable evidence IDs;
- artifact references instead of inline raw artifacts;
- history summarization;
- relevance and recency ranking;
- task-state snapshots;
- progressive compression of old tool output;
- on-demand rehydration of raw evidence.

### 14.1 Compression rule

```text
Raw evidence is preserved outside the model context.
Compressed context points back to raw evidence by stable reference.
```

Compression MUST NOT destroy provenance or convert uncertain observations into certain facts.

## 15. Checkpoint, recovery, and compensation

Before meaningful multi-step execution, the runtime SHOULD create durable checkpoints.

Recovery uses:

1. last valid checkpoint;
2. completed-node idempotency records;
3. current provider/resource health;
4. revalidated AuthorityEnvelope;
5. current budget/grant state;
6. pending DAG nodes.

### 15.1 Rollback semantics

WorkSpace distinguishes:

- **rollback**: restoring reversible internal state;
- **retry**: re-running a safe/idempotent operation;
- **compensation**: performing a new action to counter a prior external effect;
- **reconciliation**: detecting and resolving unknown external state;
- **manual recovery**: requiring an operator when automation cannot prove safety.

A remote router configuration change, credential change, external purchase, or physical action MUST NOT be described as rolled back unless the system has verified the reversal.

## 16. Skill system and procedural knowledge

A skill is versioned procedural knowledge with executable implications. It is not merely a text snippet.

An active skill SHOULD declare:

- skill ID/version;
- purpose;
- prerequisites;
- inputs/outputs;
- allowed capability patterns;
- forbidden operations;
- authority requirements;
- evidence requirements;
- success/failure conditions;
- supporting references/files;
- content hash;
- validation status;
- security review state.

## 17. Self-improvement lifecycle

WorkSpace may learn from successful and failed work, but production behavior remains governed.

```text
EXECUTION
   |
   v
OBSERVATION
   |
   v
POST-TASK REVIEW
   |
   v
LESSON
   |
   v
CANDIDATE PROCEDURE
   |
   v
CANDIDATE SKILL
   |
   v
TESTS
   |
   v
SECURITY REVIEW
   |
   v
BENCHMARK
   |
   v
APPROVAL POLICY
   |
   v
ACTIVE SKILL
```

### 17.1 Prohibited behavior

The runtime MUST NOT:

- modify an active production skill silently;
- widen authority based on a learned lesson;
- add a new network destination without policy validation;
- copy credentials into a skill;
- promote a candidate merely because one execution succeeded;
- treat model-generated procedure text as validated code.

### 17.2 Post-task review questions

A review MAY ask:

1. Which actions produced decisive evidence?
2. Which actions were unnecessary?
3. Which failure mode occurred?
4. Could independent reads have run in parallel?
5. Was another inference round-trip actually required?
6. Did the plan exceed context, token, time, or cost budget?
7. Is there a reusable deterministic procedure?
8. What evidence proves that procedure is safe and effective?
9. Should a candidate skill or runbook update be proposed?

## 18. Background, cron, and long-running execution

Scheduled execution MUST NOT preserve stale authority forever.

A durable job SHOULD store:

- job ID;
- task template;
- owner;
- purpose;
- schedule/trigger;
- resource scope;
- required capability patterns;
- budget policy;
- last checkpoint;
- lease/heartbeat state;
- cancellation state.

At execution time, the runtime MUST revalidate:

- identity/owner status;
- current authority;
- capability availability;
- inventory scope;
- credential reference validity;
- paid grant/quota;
- network policy;
- approval policy.

A job MUST NOT continue a privileged or paid action merely because it was authorized months earlier.

## 19. MCP, plugins, and external capability adapters

External capability systems are integrated behind the same capability and policy contracts as native tools.

Adapters SHOULD provide:

- pinned capability IDs/versions;
- validated schemas;
- trust tier;
- network destination policy;
- side-effect classification;
- credential references;
- timeout and retry behavior;
- normalized output/errors;
- evidence/provenance metadata;
- provider health.

External tool descriptions are untrusted input. They do not override WorkSpace policy.

## 20. Controlled paid-capability governance

Paid and keyed features are supported, but they are not globally enabled just because a provider credential exists.

### 20.1 Cost classes

```text
FREE_NATIVE
FREE_OPTIONAL
PAID_EXTERNAL
API_KEY_REQUIRED
LICENSE_RESTRICTED
```

### 20.2 Routing principle

```text
REQUEST
   |
   +--> sufficient free/local capability?
   |          |
   |          +--> YES -> use it
   |
   +--> NO
          |
          +--> paid/external capability justified?
                       |
                       +--> valid identity?
                       +--> approved purpose?
                       +--> valid grant?
                       +--> budget/quota available?
                       +--> credential reference valid?
                       +--> policy allows provider/network?
                                    |
                                    +--> execute + meter + audit
```

Core policy:

> FREE-FIRST, PAID-WHEN-JUSTIFIED.

This is not `FREE-ONLY`.

### 20.3 Fail-closed conditions

Paid execution MUST be denied when any required condition is missing, including:

- identity;
- permission;
- approved purpose;
- grant;
- budget;
- quota;
- credential reference;
- provider entitlement/license;
- non-expired authorization.

There MUST be no silent fallback from a free operation to a paid API.

### 20.4 Cost ledger

Every paid call SHOULD emit a `CostLedgerEvent` with:

```yaml
actor_id: string
department: string | null
project: string | null
purpose: string
capability_id: string
provider: string
request_count: integer
input_tokens: integer | null
output_tokens: integer | null
estimated_cost_usd: number
actual_cost_usd: number | null
budget_ref: string
timestamp: timestamp
```

## 21. Credential security

Raw secrets MUST NOT be placed in:

- source control;
- frontend payloads;
- model prompts;
- model context;
- logs;
- evidence artifacts;
- candidate skills;
- exported reports.

Runtime plans use references such as:

```text
credential_ref=cred_external_search_prod
```

The execution adapter resolves the credential at the latest practical point and exposes only the minimum secret material to the provider call that requires it.

## 22. Side-effect and risk model

Suggested side-effect classes:

| Class | Meaning | Default policy |
|---|---|---|
| `READ_ONLY` | Observe/query without intended state change | Allowed when in scope |
| `LOCAL_WRITE` | Change local non-privileged state | Validate + audit |
| `REMOTE_WRITE` | Change another device/service | Explicit authority + evidence + policy |
| `PRIVILEGED` | Admin/root/security-sensitive action | Strong approval policy |
| `DESTRUCTIVE` | Delete, reset, wipe, disable, irreversible/high-impact action | Human approval; fail closed |

Suggested task risk classes:

- `R0`: pure reasoning over supplied data;
- `R1`: read-only local/inventory-scoped observation;
- `R2`: active probes or local controlled writes;
- `R3`: remote/privileged consequential changes;
- `R4`: destructive, safety-critical, high-cost, or organization-wide effects.

Policy may require direct operator confirmation or physical-device confirmation for selected `R3/R4` operations.

## 23. Evidence, audit, and observability

Every execution SHOULD be reconstructable through a common trace:

```text
trace_id
  -> task_id
  -> plan_id/version
  -> node_id
  -> capability invocation
  -> observation
  -> evidence IDs
  -> subagent/delegation IDs
  -> artifact IDs
  -> approvals
  -> cost events
  -> final result
```

### 23.1 Required telemetry

WorkSpace SHOULD measure:

- task wall time;
- planner time;
- model inference count;
- model tokens;
- tool calls per inference;
- parallel execution utilization;
- capability success/failure rate;
- retry count;
- recovery rate;
- policy denials;
- approval latency;
- paid spend;
- evidence completeness;
- task completion rate;
- partial-result rate;
- hallucinated-action mismatch rate.

Audit records SHOULD be append-oriented and tamper-evident where practical.

## 24. Error taxonomy and retry policy

Normalized error classes SHOULD include:

```text
POLICY_DENIED
AUTHORITY_EXPIRED
INVALID_INPUT
DEPENDENCY_FAILURE
TIMEOUT
PROVIDER_ERROR
RATE_LIMIT
CREDENTIAL_ERROR
RESOURCE_CONFLICT
VALIDATION_FAILURE
PARTIAL_SUCCESS
UNAVAILABLE
NON_IDEMPOTENT_FAILURE
IRREVERSIBLE_FAILURE
CANCELLED
```

Retry rules:

- never retry `POLICY_DENIED` as a way to bypass policy;
- never blindly retry invalid input;
- retry transient provider/rate-limit failures only within budget;
- retry writes only when idempotency is proven or a safe reconciliation mechanism exists;
- revalidate authority and budget before delayed retries;
- record every retry in the trace.

## 25. Network, cybersecurity, monitoring, and device-diagnostics application

The runtime architecture is especially important for WorkSpace domain modules because useful diagnosis is not a single model answer.

### 25.1 Network/device diagnostic loop

```text
Target / incident
   |
   v
Inventory scope check
   |
   v
Passive evidence collection
   |
   v
Bounded active probes when permitted
   |
   v
Topology + dependency correlation
   |
   v
Hypothesis set
   |
   v
Discriminating tests
   |
   v
Root-cause confidence
   |
   v
Remediation proposal
   |
   +--> read-only report
   |
   +--> approved remediation action
              |
              v
        post-change verification
              |
              v
        evidence + audit
```

A missing device is not automatically a device failure. Diagnosis should correlate power/PoE, switch port, VLAN, ARP/MAC learning, routing, reachability, service health, camera protocols, monitoring history, and adjacent-device evidence according to available capabilities.

### 25.2 Cybersecurity/DFIR

Security investigation SHOULD use:

- read-only acquisition first;
- evidence hashing/provenance;
- time correlation;
- scoped queries;
- hypothesis-driven enrichment;
- strict distinction between observation and conclusion;
- explicit authority for active containment;
- separate forensic acquisition and remediation phases when required.

### 25.3 Monitoring

Monitoring events SHOULD be treated as signals, not final diagnoses.

The runtime may correlate:

- historical baselines;
- device dependencies;
- topology;
- neighboring failures;
- authentication/log events;
- power and PoE state;
- interface errors;
- packet/service probes;
- application telemetry.

### 25.4 Camera and edge systems

Camera/device procedures may combine:

- inventory identity;
- ARP/MAC evidence;
- vendor discovery protocols;
- ONVIF;
- RTSP;
- HTTP/HTTPS health;
- PoE/switch-port evidence;
- stream decoding evidence;
- edge-node resource evidence;
- configuration state;
- firmware/vendor runbooks.

The same authority/evidence contracts apply. A diagnostic skill does not receive unrestricted device-write permission simply because it knows how to configure the device.

## 26. Existing WorkSpace architecture relationship

This document does not replace the existing application architecture.

The current architecture already defines an Orchestrator, runtime stores, agent roles, a single Internet Gateway, an Execution Gateway, evidence-gated presentation generation, local model integration, and auditable artifact flows.

The agent runtime defined here sits underneath and across those product components:

```text
Existing WorkSpace product roles and UI
                |
                v
       WorkSpace Agent Runtime
  ---------------------------------
  Control | Authority | Context
  Registry| Scheduler | Evidence
  Skills  | Recovery  | Governance
  ---------------------------------
                |
                v
 Existing gateways / domain modules / adapters
```

Existing implementations that already satisfy these contracts SHOULD be retained and adapted rather than rewritten for architectural uniformity.

## 27. Implementation boundaries

The following components SHOULD become explicit modules/contracts over time. Names are architectural targets, not mandatory package names.

```text
runtime/
  task_context
  planner
  execution_plan
  scheduler
  checkpoints
  recovery

capabilities/
  registry
  descriptors
  adapters
  result_normalization

security/
  authority
  policy
  approvals
  credential_references

context/
  session
  retrieval
  compression
  memory

skills/
  active
  candidates
  validation
  promotion

agents/
  delegation
  specialists
  aggregation

evidence/
  records
  provenance
  audit
  artifacts

governance/
  grants
  budgets
  cost_ledger
  licensing

integrations/
  models
  mcp
  plugins
  external_services
```

Before creating any new module, implementation work MUST audit current source for an equivalent component and extend it when appropriate.

## 28. Implementation sequence

### P0 - Runtime contracts and guarded execution

- TaskContext;
- AuthorityEnvelope;
- CapabilityDescriptor/Registry;
- ExecutionPlan/DAG;
- normalized Observation;
- evidence linkage;
- policy revalidation at dispatch.

### P1 - Efficiency and resilience

- bounded concurrency;
- programmatic tool execution;
- deterministic fan-in;
- context compression;
- checkpoints;
- recovery/reconciliation;
- runtime metrics.

### P2 - Delegation and learning

- subagent DelegationContract;
- specialist profiles;
- candidate-skill lifecycle;
- post-task review;
- benchmark and security promotion gates.

### P3 - Extensibility and governed external capability

- MCP/plugin adapters;
- durable background jobs;
- external provider abstraction;
- purpose-bound paid capability grants;
- CostLedger;
- licensing metadata.

Implementation priority may change when live source audit proves that a target is already complete or a different gap has higher operational impact.

## 29. Acceptance metrics

A runtime improvement is accepted by measured outcome, not architectural appearance.

Minimum benchmark dimensions:

1. inference turns per completed task;
2. tool calls per inference turn;
3. wall-clock time to result;
4. parallel execution efficiency;
5. model-token consumption;
6. model/provider cost;
7. task completion rate;
8. partial-result quality;
9. failure recovery rate;
10. evidence completeness;
11. policy enforcement correctness;
12. approval correctness;
13. hallucinated-action mismatch rate;
14. deterministic replay/reconstruction coverage;
15. operator intervention rate.

A faster runtime that weakens authority or evidence guarantees is a regression.

## 30. Runtime invariants

These are non-negotiable product rules.

1. No executable action without valid authority.
2. Delegated authority cannot exceed parent authority.
3. Inventory/resource scope is enforced at runtime, not only described in prompts.
4. Raw credentials never enter model context.
5. Paid execution requires a valid purpose-bound grant when policy requires one.
6. Consequential actions follow approval policy.
7. Every executed node produces an Observation and trace linkage.
8. Evidence provenance survives aggregation and delegation.
9. Active skills are not silently self-modified.
10. Background jobs revalidate current authority and grants before execution.
11. External irreversible effects are never represented as automatically rollback-able.
12. Parallel result merging follows deterministic rules where possible.
13. Retries respect idempotency, authority, deadline, and budget.
14. Policy uncertainty fails closed for consequential execution.
15. The model cannot elevate itself, a tool, a plugin, or a subagent.
16. Tool/provider descriptions cannot override WorkSpace policy.
17. Context retrieval obeys security scope before semantic relevance.
18. Conclusions distinguish observed facts, inferred hypotheses, and proposed actions.
19. Production skill promotion requires validation and security policy.
20. Capability success claims require measurable evidence.

## 31. Product decision

WorkSpace should treat reasoning models as replaceable cognitive engines.

The durable competitive capability is the governed runtime around them:

```text
INTENT
  + CONTEXT
  + PROCEDURAL KNOWLEDGE
  + CAPABILITY DISCOVERY
  + AUTHORITY
  + PLANNING
  + PROGRAMMATIC EXECUTION
  + PARALLELISM
  + MEMORY
  + EVIDENCE
  + RECOVERY
  + LEARNING
  + AUDIT
  = OPERATIONAL INTELLIGENCE
```

This architecture allows WorkSpace to improve as models, local inference, tools, protocols, and external services evolve without surrendering security boundaries or rebuilding the product around each new model generation.
