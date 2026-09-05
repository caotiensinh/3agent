# Harness Agent v0.0.1

**Project:** WorkSpace (`caotiensinh/3agent`)  
**Document type:** Architecture + Runtime Harness Specification  
**Version:** `0.0.1`  
**Status:** Baseline specification; implementation is not implied by this document  
**Language:** Vietnamese prose; code, schemas, identifiers, test IDs, and commit evidence use English  
**Date:** 2026-09-03

---

## 1. Purpose

Harness Agent v0.0.1 defines the cognitive/runtime layer that sits between human input, WorkSpace agents, local/remote models, memory, knowledge, tools, and deterministic runtime policy.

The Harness is not a replacement LLM and is not another unrestricted agent. Its purpose is to make model execution more reliable by controlling:

- task interpretation;
- language normalization;
- knowledge scope;
- context selection and compression;
- long-running conversation continuity;
- reasoning strategy selection;
- adaptive problem solving;
- acceptance verification;
- failure recovery;
- memory curation;
- evidence provenance;
- capability/security boundaries.

The central design objective is:

> Deliver the smallest high-signal working context necessary to solve the current task, while preserving an auditable, durable, logically unbounded history outside the model context window.

A second equally important objective is:

> A task must not be marked complete merely because a model produced an answer. Completion requires evidence that the declared acceptance contract has passed.

---

## 2. Position inside WorkSpace

Harness v0.0.1 extends the current WorkSpace architecture rather than replacing it.

Existing architectural anchors remain authoritative:

- `Orchestrator`;
- SQLite `TaskStore` / `ActivityStore`;
- `KnowledgeGateway`;
- `InternetGateway`;
- `ExecutionGateway`;
- immutable `TaskContract`;
- `TaskModelAuthority`;
- `TaskCapabilityAuthority`;
- `CapabilityBroker`;
- local-first model adapters;
- JSON/Markdown audit artifacts.

Related baseline documents:

- [`ARCHITECTURE.md`](./ARCHITECTURE.md)
- [`CHAT_GATEWAY.md`](./CHAT_GATEWAY.md)
- [`CAPABILITY_BROKER.md`](./CAPABILITY_BROKER.md)

Harness MUST reuse these boundaries. It MUST NOT introduce a second authority model that can bypass `TaskContract`, and v0.0.1 MUST NOT require a second durable runtime database.

Conceptual placement:

```text
Human / LAN Chat / Future UI
            |
            v
+-------------------------------+
|       Cognitive Harness       |
|                               |
| Input + Task Compiler         |
| Context Compiler              |
| Memory OS                     |
| Strategy Router               |
| Meta-Solver                   |
| Adaptive Solver Loop          |
| Evaluator / Evidence Gate     |
+---------------+---------------+
                |
                v
          Orchestrator
                |
       +--------+--------+
       |                 |
       v                 v
 Research / Analyst / Security / Presentation / Other Agents
       |                 |
       +--------+--------+
                |
        Local LLM Adapter
                |
     +----------+-----------+
     |                      |
KnowledgeGateway      CapabilityBroker
     |                 /            \
InternetGateway   ExecutionGateway   bounded writes
```

The Harness controls cognition and context. Deterministic runtime authority remains outside model discretion.

---

## 3. Non-goals

Harness v0.0.1 does **not**:

1. grant capabilities that are absent from `TaskContract`;
2. convert arbitrary user text, web text, file content, tool output, or model output into system-level authority;
3. expose or require raw private chain-of-thought;
4. guarantee that every model can physically ingest one million tokens;
5. guarantee infinite execution loops;
6. replace ground-truth tests with an LLM judge when deterministic verification exists;
7. delete source history after summarization;
8. introduce autonomous Internet upload or network-write authority;
9. silently cross project/customer/security boundaries when retrieving memory;
10. claim implementation readiness merely because this specification exists.

---

## 4. Core architectural principles

### P-001 — User intent is preserved, not promoted to authority

Natural-language input is normalized into a structured `CanonicalTaskSpec`.

The Harness MUST NOT perform:

```text
User text -> promoted SYSTEM prompt -> model
```

It SHALL perform:

```text
User text
  -> Input classification
  -> Semantic normalization
  -> CanonicalTaskSpec
  -> TaskContract/authority projection
  -> Context planning
  -> Model input
```

The original user message remains available as immutable evidence.

### P-002 — Raw history is the source of truth

Summaries, embeddings, entity records, graph edges, checkpoints, and memories are indexes/derived views.

They MUST NOT replace or overwrite the source event.

### P-003 — Logical history and physical context are separate

The conversation may contain far more information than a model can ingest at one time.

The Harness preserves long-lived logical history while compiling only relevant working context for the current inference.

### P-004 — Correctness before optimization

Correctness, safety, authorization, and acceptance requirements are hard gates.

Speed, cost, token count, latency, elegance, and implementation complexity are optimization objectives only after mandatory gates pass.

### P-005 — No false completion

`SUCCESS` is legal only when all mandatory acceptance criteria are proven PASS.

### P-006 — Failure changes strategy

Repeated execution of the same strategy against the same state and same failure is not progress.

The Harness MUST detect stagnation and change strategy or reframe the problem.

### P-007 — Deterministic work stays deterministic

Sorting, hashing, exact filtering, counters, schema validation, permission checks, exact date arithmetic, deduplication, and state transitions SHOULD be implemented in deterministic code rather than delegated to an LLM.

### P-008 — Evidence and provenance are first-class

Critical facts, memory entries, task completion, and capability-sensitive decisions MUST be traceable to source evidence.

---

## 5. Trust and authority model

The Harness operates with explicit trust domains:

```text
T0  Runtime policy / immutable TaskContract
T1  Operator-approved project policy
T2  Authenticated user instruction
T3  Trusted internal project data
T4  Tool output
T5  Retrieved public-web data
T6  User-provided document content
T7  Generated model content
T8  Derived memory / summaries
```

Trust level does not automatically equal capability authority.

Only deterministic authority derived from `TaskContract` may authorize side effects.

### 5.1 Authority invariant

```text
Prompt text
Model output
Web content
File content
Tool output
Memory content
        |
        X
        |
        v
Capability grant
```

The above path is forbidden.

Allowed path:

```text
TaskContract
   |
   v
TaskModelAuthority
   |
   v
TaskCapabilityAuthority
   |
   v
CapabilityBroker
   |
   v
Approved bounded effect
```

### 5.2 Prompt-injection boundary

Untrusted content may provide data/evidence but MUST NOT redefine:

- system policy;
- tool permissions;
- write scope;
- network scope;
- memory-write policy;
- acceptance criteria;
- project identity;
- user identity;
- trusted instruction hierarchy.

---

## 6. Canonical Task Compiler

Every meaningful request is compiled into a typed internal representation.

Example:

```yaml
task_id: task_20260903_001
conversation_id: conv_xxx
project_scope: workspace

intent:
  primary: design_harness
  secondary:
    - context_compression
    - long_term_memory
    - adaptive_problem_solving

goal:
  statement: "Define a reusable cognitive harness for WorkSpace."
  preserve_user_intent: true

clarification_policy:
  mode: strict
  blocking_ambiguity_requires_user: true

constraints:
  privacy: local_first
  authority_source: task_contract
  external_write: denied_by_default
  preserve_raw_history: true
  evidence_required: true

knowledge_requirements:
  freshness: current_when_required
  project_memory: allowed
  public_web: task_contract_dependent

reasoning_policy:
  decomposition: adaptive
  retrieval_before_inference: true
  contradiction_check: true
  adaptive_solver_loop: true
  verification_required: true

output_contract:
  language: vi
  artifact: markdown
  detail: technical_spec

acceptance:
  contract_ref: acc_task_20260903_001
```

### 6.1 Clarification gate

In `strict` mode, the Harness MUST request clarification before execution when ambiguity could materially change:

- target repository/project;
- destructive/write target;
- user goal;
- acceptance condition;
- data sensitivity;
- authority/capability scope;
- irreversible action;
- security boundary.

Non-blocking stylistic ambiguity MAY be resolved by project defaults only when the decision is reversible and does not change the requested outcome.

---

## 7. Acceptance Contract

Before a non-trivial task enters execution, the Harness SHOULD create an explicit `AcceptanceContract`.

Example:

```yaml
acceptance_id: acc_001

required:
  - id: AC-01
    statement: "Document exists at the approved repository path."
    verifier: github_file_exists

  - id: AC-02
    statement: "Document version equals 0.0.1."
    verifier: exact_content_check

  - id: AC-03
    statement: "No existing architecture authority is bypassed."
    verifier: architecture_review

hard_gates:
  correctness: required
  authorization: required
  security: required
  evidence: required

optimization:
  - token_efficiency
  - execution_time
  - maintainability
  - complexity

prohibited:
  - bypass_task_contract
  - invent_pass_evidence
  - mark_success_with_failed_required_gate
```

Mandatory criteria are binary gates. Optional quality metrics may be scored.

---

## 8. Memory OS

The Harness memory model is layered.

### M0 — Immutable Event Log

Stores or references source events:

- user messages;
- assistant responses;
- tool calls;
- tool results;
- decisions;
- failures;
- artifacts;
- tests;
- commits;
- timestamps.

The event log is append-only at the logical level.

### M1 — Working Memory

Contains only information required for the current task:

- current goal;
- current state;
- active constraints;
- open blockers;
- latest decisions;
- current evidence;
- relevant entities.

Working memory is intentionally small and disposable because it can be reconstructed.

### M2 — Episodic Memory

Stores what happened.

Example:

```yaml
memory_id: mem_episode_001
type: episodic
timestamp: 2026-09-03T08:00:00+09:00
actor: ci
action: run_tests
object: commit_abc
result: pass
source_ref: event_123
confidence: 1.0
```

### M3 — Semantic Memory

Stores relatively stable facts with temporal validity.

```yaml
memory_id: mem_semantic_001
type: semantic
statement: "Current switch management IP is 192.168.11.116."
valid_from: 2026-08-31T00:00:00+09:00
valid_until: null
supersedes: mem_semantic_000
source_ref: event_987
confidence: 0.99
project_scope: network_lab
```

### M4 — Procedural Memory

Stores approved procedures and project conventions:

- deployment procedure;
- testing procedure;
- release procedure;
- incident procedure;
- coding conventions;
- security policy;
- known operational playbooks.

Procedural memory MUST NOT be created from untrusted web/file instructions without trusted approval.

### M5 — Knowledge Memory

Indexes project knowledge:

- source code;
- specifications;
- manuals;
- research;
- tickets;
- logs;
- schemas;
- reports;
- approved external sources.

Knowledge remains outside active context until retrieved.

---

## 9. Memory provenance and temporal truth

Every durable memory record MUST include enough provenance to answer:

- Who/what produced this information?
- When was it valid?
- Which project/task does it belong to?
- What source event/artifact supports it?
- How confident is the system?
- Has a newer record superseded it?

Critical memory MUST NOT exist as an unsupported plain statement.

### 9.1 Contradiction handling

Old facts are not silently deleted.

Example:

```text
old: server_ip = 192.168.11.100
new: server_ip = 192.168.11.116
```

The new record SHALL supersede the old record with temporal boundaries.

This allows both:

- "What is the IP now?"
- "What was the IP before the change?"

to be answered correctly.

### 9.2 Memory promotion

Candidate memory flow:

```text
source event
   -> candidate extraction
   -> importance scoring
   -> novelty check
   -> contradiction check
   -> project/sensitivity classification
   -> trust/security check
   -> provenance check
   -> durable memory write
```

Not every message becomes memory.

### 9.3 Memory poisoning protection

External web pages, uploaded files, tool output, and model-generated text MUST NOT directly create high-trust procedural authority.

Memory writes derived from untrusted content require:

- source classification;
- bounded scope;
- provenance;
- no authority escalation;
- optional trusted confirmation when required by policy.

---

## 10. Long-running conversation model

### 10.1 Requirement

WorkSpace SHALL target at least **1,000,000 tokens of persisted logical conversation history per conversation** without requiring that the full history be supplied to the model on every turn.

This is a logical-history requirement, not a universal model-context guarantee.

### 10.2 Physical context

`physical_context_limit` is model-dependent.

The Harness MUST discover/configure the actual model limit and never assume one million physical tokens.

### 10.3 Effective working context

For each model invocation:

```text
logical history
      |
      v
retrieval + ranking + compaction
      |
      v
task-specific working context
      |
      v
model
```

Typical working context SHOULD be significantly smaller than total persisted history.

### 10.4 Architectural invariant

```text
logical_history_size != inference_context_size
```

The long-term architecture SHALL remain valid if future models expose smaller or larger context windows.

---

## 11. Context Compiler

The Context Compiler determines what the model sees.

Inputs may include:

- trusted system/runtime policy;
- current `TaskContract` projection;
- `CanonicalTaskSpec`;
- `AcceptanceContract`;
- recent conversation turns;
- current project state;
- retrieved memory;
- retrieved knowledge;
- tool evidence;
- failure history;
- current strategy state.

Conceptual budget:

```text
SYSTEM / SECURITY POLICY
TASK AUTHORITY
CANONICAL TASK SPEC
ACCEPTANCE CONTRACT
RECENT HIGH-VALUE TURNS
PROJECT STATE
RELEVANT MEMORY
RETRIEVED KNOWLEDGE
TOOL EVIDENCE
FAILURE / STRATEGY STATE
OUTPUT RESERVE
```

The budget is adaptive, not fixed.

---

## 12. Context compression

Compression MUST preserve recoverability.

Forbidden design:

```text
100k raw history
   -> 2k summary
   -> delete raw history
```

Required design:

```text
Raw history
  |
  +-> hierarchical summaries
  +-> event index
  +-> entity index
  +-> decision index
  +-> temporal index
  +-> semantic/vector index when enabled
  +-> source pointers
```

### 12.1 Hierarchical summary levels

```text
Turn
 -> Episode
 -> Session
 -> Daily/Work period
 -> Project
 -> Project lifetime
```

Every derived summary SHOULD preserve pointers to lower-level source records.

### 12.2 Compression modes

1. **Lossless structural compression**
   - deduplicate repeated schemas;
   - remove repeated boilerplate;
   - collapse repeated tool metadata;
   - reference large artifacts by ID/hash.

2. **Extractive compression**
   - preserve exact errors;
   - IDs;
   - numbers;
   - commands;
   - decisions;
   - evidence excerpts.

3. **Abstractive compression**
   - narrative/background only;
   - never the sole source for critical facts.

### 12.3 Compaction thresholds

Thresholds are configurable, but the recommended starting policy is:

```yaml
soft_threshold: 0.60
hard_threshold: 0.80
emergency_threshold: 0.92
```

At soft threshold:

- deduplicate;
- evict obsolete derived material;
- replace large tool output with artifact references.

At hard threshold:

- create/update checkpoint;
- compress older working context;
- preserve critical evidence verbatim.

At emergency threshold:

- build a fresh model context;
- rehydrate from checkpoint + source retrieval;
- never delete the persistent logical history.

---

## 13. Checkpoint model

A checkpoint is a compact reconstruction anchor.

```yaml
checkpoint_id: chk_001
task_id: task_001
conversation_id: conv_001
created_at: 2026-09-03T08:30:00+09:00

goal:
  ...

current_state:
  ...

completed:
  ...

open_tasks:
  ...

decisions:
  ...

constraints:
  ...

known_failures:
  ...

important_entities:
  ...

latest_evidence:
  ...

next_action:
  ...

source_refs:
  - event_...
  - artifact_...

integrity:
  content_hash: sha256:...
```

A checkpoint is not allowed to become an untraceable replacement for source history.

---

## 14. Retrieval

Harness SHOULD support hybrid retrieval.

```text
Query
  |
  +-> recent-context retrieval
  +-> exact/keyword retrieval
  +-> semantic retrieval
  +-> entity retrieval
  +-> temporal retrieval
  +-> relationship/graph traversal when implemented
```

Candidate results flow through:

```text
candidate retrieval
 -> authority/scope filter
 -> freshness filter
 -> conflict detection
 -> deduplication
 -> reranking
 -> token-budget selection
 -> source pointer preservation
```

A vector similarity score alone MUST NOT be treated as truth.

---

## 15. Reasoning Strategy Router

The Harness selects a structured problem-solving strategy rather than demanding raw chain-of-thought.

Strategy families may include:

```text
FACT_LOOKUP
DIAGNOSTIC
ROOT_CAUSE
ARCHITECTURE
CODE_CHANGE
SECURITY_REVIEW
RESEARCH
COMPARISON
PLANNING
MATHEMATICAL
INCIDENT_RESPONSE
DECISION_SUPPORT
```

A strategy defines observable steps such as:

```yaml
strategy: ROOT_CAUSE
steps:
  - establish_current_state
  - gather_evidence
  - generate_hypotheses
  - eliminate_candidates
  - execute_safe_test
  - verify_result
```

The Harness records decisions, evidence, and outcomes; it does not require storage of private raw chain-of-thought.

---

## 16. Adaptive Problem-Solving Loop (APSL)

APSL is a mandatory Harness capability for non-trivial execution tasks.

```text
Goal
  |
  v
AcceptanceContract
  |
  v
Observe current state
  |
  v
Select strategy
  |
  v
Execute bounded action
  |
  v
Collect evidence
  |
  v
Evaluate
  |
  +---- PASS all mandatory gates ----> SUCCESS
  |
  +---- FAIL ----> classify failure
                    |
                    v
                gap analysis
                    |
                    v
             stagnation detection
                /          \
              no            yes
              |              |
           refine        escape mode
              |              |
              +------> new strategy
                            |
                            v
                        execute again
```

### 16.1 No false-success invariant

The following is forbidden:

```text
model says "done"
-> SUCCESS
```

Required:

```text
result
 -> evaluator
 -> acceptance checks
 -> evidence
 -> all mandatory PASS
 -> SUCCESS
```

---

## 17. Failure taxonomy

Failures SHALL be classified before retry where practical.

Baseline classes:

```text
KNOWLEDGE_GAP
WRONG_ASSUMPTION
WRONG_STRATEGY
IMPLEMENTATION_ERROR
TOOL_ERROR
ENVIRONMENT_ERROR
DEPENDENCY_ERROR
PERMISSION_ERROR
MISSING_EVIDENCE
AMBIGUOUS_REQUIREMENT
RESOURCE_LIMIT
SECURITY_CONSTRAINT
TEST_FAILURE
PERFORMANCE_FAILURE
STAGNATION
EXTERNAL_BLOCKER
UNKNOWN
```

Retry behavior depends on failure type.

Examples:

- `TOOL_ERROR` may permit bounded retry;
- `WRONG_STRATEGY` requires strategy change;
- `AMBIGUOUS_REQUIREMENT` enters clarification state;
- `PERMISSION_ERROR` MUST NOT be solved by expanding authority;
- `EXTERNAL_BLOCKER` can terminate as `BLOCKED` with evidence;
- `SECURITY_CONSTRAINT` MUST fail closed.

---

## 18. Stagnation Detector

The Harness MUST detect "busy but not progressing".

Example signals:

```text
progress_delta <= threshold for N iterations
same_failure_signature >= N
same_result_signature >= N
same strategy + same state + same failure
acceptance_pass_count unchanged
```

Recommended initial defaults:

```yaml
same_failure_limit: 2
no_progress_limit: 3
minimum_meaningful_progress_delta: 0.01
```

These are policy defaults, not universal constants.

---

## 19. Anti-loop fingerprint

Each attempt SHOULD have a deterministic fingerprint.

```yaml
attempt_id: att_003
problem_state_hash: sha256:...
strategy_family: CONFIG_DIFF
strategy_hash: sha256:...
input_evidence_hash: sha256:...
tool_sequence_hash: sha256:...
result_signature: sha256:...
failure_signature: sha256:...
acceptance_snapshot_hash: sha256:...
```

If the Harness detects:

```text
same problem state
+ same strategy
+ same relevant inputs
+ same failure
```

it SHOULD block blind retry and require one of:

- new evidence;
- new strategy;
- problem decomposition;
- problem reframing;
- user clarification;
- verified external dependency change.

---

## 20. Escape Mode and strategy diversity

When stagnation is detected, the Harness SHALL avoid producing multiple superficial variants of the same approach.

It SHOULD generate different strategy families.

Example for software debugging:

```text
MINIMAL_REPRODUCTION
LOG_ANALYSIS
BISECTION
DEPENDENCY_CHECK
CONFIG_DIFF
ENVIRONMENT_DIFF
STATIC_ANALYSIS
RUNTIME_TRACE
ROLLBACK_COMPARE
REFERENCE_IMPLEMENTATION
ISOLATE_COMPONENT
REWRITE_COMPONENT
```

Example for network diagnostics:

```text
L1_PHYSICAL
L2_SWITCHING
L3_ROUTING
DNS_DIAGNOSTIC
FIREWALL_PATH
MTU_ANALYSIS
PACKET_CAPTURE
ROUTE_COMPARE
CONFIG_DIFF
END_TO_END_TRACE
```

Example for research:

```text
PRIMARY_SOURCE
CROSS_SOURCE
COUNTER_EVIDENCE
HYPOTHESIS_SEARCH
TEMPORAL_SEARCH
ENTITY_SEARCH
LITERATURE_EXPANSION
```

---

## 21. Adaptive branching

The Harness SHOULD not create a large solution tree by default.

Recommended policy:

```text
normal case      -> 1 active strategy
first failure    -> 2-3 alternatives
stagnation       -> 3-5 genuinely different alternatives
critical sandbox -> bounded parallel exploration
```

Low-value branches are pruned after evaluation.

---

## 22. Explore -> Evaluate -> Exploit

APSL uses an optimization cycle:

### Explore

Generate bounded, materially different candidate strategies.

### Evaluate

Prefer deterministic ground truth:

- tests;
- compiler;
- linter;
- benchmark;
- CI;
- network measurements;
- API result;
- database constraint;
- permission test;
- policy test;
- security negative test.

### Exploit

Choose the best candidate that passes hard gates, then refine it.

LLM-based judging is supplemental when deterministic evaluation is impossible.

---

## 23. Solution selection

Correctness and safety are hard constraints.

Example:

```yaml
hard_gates:
  correctness: pass
  security: pass
  authorization: pass
  mandatory_acceptance: pass

optimization_metrics:
  time_to_solution: 0.90
  token_efficiency: 0.84
  maintainability: 0.95
  implementation_complexity: 0.88
  operational_risk: 0.97
```

A faster solution MUST NOT defeat a correct/safe solution if the faster solution fails a hard gate.

When multiple candidates pass, Pareto-style selection SHOULD prefer solutions that are not dominated across:

- execution time;
- resource cost;
- complexity;
- maintainability;
- reliability;
- operational risk.

---

## 24. Requirement Gap Loop

After each execution:

```text
actual result
   |
   v
compare to AcceptanceContract
   |
   v
gap set
   |
   +-> empty -> SUCCESS
   |
   +-> non-empty -> create next bounded solving objective
```

Example:

```text
required latency <= 200 ms
actual latency    = 318 ms
gap               = 118 ms
```

The next iteration targets the remaining gap rather than repeating the full task blindly.

---

## 25. Dynamic decomposition

When a problem is too large or poorly separable, the Harness SHOULD recursively decompose it.

```text
Goal
 +-- A
 +-- B
 +-- C
 +-- D
```

A subproblem may decompose again:

```text
B
 +-- B1
 +-- B2
 +-- B3
       +-- B3.1
       +-- B3.2
```

Decomposition continues until tasks are independently solvable and independently verifiable.

Where dependencies permit, priority SHOULD favor closing near-complete high-value work before opening additional work in order to reduce work-in-progress.

---

## 26. Meta-Solver

The Solver asks:

> How do we solve the current problem?

The Meta-Solver asks:

> Why is the current framing or strategy failing, and what should change?

The Meta-Solver is activated by conditions such as:

- repeated stagnation;
- contradictory evidence;
- multiple strategy-family failures;
- acceptance score not improving;
- evidence suggesting the reported symptom is not the root problem.

### 26.1 Problem reframing

The Meta-Solver may replace the current hypothesis/problem framing, but MUST NOT silently replace the user's goal or authority constraints.

Example:

```text
symptom: RTSP lag
possible root domains:
  - network jitter
  - TCP retransmission
  - decoder saturation
  - buffering policy
  - renderer latency
```

The Harness may reframe "fix RTSP" into a bounded root-cause investigation while preserving the original desired outcome.

---

## 27. Learning Loop

The Harness learns operationally through approved memory, not by silently changing model weights.

### 27.1 Failure experience

```yaml
experience_id: exp_fail_001
problem_signature: sha256:...
environment_signature: sha256:...
strategy: DEPENDENCY_REINSTALL
outcome: failed
failure_class: WRONG_STRATEGY
evidence_refs:
  - event_...
lesson: "Failure was caused by mixed runtime configuration, not package absence."
avoid_when:
  - config_mismatch_present
```

### 27.2 Success experience

```yaml
experience_id: exp_success_001
problem_signature: sha256:...
strategy: CONFIG_DIFF
outcome: success
verification:
  - test_001
  - test_002
success_rate_snapshot: 0.91
median_time_seconds: 720
```

Future strategy selection may use historical success/failure rates as ranking signals.

Historical experience NEVER grants new capability authority.

---

## 28. Safe exploration policy

A previously successful strategy should usually receive priority, but controlled exploration is useful in sandbox/test environments.

Example policy:

```yaml
environment: sandbox
best_known_strategy_probability: 0.90
safe_exploration_probability: 0.10
```

For production or sensitive tasks:

```yaml
environment: production
safe_exploration_probability: 0.00
```

unless explicitly permitted by policy and bounded by tests/canary controls.

New risky strategies SHOULD follow:

```text
sandbox
 -> test
 -> benchmark
 -> security verification
 -> comparison
 -> canary when applicable
 -> production
```

---

## 29. Stop conditions

"Do not stop until correct" is represented as:

> The Harness MUST NOT report `SUCCESS` until all required acceptance gates pass.

This does not permit infinite uncontrolled looping.

Legal terminal states:

```text
SUCCESS
PARTIAL
BLOCKED
IMPOSSIBLE
FAILED_SAFE
ABORTED
```

### SUCCESS

All mandatory criteria pass.

### PARTIAL

Only legal when the `AcceptanceContract` explicitly permits independently useful partial completion.

### BLOCKED

Execution cannot proceed because of a proven external dependency, permission, credential, unavailable service, missing hardware, or required human input.

### IMPOSSIBLE

Evidence demonstrates that the requested outcome cannot be achieved under the current constraints.

### FAILED_SAFE

The system cannot prove a safe/correct continuation and therefore fails closed.

### ABORTED

A trusted operator, policy, safety boundary, or explicit execution budget terminates the run.

None of these states may be mislabeled as `SUCCESS`.

---

## 30. Progress measurement

Each iteration SHOULD expose machine-readable progress.

```yaml
iteration: 4
acceptance:
  passed: 17
  total_required: 20

completion_ratio: 0.85

quality_score:
  previous: 0.71
  current: 0.84
  delta: 0.13

unresolved:
  - AC-08
  - AC-11
  - AC-19
```

Progress is based primarily on acceptance coverage and evidence, not model self-assessment.

---

## 31. Runtime state machine

Baseline state model:

```text
NEW
 |
 v
NORMALIZING
 |
 v
CLARIFICATION_REQUIRED <----+
 |                          |
 v                          |
READY                       |
 |                          |
 v                          |
RUNNING --------------------+
 |
 +-> VERIFYING
 |     |
 |     +-> SUCCESS
 |     |
 |     +-> GAP_ANALYSIS
 |             |
 |             +-> RUNNING
 |             +-> STAGNATED
 |
 +-> STAGNATED
       |
       v
   REFRAMING
       |
       +-> RUNNING
       +-> CLARIFICATION_REQUIRED
       +-> BLOCKED
       +-> FAILED_SAFE
```

---

## 32. End-to-end runtime flow

Baseline flow:

```text
01 Receive authenticated input
02 Append raw source event
03 Classify trust/sensitivity
04 Normalize language without changing intent
05 Resolve project/conversation scope
06 Compile CanonicalTaskSpec
07 Run clarification gate
08 Bind/validate TaskContract authority
09 Build AcceptanceContract
10 Resolve entities and temporal references
11 Retrieve current project state
12 Retrieve relevant memories
13 Retrieve relevant knowledge
14 Detect conflicts/staleness
15 Select reasoning strategy
16 Allocate context budget
17 Compile model working context
18 Invoke model/agent
19 Request bounded capability decisions
20 Execute authorized tools
21 Collect ground-truth evidence
22 Evaluate AcceptanceContract
23 If PASS -> SUCCESS
24 If FAIL -> classify failure + gap
25 Detect stagnation / anti-loop collision
26 Refine, decompose, reframe, or change strategy
27 Repeat bounded execution
28 Curate success/failure experience
29 Update memory/checkpoint
30 Append auditable terminal state
```

---

## 33. Storage model for v0.0.1

Harness v0.0.1 SHALL reuse the current WorkSpace storage direction:

- SQLite for durable runtime state;
- JSON/JSONL for append/audit interchange where already used;
- Markdown/JSON for curated artifacts/evidence;
- filesystem/object-style artifact references for large tool output;
- GitHub for versioned source/specification/curated artifacts;
- local secret/config locations outside Git.

Suggested logical tables/entities can be added to the existing database rather than creating a second database:

```text
harness_events
harness_memories
harness_memory_links
harness_checkpoints
harness_attempts
harness_strategy_stats
harness_acceptance
harness_context_manifests
```

This document does not mandate a schema migration yet.

Vector indexing MAY be introduced later. It is not required for v0.0.1 specification compliance.

Graph relationships MAY initially be represented in SQLite relational tables. A separate graph database is not required.

---

## 34. Context Manifest

Every significant model invocation SHOULD be auditable through a context manifest without storing secret/private prompt bodies in unsafe telemetry.

```yaml
context_manifest_id: ctx_001
task_id: task_001
model_id: local_model_x
created_at: 2026-09-03T09:00:00+09:00

token_budget:
  max_input: 120000
  reserved_output: 12000
  compiled_input: 68421

sections:
  - type: task_spec
    source_hash: sha256:...
    tokens: 1300

  - type: memory
    item_count: 18
    source_hash: sha256:...
    tokens: 8200

  - type: knowledge
    item_count: 11
    source_hash: sha256:...
    tokens: 22000

compaction:
  applied: true
  mode:
    - structural
    - extractive

authority_fingerprint: sha256:...
```

---

## 35. Observability and metrics

Minimum Harness metrics:

```text
intent_fidelity
clarification_rate
critical_memory_recall
temporal_fact_accuracy
contradiction_detection_rate
critical_fact_retention_after_compaction
context_relevance
context_redundancy
context_token_count
logical_history_token_count
compression_ratio
retrieval_precision
retrieval_source_coverage
acceptance_pass_ratio
iteration_count
progress_delta
stagnation_count
strategy_switch_count
same_failure_retry_block_count
time_to_solution
tool_failure_rate
unauthorized_capability_attempts
cross_scope_memory_leak_count
memory_poisoning_block_count
```

Security counters MUST NOT include raw secrets or sensitive content.

---

## 36. Evaluation harness

Harness quality is not judged by appearance alone.

### 36.1 Intent fidelity

Can the compiler preserve the user's real objective after normalization?

### 36.2 Memory recall

Can the system recover a critical fact after long conversation history?

### 36.3 Temporal correctness

Can it distinguish current and superseded facts?

### 36.4 Contradiction handling

Does new verified information supersede old memory without destroying historical truth?

### 36.5 Compression fidelity

Does compaction preserve critical IDs, numbers, constraints, evidence, and decisions?

### 36.6 Adaptive solving

Does the system change strategy after repeated failure rather than retrying blindly?

### 36.7 Completion fidelity

Does `SUCCESS` occur only when mandatory acceptance checks pass?

### 36.8 Security

Can untrusted content:

- alter capability authority?
- poison procedural memory?
- escape project scope?
- turn public-web data into trusted instruction?
- cause unauthorized network/write side effects?

Expected answer for all is **no**.

---

## 37. Long-context test matrix

The Harness SHOULD be tested with persisted logical histories at:

```text
1K tokens
10K tokens
50K tokens
100K tokens
250K tokens
500K tokens
1M tokens
5M+ logical tokens
```

The `5M+` tier validates architecture beyond the initial one-million-token target; it does not require any single model call to contain 5M tokens.

Test families:

```text
NEEDLE_RETRIEVAL
MULTI_HOP_RETRIEVAL
TIMELINE_RECONSTRUCTION
UPDATED_FACT
CONTRADICTION
PROJECT_CONTINUATION
PROCEDURAL_MEMORY
CROSS_SESSION_MEMORY
SOURCE_PROVENANCE
COMPACTION_FIDELITY
SCOPE_ISOLATION
```

---

## 38. Adaptive solver test matrix

Required scenarios:

```text
ASL-001  first strategy succeeds
ASL-002  first strategy fails, second succeeds
ASL-003  repeated same failure triggers strategy switch
ASL-004  same-state/same-strategy fingerprint blocks blind retry
ASL-005  problem decomposition creates independently verifiable subtasks
ASL-006  meta-solver reframes symptom into root-cause investigation
ASL-007  deterministic test defeats optimistic model claim
ASL-008  hard security gate defeats faster unsafe solution
ASL-009  external blocker returns BLOCKED, never SUCCESS
ASL-010  successful strategy becomes ranked experience without granting authority
```

---

## 39. Security test matrix

```text
SEC-HARNESS-001  user text cannot mint capability
SEC-HARNESS-002  web content cannot mint capability
SEC-HARNESS-003  tool output cannot mint capability
SEC-HARNESS-004  model output cannot expand write_scope
SEC-HARNESS-005  untrusted content cannot create trusted procedural memory
SEC-HARNESS-006  memory retrieval is project/scope bounded
SEC-HARNESS-007  secrets are absent from audit-safe manifests
SEC-HARNESS-008  failed capability request produces no inner side effect
SEC-HARNESS-009  compaction does not drop mandatory security constraint
SEC-HARNESS-010  stale/superseded memory is not presented as current fact
```

---

## 40. Architectural invariants

### H-INV-001

User content MUST NOT become system/capability authority.

### H-INV-002

Persistent raw history MUST remain recoverable after compaction.

### H-INV-003

Derived summaries MUST preserve provenance to source history.

### H-INV-004

Memory retrieval MUST respect project/task/security scope.

### H-INV-005

`SUCCESS` MUST require all mandatory acceptance gates to pass.

### H-INV-006

Same-state + same-strategy + same-failure blind retry MUST be detected and bounded.

### H-INV-007

Strategy selection, model routing, or stronger reasoning MUST NOT expand capability authority.

### H-INV-008

Untrusted content MUST NOT directly create trusted procedural memory.

### H-INV-009

Critical durable memory MUST contain provenance.

### H-INV-010

Compaction MUST be reconstructable through checkpoints/source pointers.

### H-INV-011

Logical conversation history MUST NOT be bounded by the physical inference context window.

### H-INV-012

Deterministic policy/permission decisions MUST stay outside model discretion.

### H-INV-013

A model's self-reported confidence MUST NOT substitute for evidence.

### H-INV-014

A terminal non-success state MUST state the exact blocker/failure evidence available.

### H-INV-015

Harness MUST reuse WorkSpace authority boundaries rather than create a parallel bypass path.

---

## 41. Initial KPI targets

These are target metrics for implementation/evaluation, not claims about current code.

```text
Intent preservation                 >= 99%
Critical-memory recall              >= 95%
Temporal correctness                >= 95%
Contradiction detection             >= 95%
Critical fact retention             >= 99% for declared critical fields
Raw history recoverability          = 100%
Critical memory provenance          = 100%
Required acceptance evidence        = 100%
Unauthorized memory authority write = 0
Cross-project memory leakage         = 0
Capability escalation via content    = 0
False SUCCESS on required gate fail  = 0
```

Typical compression objective:

```text
2x-10x working-context reduction
```

but compression ratio is secondary to critical-information retention.

---

## 42. Implementation sequence

This document defines the target. Implementation should proceed incrementally and reuse existing code.

### Phase H0 — Specification baseline

- commit this document;
- map existing runtime components;
- identify reusable TaskContract/Store/Gateway interfaces;
- create implementation checklist.

### Phase H1 — Task Compiler + Acceptance Contract

- typed `CanonicalTaskSpec`;
- typed `AcceptanceContract`;
- clarification state;
- invariant tests.

### Phase H2 — Memory foundation

- append-only logical event records;
- memory provenance;
- temporal supersession;
- checkpoint format;
- scope isolation.

### Phase H3 — Context Compiler

- context manifest;
- token budgeting;
- structural/extractive compaction;
- source pointers;
- rehydration tests.

### Phase H4 — Adaptive Solver Loop

- failure taxonomy;
- attempt fingerprint;
- stagnation detector;
- strategy switch;
- requirement gap loop;
- completion gate.

### Phase H5 — Meta-Solver + Strategy Memory

- problem reframing;
- success/failure experience;
- strategy statistics;
- safe ranking.

### Phase H6 — Long-context evaluation

- 100K;
- 250K;
- 500K;
- 1M logical-token tests;
- cross-session continuation;
- compaction fidelity.

### Phase H7 — Enterprise hardening

- security gates;
- load tests;
- concurrency;
- crash recovery;
- audit retention;
- operator observability;
- production rollout policy.

---

## 43. Definition of Done for Harness v0.0.1 implementation

The specification version and implementation version are distinct.

An implementation MAY claim `Harness v0.0.1 PASS` only when exact-head evidence demonstrates at minimum:

```text
HDOD-001 CanonicalTaskSpec implemented and schema-tested
HDOD-002 AcceptanceContract implemented
HDOD-003 TaskContract authority remains immutable and authoritative
HDOD-004 raw event history remains recoverable
HDOD-005 scoped memory with provenance implemented
HDOD-006 temporal supersession tested
HDOD-007 context manifest + token budget implemented
HDOD-008 compaction preserves critical fields in tests
HDOD-009 adaptive solver changes strategy after stagnation
HDOD-010 blind retry fingerprint works
HDOD-011 SUCCESS is impossible with a failed mandatory gate
HDOD-012 BLOCKED/FAILED_SAFE terminal states are evidenced
HDOD-013 untrusted content cannot mint capability
HDOD-014 untrusted content cannot poison trusted procedural memory
HDOD-015 1M logical-history continuation test passes
HDOD-016 existing WorkSpace regression suite passes
HDOD-017 exact-head CI evidence is recorded
```

No percentage or READY claim should override a failed mandatory item.

---

## 44. Design summary

Harness Agent v0.0.1 is best understood as four cooperating control loops:

### Cognitive Loop

```text
understand
 -> retrieve
 -> compile context
 -> choose reasoning strategy
 -> produce candidate action/answer
```

### Solver Loop

```text
attempt
 -> execute
 -> collect evidence
 -> verify
 -> gap analysis
 -> refine/change strategy
 -> repeat
```

### Meta-Solver Loop

```text
detect stagnation
 -> inspect failure pattern
 -> decompose or reframe problem
 -> choose a different strategy family
 -> return to Solver Loop
```

### Learning Loop

```text
observe success/failure
 -> extract bounded experience
 -> verify provenance/trust
 -> update strategy/memory statistics
 -> improve future ranking
```

Together:

```text
                   +-------------------+
                   |   Human Goal      |
                   +---------+---------+
                             |
                             v
                   CanonicalTaskSpec
                             |
                             v
                   AcceptanceContract
                             |
          +------------------+------------------+
          |                                     |
          v                                     v
      Memory OS                          Knowledge / Tools
          |                                     |
          +------------------+------------------+
                             |
                             v
                      Context Compiler
                             |
                             v
                        Meta-Solver
                             |
                             v
                      Strategy Router
                             |
                             v
                    Adaptive Solver Loop
                             |
                             v
                    Evidence / Evaluator
                         /          \
                       PASS         FAIL
                        |             |
                        v             v
                     SUCCESS      Gap/Failure
                                      |
                              Stagnation Detector
                                  /        \
                                no          yes
                                |            |
                              refine      reframe/
                                |          escape
                                +-----+------+
                                      |
                                      v
                                  next attempt
                                      |
                                      v
                               Learning Memory
```

The design goal is not "make the prompt longer."

The design goal is:

> Make WorkSpace continuously aware of the right task, the right evidence, the right history, the right authority, and the right next strategy — while keeping every important claim reconstructable from source evidence.

---

## 45. Normative v0.0.1 statement

For WorkSpace Harness Agent v0.0.1:

1. The Harness SHALL compile natural-language requests into structured task specifications.
2. The Harness SHALL preserve immutable/raw source history independently from derived summaries.
3. The Harness SHALL maintain scoped, provenance-aware memory.
4. The Harness SHALL support at least one million tokens of persisted logical conversation history as an architectural target.
5. The Harness SHALL compile bounded task-specific working context according to the actual model context limit.
6. The Harness SHALL use explicit acceptance contracts for non-trivial work.
7. The Harness SHALL continue problem solving after failed attempts by changing strategy, decomposing, or reframing when appropriate.
8. The Harness SHALL detect and prevent blind same-state/same-strategy retry loops.
9. The Harness SHALL prefer deterministic evidence over model self-evaluation.
10. The Harness SHALL never report `SUCCESS` while a mandatory acceptance gate is failing.
11. The Harness SHALL fail closed on authority/security ambiguity.
12. The Harness SHALL not allow prompt, model, web, file, tool, or memory content to expand runtime authority.
13. The Harness SHALL reuse WorkSpace's existing `TaskContract`, Capability Broker, gateways, and durable-state architecture.
14. The Harness SHALL preserve evidence needed to explain terminal `BLOCKED`, `IMPOSSIBLE`, `FAILED_SAFE`, or `ABORTED` outcomes.
15. The Harness SHALL be model-agnostic and SHOULD reserve strong models for reasoning tasks while using deterministic code or smaller models for routing/compression/classification where validated.

This document is the architecture baseline for subsequent Harness implementation work.
