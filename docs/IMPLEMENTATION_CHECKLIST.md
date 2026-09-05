# WorkSpace Pico-First Implementation Checklist

**Execution rule:** implement in dependency order. Do not skip a `NEXT` item to install a later optional optimization. Every completed item requires code/evidence/tests. Optional technologies may complete as `REJECTED` if benchmarks do not justify adoption.

## Status legend

`DONE` · `NEXT` · `TODO` · `PARTIAL` · `BENCHMARK-GATED` · `DEFERRED` · `REJECTED`

---

## P0 — Pico-first foundation

### PICO-001 — Codify Pico-first doctrine — `DONE`

Acceptance:
- normative doctrine exists;
- explicitly separates PicoLM inspiration from WorkSpace implementation;
- defines resource, deterministic-control, escalation, replaceability, and benchmark laws.

Evidence:
- `docs/PICO_FIRST_ENGINEERING_PHILOSOPHY.md`
- `docs/ENGINEERING_DOCTRINE_INDEX.md`

### PICO-002 — Preserve runtime replaceability — `DONE`

Acceptance:
- Pico-first doctrine does not require migration from Ollama to PicoLM;
- serving engines remain implementation adapters;
- optional serving migration is benchmark-gated.

### PICO-003 — Minimum-hot-working-set contract — `PARTIAL`

Goal: make hot/cold state explicit for context, models, artifacts, and task state.

Acceptance still required:
- runtime-visible hot-set accounting for active context/evidence;
- no eager materialization path without a documented reason;
- tests for bounded context/materialization behavior.

### PICO-004 — Eliminate probabilistic syntax repair — `DONE`

Evidence:
- native Ollama JSON Schema structured output;
- deterministic schema validation;
- malformed/schema-invalid JSON does not trigger model-based repair retry.

### PICO-005 — Metadata-only inference telemetry — `DONE`

Acceptance:
- inference timings/token counters/hashes can be logged;
- raw prompt/response/source text is not required or persisted by runtime telemetry.

---

## P1 — Trust boundaries and deterministic handoffs

### SEC-001 — Enforce sanitizer at Agent 1 → Agent 2 handoff — `NEXT`

Problem: `sanitize_untrusted_payload()` exists as a primitive, but the canonical Research → Presentation handoff does not yet enforce it as a real boundary.

Implementation:
- sanitize research-derived handoff data before Presentation consumes it;
- preserve suspicious text as **data**, never capability/instruction;
- attach deterministic security metadata: sanitizer version, risk level, finding count/types;
- make sanitization idempotent;
- preserve source/fact lineage;
- do not break research↔handoff consistency validation.

Acceptance tests:
- zero-width/control characters normalized/removed deterministically;
- injection-like `SYSTEM:`, `ignore previous...`, role-switch text remains inert data and is flagged;
- clean handoff remains semantically unchanged;
- Presentation accepts a valid sanitized handoff;
- task/source/fact lineage remains exact;
- no new network/tool/credential authority is created.

### SEC-002 — Enforce sanitizer at Agent 2 → Agent 3 and tool/retrieval boundaries — `TODO`

Depends on: `SEC-001`.

Acceptance:
- every cross-agent handoff has explicit trust metadata;
- retrieval/tool/upload external text enters the model only through a typed untrusted-data envelope;
- security findings are auditable without storing secrets unnecessarily.

### SEC-003 — Cache/trust-domain isolation invariants — `TODO`

Acceptance:
- stable-prefix/cache identity contains trust domain;
- confidential/public or tenant/task domains cannot reuse unsafe state;
- deterministic tests prove isolation.

### DET-001 — TaskContract owns policy/budget/routing authority — `PARTIAL`

Acceptance still required:
- all model/context/tool escalation budgets are represented in one typed contract or compatible deterministic control structure;
- model output cannot increase its own authority/budget.

### DET-002 — Capability broker is the only tool-authority boundary — `TODO`

Acceptance:
- model emits intent/request, not unrestricted execution authority;
- capability checks happen before execution;
- denial is deterministic and audited.

---

## P2 — Context precision and minimum working set

### CTX-001 — Bounded Map → Search → Rank → Expand pipeline — `TODO`

Acceptance:
- retrieval starts from compact metadata/index;
- expansion is bounded by token/item/source budgets;
- irrelevant source bodies are not loaded eagerly;
- selected evidence remains citation-addressable.

### CTX-002 — Semantic viewers per resource type — `TODO`

Examples: code symbol outline, document section map, artifact metadata, log-window selector.

Acceptance:
- model sees compact structural view before full content;
- full content only on explicit need.

### CTX-003 — Context precision/recall telemetry — `TODO`

Measure:
- selected evidence count/size;
- unused evidence ratio when observable;
- citation/evidence coverage;
- retrieval escalation reason.

### CTX-004 — Compression exclusion zones — `TODO`

Acceptance:
- policy, exact constraints, code/commands requiring fidelity, credentials/secrets metadata, citations, and deterministic contracts are never lossy-compressed;
- compression applies only to approved semantic context.

---

## P3 — Prefix reuse and cache economics

### CACHE-001 — Stable-prefix prompt envelope — `DONE`

### CACHE-002 — Prefix reuse-opportunity telemetry — `DONE`

Current behavior deliberately reports reuse **opportunity**, not a backend cache-hit claim.

### CACHE-003 — Workload-trace analyzer — `TODO`

Acceptance:
- aggregate inference telemetry by model/template/trust domain;
- compute stable-prefix reuse opportunity;
- estimate/measure prefill share, generation share, wall time, error rate;
- no raw confidential prompt is required.

### CACHE-004 — Backend cache decision benchmark — `BENCHMARK-GATED`

Candidates:
- stay on Ollama;
- vLLM automatic prefix caching;
- SGLang RadixAttention;
- other future backend only if compatible with security/runtime needs.

Adoption gate:
- representative WorkSpace trace;
- identical/golden task set;
- verified task quality does not regress;
- measurable latency/throughput/resource gain justifies complexity.

Outcome may be `REJECTED` for all migration candidates.

### CACHE-005 — External/persistent KV cache — `BENCHMARK-GATED`

Candidates such as LMCache/HiCache enter only after `CACHE-003/004` show repeated-prefix/pre-fill pressure that native serving cache cannot satisfy economically.

---

## P4 — Structured output and deterministic verification

### STRUCT-001 — Native JSON Schema generation — `DONE`

### STRUCT-002 — Deterministic schema-subset validator — `DONE`

### STRUCT-003 — Agent-specific schemas — `TODO`

Acceptance:
- Research, Presentation planning, Daily Report, router/escalation decisions have explicit versioned schemas where structure is known;
- schema identity appears in telemetry;
- schema failures are classified, not blindly retried.

### VERIFY-001 — Failure taxonomy and retry policy — `TODO`

Failure classes should distinguish at least:
- syntax/schema;
- semantic contract;
- insufficient evidence;
- source conflict;
- tool/network failure;
- resource denial;
- policy denial;
- model capability failure.

Acceptance:
- each class has deterministic retry/escalation/stop behavior;
- retries are bounded and reason-coded.

### VERIFY-002 — Golden verified-task suite — `TODO`

Acceptance:
- representative Research/Presentation/Daily Report tasks;
- correctness/evidence/security metrics;
- used by every model/backend/compression/quantization benchmark.

---

## P5 — Small-first routing and escalation

### ROUTE-001 — Deterministic small-first routing with reason codes — `PARTIAL`

Current adaptive model-selection/resource controls provide a foundation.

Acceptance still required:
- explicit route reason in telemetry;
- deterministic feature/budget thresholds;
- no larger model merely because it is available;
- task success measured by route class.

### ROUTE-002 — Explicit escalation budget — `TODO`

Acceptance:
- max model escalations, retrieval expansions, retries, and tool attempts per task/phase;
- escalation requires named evidence/failure condition.

### ROUTE-003 — Learned semantic router — `DEFERRED`

Only eligible after sufficient labeled workload data proves deterministic routing leaves meaningful value on the table. First deployment must be shadow/no-authority mode.

---

## P6 — Model/runtime/resource efficiency

### PERF-001 — Quantization benchmark on golden suite — `BENCHMARK-GATED`

Evaluate target hardware/model combinations for:
- verified task success;
- VRAM/RAM;
- tokens/s and latency;
- structured-output reliability;
- factual/evidence regression.

Do not select quantization by memory saving alone.

### PERF-002 — Context compression (e.g. LLMLingua class) — `BENCHMARK-GATED`

Eligible only if `CTX-003` shows long-context cost is material after retrieval precision improvements.

### PERF-003 — Speculative decoding — `BENCHMARK-GATED`

Eligible only when generation latency is a measured bottleneck and the backend/model pair supports it safely.

### PERF-004 — Model-family architecture benchmark — `BENCHMARK-GATED`

Compare models benefiting from MLA/MoE/sparse-attention or future efficient architectures only on WorkSpace golden tasks and target hardware. Architecture marketing claims are not acceptance evidence.

### PERF-005 — PicoLM edge-worker experiment — `BENCHMARK-GATED`

Purpose: test whether a minimal PicoLM-style worker is useful for a genuinely constrained edge role.

Do **not** use this item to replace the central WorkSpace runtime by default.

Candidate acceptance:
- a real edge use case has a strict RAM/dependency/offline constraint;
- required model quality fits the role;
- protocol/security boundaries remain compatible;
- measured operational gain outweighs feature loss.

---

## P7 — Observability and continuous optimization

### OBS-001 — Verified-efficiency scorecard — `TODO`

Track together, not independently:
- verified task success;
- evidence/citation correctness;
- security/policy failures;
- prompt/eval token counts;
- latency;
- active VRAM/RAM when available;
- tool/retrieval calls;
- escalation rate;
- prefix reuse opportunity/cache hit when truthfully observable.

### OBS-002 — Regression budget — `TODO`

Any optimization candidate must state acceptable deltas before the benchmark. No performance gain may silently consume correctness/security margin.

### OBS-003 — Periodic doctrine/checklist review — `TODO`

New research is archived first, then fact-checked, then explicitly promoted. Existing source research remains immutable.

---

# Execution queue

The mandatory coding sequence from this baseline is:

```text
SEC-001
  ↓
SEC-002
  ↓
SEC-003 / DET-001 / DET-002
  ↓
CTX-001 → CTX-002 → CTX-003 → CTX-004
  ↓
CACHE-003
  ↓
STRUCT-003 → VERIFY-001 → VERIFY-002
  ↓
ROUTE-001 → ROUTE-002
  ↓
OBS-001 → OBS-002
  ↓
benchmark-gated PERF/CACHE candidates
```

`ROUTE-003` remains deferred until labeled workload evidence exists.

# Definition of done for each coding item

An item moves to `DONE` only when all apply:

1. implementation is in source control;
2. focused tests cover its invariants;
3. existing regression suite passes;
4. security/privacy boundary is unchanged or intentionally strengthened;
5. docs/status are updated;
6. exact candidate SHA is recorded;
7. CI passes on that candidate;
8. after merge, final-main CI is checked rather than inheriting a PASS from a different SHA.
