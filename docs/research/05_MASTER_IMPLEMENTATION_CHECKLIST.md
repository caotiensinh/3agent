# WorkSpace Master Implementation Checklist

Status legend:

- `DONE` — implemented and covered by repository evidence/tests.
- `PARTIAL` — meaningful foundation exists but the doctrine is not fully enforced end-to-end.
- `TODO` — required next work.
- `BENCHMARK-GATED` — do not implement into the production path until trace/evaluation gates justify it.
- `R&D` — isolated experiment only.

## Governing order

This checklist is authoritative for doctrine-driven implementation:

```text
PICO  Resource discipline
  ↓
D0    Deterministic control-plane completeness
  ↓
D1    Handoff trust boundaries
  ↓
D2    Task-specific structured schemas + semantic validators
  ↓
D3    Verified-work/context metrics
  ↓
D4    Persistent prefix/reuse measurement
  ↓
D5    Context map/rank/dedupe/hard pack
  ↓
D6    Small-first deterministic routing and failure-driven escalation
  ↓
D7    Evaluation lab + promotion gates
  ↓
D8    Compression experiment
  ↓
D9    Serving/cache benchmark
  ↓
D10   Model-architecture optimization
  ↓
D11   Edge PicoLM/BitNet R&D
  ↓
D12   Specialist/fine-tuning/internalization
```

A later phase may not become production-critical merely because it is interesting. Security defects may always preempt this order.

---

# PICO — PicoLM-derived resource discipline

## PICO-01 — Explicit per-task budgets — `DONE`

Repository foundation: `src/three_agent/task_contract.py` contains context, generation and execution budgets including input/retrieval/tool-output/output tokens, steps, tool calls, retries, escalations and wall time.

Acceptance:
- every production workflow compiles a contract before privileged execution;
- invalid/negative/out-of-range budgets fail closed;
- no model output can silently increase authority.

## PICO-02 — Lazy context expansion — `PARTIAL`

Foundation exists through Context Engine / Knowledge Plane / retrieval components.

Remaining acceptance:
- first view is map/index/summary rather than full corpus;
- expansion is targeted from unresolved evidence need;
- every expansion consumes explicit budget;
- traces show selected vs candidate context.

## PICO-03 — Lazy model/tool acquisition — `PARTIAL`

Foundation exists in model/resource/worker routing and tool gateways.

Remaining acceptance:
- deterministic/no-LLM path is explicit where feasible;
- models/tools are not loaded/invoked merely because they exist;
- model residency/tool acquisition has measurable reason codes.

## PICO-04 — Deterministic-before-LLM short circuit — `PARTIAL`

Existing policy, Task Contract, schema, DLP, resource and validation code already moves many decisions out of the LLM.

Remaining acceptance:
- introduce an explicit deterministic resolver contract (`NO_LLM` route) for tasks that can be completed without generation;
- CI fixtures prove simple deterministic tasks invoke zero LLM calls.

## PICO-05 — Constrained known syntax — `DONE` for current Ollama JSON path

Native Ollama JSON Schema + local validation are implemented. Probabilistic JSON syntax repair was removed.

Remaining doctrine work is tracked under D2 for task-specific schemas and semantic validation.

## PICO-06 — Metadata-only inference telemetry — `DONE` baseline

Stable-prefix hash, sizes, model/schema/template/trust metadata, token counts and timing are recorded without raw prompt/response storage.

## PICO-07 — Reuse-before-recompute fingerprint — `PARTIAL`

Stable-prefix reuse opportunity exists, but current reuse observation is not yet a durable cross-process/period aggregate and must not be called a backend cache hit.

Tracked to D4.

## PICO-08 — Verified work per resource — `TODO`

Need end-to-end metrics normalized by verified successful tasks rather than request/model-call volume.

Tracked to D3.

---

# D0 — Deterministic control-plane completeness

## D0-01 — Task Contract compiler/schema — `DONE` baseline

Existing `TaskContractCompiler` is deterministic, validates task/sensitivity/risk/tool/validator/network/model/cache/logging policy and contains hard budgets.

Follow-up hardening may add versioned serialization fixtures, but this is not a blocker for D1.

## D0-02 — Data/network policy boundary — `DONE` baseline

Existing secure/public zones, egress broker, privacy/DLP and tests establish local/private vs public-research separation.

## D0-03 — Capability Broker semantics — `PARTIAL`

Tool/network gateways and Task Contract allowed-tool rules exist, but the doctrine target is a uniform typed capability decision for every privileged operation.

Acceptance:
- one authorization decision format;
- task ID + capability + resource + arguments/effect metadata;
- deny-by-default;
- model cannot mint capability tokens;
- revocation/task-end expiry tests.

## D0-04 — Bounded minimal loop — `PARTIAL`

Workflow/resource code contains bounded behavior, but full Task Contract counters must be proven across all live paths.

Acceptance:
- exact hard stop on steps/tool calls/retries/escalations/wall time;
- budget exhaustion has typed failure code;
- daily/report fallback does not silently reset the parent budget.

## D0-05 — Failure taxonomy — `PARTIAL`

Current components expose several specific failures, but no single authoritative failure-code registry currently drives all recovery.

Acceptance:
- central failure enum/schema;
- deterministic failure→strategy mapping;
- policy denial = hard stop;
- missing evidence ≠ stronger model;
- tool timeout ≠ model escalation;
- CI covers each family.

## D0-06 — Validator Bus — `PARTIAL`

Many validators already exist across research, presentation, schema and tests. Consolidate their machine-readable outcomes without replacing domain validators.

Acceptance:
- validator name/version/result/reason evidence;
- required validators derived from Task Contract;
- required validator failure prevents `DONE`.

---

# D1 — Handoff trust boundaries — `NEXT CODE PHASE`

The fact-check elevates model/retrieval/tool handoff to a hard security boundary. `sanitize_untrusted_payload()` already exists but is not yet guaranteed at every consumption boundary.

## D1-01 — Research → Presentation sanitizer — `TODO`

Acceptance:
- every research handoff payload passes normalization/sanitization before Presentation consumes model/retrieved text;
- task ID/source IDs/fact IDs/provenance remain intact;
- suspicious text remains data;
- risk findings are machine-readable;
- no sanitizer result changes Task Contract authority.

Tests:
- README-style `SYSTEM:` / `ignore previous instructions` payload;
- zero-width/control-character injection;
- task-ID mismatch still fails;
- verified claims remain byte/semantic equivalent except allowed normalization.

## D1-02 — Tool/retrieval → Research sanitizer — `TODO`

Acceptance:
- web/document/tool textual payload is classified as untrusted data before entering synthesis;
- risk is propagated with provenance;
- policy/capability instructions embedded in content have no authority.

## D1-03 — Activity/artifact → Daily Report sanitizer — `TODO`

Daily Report should remain evidence-based rather than blindly trusting textual activity details.

Acceptance:
- untrusted activity/artifact strings are sanitized before model prompting;
- task/activity IDs remain authoritative from the store, not from embedded text;
- malicious artifact content cannot change reporting policy or tool authority.

## D1-04 — Handoff security metadata — `TODO`

Add typed metadata:

```text
source_agent / source_type
target_agent
task_id
trust_domain
content_hash
sanitizer_version
risk_level
findings
provenance refs
```

No raw duplicate payload in telemetry.

## D1-05 — End-to-end adversarial handoff CI — `TODO`

A poisoned research/document/tool payload must never become privileged instruction in downstream agents.

---

# D2 — Task-specific structured schemas and semantic validators

## D2-01 — Research output JSON Schema — `TODO/PARTIAL`

Existing research structure/quality contracts exist. Convert the actual model output boundary to an explicit versioned schema supplied to `generate_json()`.

Required fields should cover source catalog, claims/facts, truth class/status, source refs, conflicts, uncertainty and handoff readiness as applicable to current contract.

## D2-02 — Presentation output JSON Schema — `TODO/PARTIAL`

Version the generated slide/deck structure, claim references and evidence lineage.

## D2-03 — Daily Report output JSON Schema — `TODO/PARTIAL`

Version work items, outcomes, blockers, next actions and evidence/task references while preserving current deterministic fallback.

## D2-04 — Semantic validators after schema — `TODO`

Schema-valid does not mean true/correct.

Acceptance:
- unknown source/fact/task references fail;
- presentation claims remain bounded by verified handoff evidence;
- report cannot invent task IDs/activity not present in authoritative store;
- authorization fields, if any, are ignored as authority.

## D2-05 — Schema IDs in telemetry/artifacts — `TODO/PARTIAL`

Every structured generation records schema ID/version and validator result without raw content logging.

---

# D3 — Verified-work and context metrics

## D3-01 — Verified Task Success Rate — `TODO`

```text
verified tasks / attempted tasks
```

A task is verified only when all Task Contract-required validators pass.

## D3-02 — First-Pass Verified Success — `TODO`

Track success before retry/escalation.

## D3-03 — Tokens per verified task — `TODO`

Track input/output/total tokens divided by verified success, not merely per request.

## D3-04 — Tool calls/retries/escalations per verified task — `TODO`

## D3-05 — Evidence Coverage — `TODO/PARTIAL`

Research already tracks evidence/claims; aggregate supported material claims over claims requiring support.

## D3-06 — Context Precision proxy — `TODO`

Selected tokens/spans that are actually used/cited vs total supplied context.

## D3-07 — Context Recall — `TODO`

Only compute true recall when the evaluation case declares required evidence spans. Do not fabricate recall from unlabeled production traffic.

## D3-08 — Useful Context Ratio / duplicate ratio — `TODO`

## D3-09 — GPU seconds per verified task — `TODO`

Use local runtime/GPU instrumentation where available; do not infer GPU active time from wall time.

## D3-10 — Metadata privacy tests — `TODO`

Synthetic secrets/PII must not appear in metrics labels/logs.

---

# D4 — Persistent prefix/reuse measurement

## D4-01 — Durable reuse-observation index — `TODO`

Current in-process repeat detection becomes a local metadata aggregate keyed by model + trust domain + template/schema/policy versions + prefix hash.

## D4-02 — 7-day/representative-period report — `TODO`

Report:
- repeated-prefix opportunity rate;
- prompt-size buckets;
- prefill/prompt-eval duration share;
- trust-domain segmentation;
- schema/template versions.

## D4-03 — Decision gate — `TODO`

Planning rule from reviewed v3:
- low reuse (roughly <30% starting threshold) → redesign prompt layout first;
- high reuse + TTFT/prefill bottleneck → permit D9 serving benchmark.

Never present reuse opportunity as a real APC cache hit while using a backend that does not expose that metric.

---

# D5 — Context map/rank/deduplicate/hard pack

## D5-01 — Bounded structural first view — `PARTIAL`

Context/Knowledge Plane exists; prove map/index-before-body behavior for repo/docs/logs where supported.

## D5-02 — Rank + deduplicate — `PARTIAL`

Acceptance:
- relevance/authority/freshness/diversity signals are explicit;
- duplicate/near-duplicate context is removed before prompt packing.

## D5-03 — Hard token packer — `PARTIAL`

No context path may silently exceed Task Contract budget.

## D5-04 — Critical-span protection — `TODO/PARTIAL`

Policy, user constraints, exact citations/source IDs and critical error/code fragments must survive transformation exactly where exactness is required.

## D5-05 — Progressive expansion — `TODO/PARTIAL`

Missing-context failures request only missing evidence rather than reinjecting the whole source set.

---

# D6 — Small-first deterministic routing and escalation

## D6-01 — Deterministic route reason codes — `PARTIAL`

Existing adaptive model/worker/resource logic is a foundation. Consolidate task policy + capability + resource + quality reason codes.

## D6-02 — `NO_LLM` route — `TODO`

## D6-03 — Failure-driven escalation controller — `TODO/PARTIAL`

Escalation must consume typed failure evidence.

## D6-04 — Security monotonicity — `DONE` principle / `TODO` exhaustive proof

Stronger model must never gain more source/tool/network/write authority than the Task Contract permits.

## D6-05 — Learned router — `BENCHMARK-GATED`

Shadow only after D3/D7 traces exist.

---

# D7 — Evaluation lab and promotion gates

## D7-01 — Versioned Golden corpus — `TODO`
## D7-02 — Replay corpus — `TODO`
## D7-03 — Regression corpus — `TODO/PARTIAL` (existing unit tests are seed evidence)
## D7-04 — Adversarial/security corpus — `PARTIAL` (security/handoff fixtures exist and will expand)
## D7-05 — Edge/large-context corpus — `TODO`
## D7-06 — Efficiency/cache/concurrency corpus — `TODO`
## D7-07 — Metric versioning — `TODO`
## D7-08 — Promotion pipeline — `TODO`

Acceptance:
- optimizer cannot see final holdout labels;
- security is a hard constraint;
- production changes require regression/adversarial pass;
- rollback artifact/version exists.

DSPy/GEPA may be evaluated offline later; it is not required to build the lab.

---

# D8 — Context compression experiment — `BENCHMARK-GATED`

Prerequisites: D3 + D5 + D7.

## D8-01 — Context-size distribution measurement
## D8-02 — Protected-span framework complete
## D8-03 — LLMLingua-2 or equivalent isolated adapter
## D8-04 — break-even benchmark
## D8-05 — zero critical-span-loss gate
## D8-06 — feature flag default OFF

Do not compress short prompts or security/authorization/citation-critical text simply to improve a token metric.

---

# D9 — Serving/cache benchmark — `BENCHMARK-GATED`

Prerequisite: D4 proves enough opportunity to justify it.

## D9-01 — Trace replay harness: current Ollama vs vLLM vs SGLang
## D9-02 — same-model/same-quantization quality parity where possible
## D9-03 — TTFT/TPOT/throughput/VRAM/GPU-time measurement
## D9-04 — structured-output reliability under representative concurrency
## D9-05 — trust-domain prefix-cache isolation tests
## D9-06 — select one primary production server by ADR
## D9-07 — LMCache/HiCache only if native cache is insufficient and net cache value is positive

No framework accumulation. One primary stack wins.

---

# D10 — Model-architecture optimization — `BENCHMARK-GATED`

## D10-01 — Qwen3 MoE candidate benchmark
## D10-02 — DeepSeek MLA/MoE candidate benchmark where hardware/runtime permits
## D10-03 — long-context/sparse-attention evaluation
## D10-04 — speculative decoding experiment
## D10-05 — quantization matrix per task class

Promotion requires equal-or-better verified quality, security parity, and material measured resource/latency benefit.

---

# D11 — Edge PicoLM / BitNet lane — `R&D`

The **philosophy is Phase PICO**, but the runtime itself is late R&D.

## D11-01 — WorkSpace `InferenceBackend` adapter boundary for edge experiment
## D11-02 — PicoLM isolated prototype
## D11-03 — target CPU memory/latency/power measurement
## D11-04 — golden-output correctness matrix
## D11-05 — BitNet isolated experiment only after supported model/hardware validation
## D11-06 — no production control-plane dependency on edge runtime

---

# D12 — Specialist model / prompt internalization — `BENCHMARK-GATED`

Prerequisites: stable high-volume repetitive task family + D7 evaluation lab.

## D12-01 — repetition analysis
## D12-02 — prompt/template optimization baseline
## D12-03 — LoRA/distillation/PromptIntern-style pilot
## D12-04 — holdout/OOD regression
## D12-05 — resource delta per verified task
## D12-06 — policy-in-weights audit

Authorization, DLP, network rules, tenant boundaries, retention policy and incident kill switches must remain external to weights.

---

# Definition of Done for each checklist item

An item may move to `DONE` only when all applicable evidence exists:

1. implementation merged on exact `main` SHA;
2. focused unit tests PASS;
3. existing regression suite PASS;
4. security invariants PASS;
5. behavior is observable with metadata-only telemetry where relevant;
6. docs/config updated;
7. benchmark-gated items include before/after measurement on representative traces;
8. no new dependency/framework is accepted without an ADR explaining why existing code/runtime cannot provide the same outcome more simply.

# Immediate execution queue

The next code sequence is fixed as:

```text
D1-01 Research → Presentation sanitizer
D1-02 Tool/Retrieval → Research sanitizer
D1-03 Activity/Artifact → Daily Report sanitizer
D1-04 typed handoff security metadata
D1-05 end-to-end adversarial handoff CI
        ↓
D2 task-specific schemas + semantic validators
        ↓
D3 verified-work/context metrics
```

Do not begin D8/D9/D10/D11/D12 production integration before their prerequisite evidence gates are satisfied.
