# WorkSpace Master Implementation Checklist

## Status legend

- `DONE` — implemented and covered by repository evidence/tests.
- `PARTIAL` — meaningful foundation exists but the doctrine is not fully enforced end-to-end.
- `TODO` — required next work.
- `EVIDENCE-PENDING` — implementation/profile exists, but representative external/hardware evidence is not yet materialized.
- `BENCHMARK-GATED` — production integration is prohibited until representative benchmark evidence justifies it.
- `R&D` — isolated experiment only.

## Governing order

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

## Current closure baseline

Authoritative implementation lineage at this checklist sync starts from main:

`704955f8efba430b1a57b661bc5d03b7e92d2d76`

The deterministic control plane is now closed at baseline level. The following recent work is merged and regression-protected:

- PICO-03 / D0-03 typed task capability authority + persistent monotonic revocation — `DONE` baseline
- D0-04 persistent hard execution limits for steps, tool calls, retries, escalations and wall time — `DONE`
- D0-05 authoritative deterministic failure taxonomy driving current automatic recovery — `DONE`
- D7-03 regression replay pins the complete immutable execution-budget envelope — `DONE` baseline
- D1 Handoff Trust Boundaries — `DONE`
- D2 Structured Output + Semantic Validation — `DONE`
- D3 Verified Work Metrics foundation — `DONE`
- Evidence Packing Rank v1 — `DONE`
- Authoritative Packing Receipt v1 — `DONE`
- Runtime Validator Bridge — `DONE`
- Benchmark Isolation v1 — `DONE`
- Fixed-task Benchmark Execution + Required-validator Acceptance v1 — `DONE`
- D4 Durable Prefix Reuse Measurement — `DONE`
- D5-01 Structural-first Context Retrieval Trace — `DONE` baseline
- D5-03 Hard Evidence Budget — `DONE` baseline
- D5-04 Atomic Provenance / Critical-span Protection — `DONE` baseline
- D6-01 Deterministic Route Reason Codes — `DONE`
- D6-02 Verified `NO_LLM` Retrieval — `DONE`
- D6-03 Persistent Hard Retry/Escalation Budget — `DONE`
- D6-04 Security Monotonicity — `DONE`
- D7-01 Versioned Golden Corpus — `DONE`
- D7-02 Deterministic Replay — `DONE`
- D7-03 Regression Corpus — `DONE` baseline
- D7-04 Adversarial/Security Corpus — `DONE` baseline
- D7-07 Metric Version Registry — `DONE`
- D7-08 Fail-closed Promotion Pipeline — `DONE` infrastructure

D7-05 edge/large-context and D7-06 efficiency/cache/concurrency profiles/adapters are implemented, but representative external results are not yet materialized. They remain `EVIDENCE-PENDING`; implementation alone is not evaluation acceptance.

The fixed benchmark harness is implemented, but the real dual-RTX5090 48k/40k/32k comparison remains pending execution. No context-budget candidate is promoted by implementation alone.

---

# PICO — PicoLM-derived resource discipline

## PICO-01 — Explicit per-task budgets — `DONE`

`TaskContract` contains context, generation and execution budgets including input/retrieval/tool-output/output budgets, steps, tool calls, retries, escalations and wall time. Invalid/out-of-range policy fails closed and model output cannot increase authority.

## PICO-02 — Lazy context expansion — `PARTIAL / BENCHMARK-GATED`

Structural map-before-body retrieval is implemented and observable. Targeted/progressive body expansion remains disabled until representative evidence proves it does not reduce verified recall, evidence coverage or critical-span preservation.

## PICO-03 — Lazy model/tool acquisition — `DONE` baseline

Deterministic `NO_LLM` routing, reason-coded model selection and immutable typed `TaskCapabilityAuthority` are enforced at live tool/network boundaries. Capability checks include task identity, logical capability, resource and effect. Persistent operator revocation is task-scoped, insert-only, survives process restart and takes effect inside an already-active scope before tool budget, telemetry or side effect. There is intentionally no restore/unrevoke path; widening authority requires a new task/contract.

## PICO-04 — Deterministic-before-LLM short circuit — `DONE` baseline

Policy, TaskContract, DLP, schema, resource and validator decisions are deterministic, and verified local retrieval can complete without model construction or inference telemetry.

## PICO-05 — Constrained known syntax — `DONE`

Current structured generation uses native JSON Schema plus deterministic post-validation. Probabilistic JSON repair is prohibited.

## PICO-06 — Metadata-only inference telemetry — `DONE`

Telemetry records model/schema/template/trust metadata, token counts, timing and stable-prefix fingerprints without raw prompt/response content.

## PICO-07 — Reuse-before-recompute fingerprint — `DONE` baseline

Stable-prefix fingerprints are recorded metadata-only and D4 reconstructs durable repeated-prefix opportunity across process restarts and representative periods. WorkSpace does not call reuse opportunity a backend cache hit.

## PICO-08 — Verified work per resource — `DONE` baseline

D3 metrics normalize token/tool/retry/escalation/resource accounting by verified tasks rather than request count. Failed/unverified task cost remains visible.

---

# D0 — Deterministic control-plane completeness — `DONE` baseline

## D0-01 — Task Contract compiler/schema — `DONE`

Deterministic compiler validates sensitivity, risk, allowed tools, required validators, network/model/cache/logging policy and hard budgets.

## D0-02 — Data/network policy boundary — `DONE`

Secure/public trust zones, egress broker, privacy/DLP and tests establish confidential-local versus public-research separation.

## D0-03 — Capability Broker semantics — `DONE` baseline

One immutable typed authority projects TaskContract capability into task ID + capability + resource + effect decisions. Production gateways deny undeclared/unauthorized capability before side effect. Persistent revocation can only narrow already-bound contract authority and is checked live on every scoped capability call. Task scopes cannot reuse authority belonging to another task.

## D0-04 — Bounded minimal loop — `DONE`

Task-wide `max_steps`, `max_tool_calls`, `max_retries`, `max_escalations` and `max_wall_time_ms` are persistently bound from the immutable TaskContract. Reservations occur before the corresponding action/fallback side effect. Usage and deadline survive runtime reconstruction/process restart; exhausted dimensions fail closed. D7 regression replay pins the complete execution envelope so future optimization cannot silently widen it.

## D0-05 — Failure taxonomy — `DONE`

A versioned deterministic taxonomy distinguishes policy/security/capability/contract denial, missing evidence, validation failure, human gate, budget exhaustion, tool timeout/failure, resource pressure, model failure, invalid model output and unknown failure. Recovery operations are centrally authorized before retry/fallback/escalation budget, telemetry and secondary invocation. Unknown failures hard-stop; missing evidence means collect evidence rather than retry a model; security/policy/capability/budget denials are terminal. Failure metadata never preserves arbitrary raw exception text as a reason code.

## D0-06 — Validator Bus / Runtime Validator Bridge — `DONE`

Production execution binds an immutable TaskContract before work and records deterministic validator outcomes into `ValidatorLedger`.

Required Research → Presentation validators are derived from TaskContract. Core rules:

- no validator PASS is inferred from task status;
- model output cannot self-authorize PASS;
- evidence/schema PASS requires deterministic integrity/lineage checks;
- `ValidatorLedger.evaluate(task_id).verified` must be true before `DONE`;
- missing required validator means unverified;
- failed validator history remains visible;
- retries may recover final verification but never rewrite First-Pass Verified Success;
- ledger evidence remains metadata-only.

Daily Report is date-wide reporting and cannot mint or revoke task-specific verification.

---

# D1 — Handoff trust boundaries — `DONE`

## D1-01 — Research → Presentation sanitizer — `DONE`

Untrusted Research content is normalized/sanitized before Presentation consumption while authoritative task/source/fact/provenance identity remains outside content authority.

## D1-02 — Tool/Retrieval → Research sanitizer — `DONE`

External document/web/tool text is treated as untrusted data before Research synthesis. Embedded instructions cannot grant policy/capability authority.

## D1-03 — Activity/Artifact → Daily Report sanitizer — `DONE`

Reporting consumes sanitized activity/artifact text and authoritative store identifiers rather than trusting embedded content.

## D1-04 — Typed handoff security metadata — `DONE`

Handoffs preserve source agent/type, target agent, task ID, trust domain, content hash, sanitizer version, risk/findings and provenance references without duplicating raw payload into telemetry.

## D1-05 — End-to-end adversarial handoff CI — `DONE`

Tamper/injection fixtures verify poisoned content cannot become privileged downstream instruction and task/lineage mismatches fail closed.

---

# D2 — Task-specific structured schemas and semantic validators — `DONE`

## D2-01 — Research structured schema — `DONE`

Research generation uses versioned structured output and deterministic validation.

## D2-02 — Presentation structured schema — `DONE`

Presentation planning uses versioned structured output with evidence-bounded claim references and deterministic validation.

## D2-03 — Daily Report structured schema — `DONE`

Daily reporting uses structured output/validation while preserving deterministic fallback behavior.

## D2-04 — Semantic validators after schema — `DONE`

Schema validity alone is insufficient. Unknown references, evidence/lineage mismatches and unauthorized fields are rejected deterministically. Authorization fields in model content have no authority.

## D2-05 — Schema IDs + validation receipts/telemetry — `DONE`

Structured generation records schema/version and deterministic validation metadata without raw confidential payloads.

---

# D3 — Verified-work and context metrics — `DONE` foundation

## D3-01 — Verified Task Success Rate — `DONE`

A task is verified only when its immutable TaskContract is bound and every required validator's latest outcome is passing.

## D3-02 — First-Pass Verified Success — `DONE`

Later retries can recover final verified success but cannot rewrite first-pass history.

## D3-03 — Tokens per Verified Task — `DONE`

Failed/unverified task spend stays in the numerator.

## D3-04 — Tool calls/retries/escalations per Verified Task — `DONE`

Typed task-scoped resource events provide the authoritative accounting path.

## D3-05 — Evidence Coverage — `DONE`

Evidence-supported material claims are measured against material claims requiring support.

## D3-06 — Context Precision Proxy — `DONE`

Authoritative packing receipts provide source-text character accounting. This remains a source-level utilization proxy, not true token/span precision.

## D3-07 — Context Recall Proxy — `DONE`

Authoritative packing receipts measure retained vetted source text under the synthesis budget. This remains a retention proxy, not semantic recall.

## D3-08 — Unified `workspace metrics` snapshot — `DONE`

Verified work, token/resource efficiency, evidence coverage and context proxies are reported from one exact task scope.

## D3-09 — GPU-seconds per Verified Task — `TODO`

Only add when authoritative local GPU-active-time instrumentation exists. Never infer GPU seconds from task wall time or model request duration.

## D3-10 — Metadata privacy boundary — `DONE` baseline

Validator/metrics/packing receipts are metadata-only and do not require raw prompts, model responses, retrieved bodies, credentials or business content.

## D3-11 — Optimization Acceptance Gate — `DONE`

Optimization candidates cannot be promoted when Verified Task Success, First-Pass Verified Success, Evidence Coverage or required-validator success regresses.

---

# Benchmark foundation after D3

## Evidence Packing Rank v1 — `DONE`

Modes: `legacy_v1` and `quality_ranked_v1`. Ranking is deterministic and packing mode participates in the effective benchmark fingerprint.

## Authoritative Packing Receipt v1 — `DONE`

Metadata-only source accounting is authoritative when present; old artifacts retain fail-safe legacy fallback. Partial/tampered receipts fail closed. The synthesis context budget participates in benchmark identity.

## Benchmark Isolation v1 — `DONE`

Baseline/candidate variants use isolated task DB, artifacts, inference telemetry, resource telemetry, Internet/execution audit sinks and benchmark sandbox/manifest. Non-empty sandboxes fail closed and baseline/candidate cannot share task lineage or counters.

## Fixed-task Benchmark Execution + Required-validator Acceptance v1 — `DONE` implementation / evidence pending

The repository owns a versioned local-evidence task set and `workspace-benchmark` execution harness for:

- `legacy_v1 / 48000` baseline;
- `quality_ranked_v1 / 48000`;
- `quality_ranked_v1 / 40000`;
- `quality_ranked_v1 / 32000`.

Each variant uses isolated runtime state, exact Git lineage, deterministic fixture corpus identity and the real Runtime Validator Bridge. Candidate efficiency is not evaluated until exact required-validator parity/PASS non-regression and verified-quality gates pass. The RTX5090 workflow requires the preinstalled local model and two RTX5090 GPUs and does not silently download a missing model.

Implementation readiness does not equal benchmark acceptance. Representative hardware evidence remains pending.

---

# D4 — Persistent prefix/reuse measurement — `DONE` baseline

## D4-01 — Durable reuse-observation aggregate — `DONE`

Metadata-only inference JSONL is reused as the durable cross-process observation log. Repeated-prefix opportunity is reconstructed from model + trust-domain + template + schema + stable-prefix hash.

## D4-02 — Representative-period report — `DONE`

Default reporting window is seven days and includes reuse opportunity, distinct/repeated prefix counts, prefix-size summary, prompt-eval duration share, model segmentation, opaque trust-domain segmentation and malformed/out-of-window accounting.

## D4-03 — Decision gate — `DONE`

Insufficient events collect more metadata; low reuse points to prompt-layout redesign; high reuse plus prefill dominance makes a D9 serving/cache benchmark eligible. The gate never authorizes production migration or claims an actual backend cache hit.

---

# D5 — Context map/rank/deduplicate/hard pack

## D5-01 — Bounded structural first view — `DONE` baseline

The runtime performs one structural map pass before body retrieval and emits bounded metadata-only retrieval traces while preserving deterministic search semantics.

## D5-02 — Rank + deduplicate — `PARTIAL / BENCHMARK-GATED`

Deterministic lexical ranking and exact content deduplication are observable. Near-duplicate/diversity changes remain benchmark-gated because they can reduce recall.

## D5-03 — Hard context packer — `DONE` baseline

The complete rendered output, including separators, is charged to the hard budget and final output cannot exceed it.

## D5-04 — Critical-span protection — `DONE` baseline

Provenance/data-boundary headers are indivisible: preserve whole or skip the source. Body truncation can occur only after the complete protected header fits.

## D5-05 — Progressive expansion — `BENCHMARK-GATED`

Progressive body expansion remains disabled by default. It may not become production behavior until representative D7/benchmark evidence proves no verified-quality, evidence-coverage, recall-proxy or critical-span regression.

---

# D6 — Small-first deterministic routing and escalation

## D6-01 — Deterministic route reason codes — `DONE`

TaskContract model policy is projected into auditable reason-coded `MODEL` or `NO_LLM` decisions without reading raw task content.

## D6-02 — `NO_LLM` route — `DONE`

Verified deterministic local retrieval executes through the real TaskContract/validator path with no model client construction and zero inference telemetry.

## D6-03 — Failure-driven escalation controller — `DONE`

Retry/escalation limits are persistent task-wide and atomically reserved before fallback invocation. D0-05 now additionally requires taxonomy authorization before automatic retry/fallback/escalation.

## D6-04 — Security monotonicity — `DONE`

Model-tier changes cannot expand source/tool/network/write/cache/logging authority. Unauthorized stronger-model transitions fail before budget consumption, telemetry or model invocation.

## D6-05 — Learned router — `BENCHMARK-GATED`

A learned router may be evaluated only after deterministic baseline and representative D7 evidence exist. It may recommend a route but cannot grant capability or weaken TaskContract authority.

---

# D7 — Evaluation lab and promotion gates

## D7-01 — Versioned Golden corpus — `DONE`

Repository-owned deterministic control-plane expectations are versioned and content-addressed.

## D7-02 — Replay corpus — `DONE`

`workspace-eval` replays golden expectations through the production TaskContract compiler and deterministic route planner under exact Git lineage.

## D7-03 — Regression corpus — `DONE` baseline

Versioned regression cases protect production-critical routing, write scope, cache/logging, model locality and the complete TaskContract execution budget: steps, tool calls, retries, escalations and wall time. A future optimization that widens these limits causes a replay mismatch.

## D7-04 — Adversarial/security corpus — `DONE` baseline

Versioned reject cases require fail-closed handling for forbidden public-web, NO_LLM scope expansion, web-gateway misuse and unknown tool authority. Runtime unit/regression tests additionally protect capability revocation and failure-taxonomy invariants.

## D7-05 — Edge/large-context corpus — `EVIDENCE-PENDING`

Versioned repository profile and strict external-result adapter are implemented. The profile covers protected spans, atomic provenance, many-source pressure, adversarial-near-critical-span and exact source-ID preservation. External holdout labels and real representative results are intentionally not committed.

## D7-06 — Efficiency/cache/concurrency corpus — `EVIDENCE-PENDING`

Versioned repository profile and strict result adapter are implemented for fixed-task quality, structured-output concurrency, measured resource benefit, cache trust-domain isolation, execution-budget concurrency and cache-measurement honesty. Real RTX/concurrency results remain pending.

## D7-07 — Metric versioning — `DONE`

D3-01..D3-07 semantics are bound to `workspace-d3-core-metrics-v1` with a canonical registry fingerprint. New benchmark lineage records the exact metric registry; legacy payloads cannot retroactively claim it.

## D7-08 — Promotion pipeline — `DONE` infrastructure

`workspace-promotion` requires all mandatory evidence classes, exact baseline/candidate/rollback lineage, current metric registry, security PASS, holdout commitments/attestation where required and no waiver path. Missing D7-05/D7-06/replay evidence intentionally keeps real production promotion blocked.

Security is a hard constraint. Optimizers must not see holdout labels and production changes require regression/adversarial evidence plus rollback lineage.

---

# D8 — Context compression experiment — `BENCHMARK-GATED`

Prerequisites: D3 + D5 + representative D7 evidence.

- D8-01 Context-size distribution measurement
- D8-02 Protected-span framework
- D8-03 Isolated compression adapter
- D8-04 Break-even benchmark
- D8-05 Zero critical-span-loss gate
- D8-06 Feature flag default OFF

Do not compress short or authorization/security/citation-critical context merely to improve token metrics.

---

# D9 — Serving/cache benchmark — `BENCHMARK-GATED`

Prerequisite: D4 proves sufficient reuse/prefill opportunity on representative traces.

- D9-01 current Ollama vs candidate serving-engine replay benchmark
- D9-02 same-model/same-quantization quality parity where possible
- D9-03 TTFT/TPOT/throughput/VRAM/authoritative GPU-active-time where available
- D9-04 structured-output reliability under representative concurrency
- D9-05 trust-domain prefix-cache isolation
- D9-06 one primary production server selected by ADR
- D9-07 external cache layer only when native cache is insufficient and net value is positive

No framework accumulation. One primary stack wins. D4 eligibility permits only a benchmark, not production migration.

---

# D10 — Model-architecture optimization — `BENCHMARK-GATED`

Candidate model architecture, speculative decoding and quantization changes require equal-or-better verified quality, security parity and material measured resource/latency benefit.

---

# D11 — Edge PicoLM / BitNet lane — `R&D`

The PicoLM philosophy is production guidance; the edge runtime itself remains isolated R&D until target CPU memory/latency/power and correctness gates pass. Production control-plane behavior must not depend on it.

---

# D12 — Specialist model / prompt internalization — `BENCHMARK-GATED`

Prerequisites: stable high-volume repetitive task family + D7 evaluation lab. Authorization, DLP, network rules, tenant boundaries, retention policy and incident kill switches remain external to model weights.

---

# Definition of Done

An item may move to `DONE` only when all applicable evidence exists:

1. implementation merged on exact `main` SHA;
2. focused unit/regression tests PASS;
3. security invariants PASS;
4. behavior is observable with metadata-only telemetry where relevant;
5. docs/config are updated;
6. benchmark-gated items include representative before/after measurements;
7. no new dependency/framework is accepted without evidence that existing code/runtime cannot provide the same outcome more simply.

`EVIDENCE-PENDING` means implementation/profile work is complete but representative external, holdout or hardware evidence is still missing.

# Immediate execution queue

```text
Deterministic control plane D0 — DONE baseline
        ↓
Run real dual-RTX5090 fixed benchmark on one exact source_ref:
  legacy_v1 / 48000
  quality_ranked_v1 / 48000
  quality_ranked_v1 / 40000
  quality_ranked_v1 / 32000
        ↓
Materialize representative D7-05 edge/large-context external results
and D7-06 efficiency/cache/concurrency results
        ↓
Quality/security acceptance first:
  Verified Task Success must not decrease
  First-Pass Verified Success must not decrease
  Evidence Coverage must not decrease
  exact required-validator success must not decrease
  critical-span loss must remain zero where applicable
  TaskContract execution authority must not widen
        ↓
Only then compare tokens/context proxies/latency/retries/escalations/tool calls/resource usage
        ↓
Run D4 representative reuse report on real workload telemetry
        ↓
Evaluate D5-02 near-duplicate/diversity and D5-05 progressive expansion only through D7 gates
        ↓
Consider D3-09 only after authoritative GPU-active-time instrumentation exists
```

Do not promote 40k/32k context budgets without representative benchmark evidence. Do not begin D9 production migration unless D4 representative evidence permits its benchmark. Do not begin D8/D10/D11/D12 production integration before their prerequisite gates are satisfied.
