# WorkSpace Master Implementation Checklist

## Status legend

- `DONE` — implemented and covered by repository evidence/tests.
- `PARTIAL` — meaningful foundation exists but the doctrine is not fully enforced end-to-end.
- `TODO` — required next work.
- `EVIDENCE-PENDING` — implementation/profile is complete, but representative external/hardware evidence has not yet been collected.
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

`1b4802125a88ff5f58177ee3a07e52b0d653da7d`

The following work packages are complete in the current implementation lineage:

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

D7-05 edge/large-context and D7-06 efficiency/cache/concurrency profiles and adapters are implemented, but **representative external results are not yet materialized**, so they remain `EVIDENCE-PENDING` rather than being treated as completed evaluation evidence.

The fixed benchmark harness is implemented, but the **real dual-RTX5090 48k/40k/32k benchmark result is still pending execution**. No context-budget candidate is promoted by implementation alone.

---

# PICO — PicoLM-derived resource discipline

## PICO-01 — Explicit per-task budgets — `DONE`

`TaskContract` contains context, generation and execution budgets including input/retrieval/tool-output/output budgets, steps, tool calls, retries, escalations and wall time. Invalid/out-of-range policy fails closed and model output cannot increase authority.

## PICO-02 — Lazy context expansion — `PARTIAL`

Structural map-before-body retrieval is implemented and observable. Remaining proof is benchmark-justified targeted/progressive body expansion from unresolved evidence need without reducing verified recall.

## PICO-03 — Lazy model/tool acquisition — `PARTIAL`

Deterministic `NO_LLM` routing and reason-coded model selection exist. Remaining target is a unified capability/tool acquisition authority with explicit typed decisions and revocation/task-end expiry.

## PICO-04 — Deterministic-before-LLM short circuit — `DONE` baseline

Policy, TaskContract, DLP, schema, resource and validator decisions are deterministic, and the verified local retrieval path proves a real `NO_LLM` task can complete without model invocation or inference telemetry.

## PICO-05 — Constrained known syntax — `DONE`

Current Ollama structured generation uses native JSON Schema plus deterministic post-validation. Probabilistic JSON repair is prohibited.

## PICO-06 — Metadata-only inference telemetry — `DONE`

Telemetry records model/schema/template/trust metadata, token counts, timing and stable-prefix fingerprints without raw prompt/response content.

## PICO-07 — Reuse-before-recompute fingerprint — `DONE` baseline

Stable-prefix fingerprints are recorded metadata-only and D4 reconstructs durable repeated-prefix opportunity across process restarts and representative periods. Reuse identity includes model + trust domain + template + schema + prefix hash. WorkSpace still does not call reuse opportunity a backend cache hit.

## PICO-08 — Verified work per resource — `DONE` baseline

D3 metrics normalize token/tool/retry/escalation/resource accounting by verified tasks rather than request count. Failed/unverified task cost remains visible.

---

# D0 — Deterministic control-plane completeness

## D0-01 — Task Contract compiler/schema — `DONE`

Deterministic compiler validates sensitivity, risk, allowed tools, required validators, network/model/cache/logging policy and hard budgets.

## D0-02 — Data/network policy boundary — `DONE`

Secure/public trust zones, egress broker, privacy/DLP and tests establish confidential-local versus public-research separation.

## D0-03 — Capability Broker semantics — `PARTIAL`

Tool/network gateways are hardened foundations, but one authoritative typed authorization decision format for task ID + capability + resource + effect metadata is still required. Target remains deny-by-default with bounded grants, revocation and task-end expiry.

## D0-04 — Bounded minimal loop — `PARTIAL`

Task-wide retries/escalations are now persistently and atomically enforced before fallback invocation. Remaining proof is uniform hard-stop enforcement for steps/tool-call/wall-time budgets across every live execution and reporting path.

## D0-05 — Failure taxonomy — `PARTIAL`

Specific failures exist but no single authoritative registry yet drives all recovery. Policy denial must remain a hard stop; missing evidence, budget exhaustion, tool timeout, resource admission and model failure must remain distinct typed failure families.

## D0-06 — Validator Bus / Runtime Validator Bridge — `DONE`

Production `WorkflowRunner` binds an immutable TaskContract before Research and records deterministic validator outcomes into `ValidatorLedger`.

Required Research → Presentation validators are derived from TaskContract and are:

- `policy`
- `evidence`
- `schema`

Rules:
- no validator PASS is inferred from `TaskStatus.DONE`, `RESEARCH_COMPLETED` or `PRESENTATION_COMPLETED`;
- model output cannot self-authorize a PASS;
- Research evidence PASS requires typed handoff integrity, lineage and deterministic readiness/evidence gates;
- Presentation schema PASS requires deterministic QA plus exact Research-handoff SHA-256 lineage;
- `ValidatorLedger.evaluate(task_id).verified` must be true before `TaskStatus.DONE` is written;
- missing required validator means unverified;
- failed validator history remains visible;
- retry may reach final verified success but cannot rewrite First-Pass Verified Success;
- ledger evidence is metadata-only compact identifiers/hashes/paths.

Daily Report is date-wide reporting and is not allowed to mint or revoke task-specific verification.

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

Only add when authoritative local GPU-active-time instrumentation exists. Never infer GPU seconds from wall time.

## D3-10 — Metadata privacy boundary — `DONE` baseline

Validator/metrics/packing receipts are metadata-only and do not require raw prompts, model responses, retrieved bodies, credentials or business content.

## D3-11 — Optimization Acceptance Gate — `DONE`

Optimization candidates cannot be promoted when Verified Task Success, First-Pass Verified Success, Evidence Coverage or required-validator success regresses.

---

# Benchmark foundation after D3

## Evidence Packing Rank v1 — `DONE`

Modes:
- `legacy_v1`
- `quality_ranked_v1`

Ranking is deterministic and the default remains `legacy_v1`. Packing mode participates in the effective benchmark fingerprint.

## Authoritative Packing Receipt v1 — `DONE`

Metadata-only source accounting is authoritative when present; old artifacts retain fail-safe legacy fallback. Partial/tampered receipts fail closed. `WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS` is bounded and participates in the benchmark fingerprint.

## Benchmark Isolation v1 — `DONE`

Baseline/candidate variants use isolated:
- task DB;
- artifacts;
- inference telemetry;
- resource telemetry;
- Internet/execution audit sinks;
- benchmark sandbox/manifest.

Non-empty sandboxes fail closed and process-global optimization knobs are serialized/restored. Baseline and candidate must never share counters or task lineage.

## Fixed-task Benchmark Execution + Required-validator Acceptance v1 — `DONE`

The repository owns a versioned local-evidence task set and `workspace-benchmark` execution harness for:

- `legacy_v1 / 48000` baseline;
- `quality_ranked_v1 / 48000`;
- `quality_ranked_v1 / 40000`;
- `quality_ranked_v1 / 32000`.

Each variant uses isolated runtime state, exact Git lineage, deterministic fixture corpus identity and the real Runtime Validator Bridge. Candidate efficiency is not evaluated until exact required-validator parity/PASS non-regression and verified-quality gates pass. The self-hosted RTX5090 workflow publishes metadata-only benchmark evidence and does not download a missing model or dependencies during benchmark setup.

Implementation readiness does not equal benchmark acceptance. The real hardware comparison remains pending until the manual fixed-task benchmark is executed.

---

# D4 — Persistent prefix/reuse measurement — `DONE` baseline

## D4-01 — Durable reuse-observation aggregate — `DONE`

The existing metadata-only inference JSONL is reused as the durable cross-process observation log. `workspace reuse-report` deterministically reconstructs repeated-prefix opportunity from model + trust-domain + template + schema + stable-prefix hash rather than trusting the process-local reuse bit.

## D4-02 — Representative-period report — `DONE`

Default reporting window is 7 days and includes reuse opportunity, distinct/repeated prefix counts, prefix-size summary, prompt-eval duration share, model segmentation, opaque trust-domain segmentation and malformed/out-of-window accounting. Raw prompts/responses/tool output/prefix text/hashes and raw trust-domain labels are not emitted.

## D4-03 — Decision gate — `DONE`

Starting policy:

- insufficient representative events → collect more metadata;
- reuse below the configured planning threshold → redesign prompt layout first;
- reuse above threshold but prompt-eval does not dominate measured model duration → continue measurement/optimize elsewhere;
- reuse above threshold and prompt-eval dominates → a D9 serving/cache **benchmark** becomes eligible.

The gate never authorizes a production serving change and never reports repeated-prefix opportunity as a backend cache hit.

---

# D5 — Context map/rank/deduplicate/hard pack

## D5-01 — Bounded structural first view — `DONE` baseline

The runtime performs one structural map pass before body retrieval and emits bounded metadata-only retrieval traces while preserving the existing deterministic search semantics.

## D5-02 — Rank + deduplicate — `PARTIAL / BENCHMARK-GATED`

Deterministic lexical ranking and exact content deduplication are observable. Near-duplicate/diversity changes remain benchmark-gated because they can reduce recall.

## D5-03 — Hard context packer — `DONE` baseline

The complete rendered output, including separators, is charged to the hard budget and final output cannot exceed it.

## D5-04 — Critical-span protection — `DONE` baseline

Provenance/data-boundary headers are indivisible: preserve whole or skip the source. Body truncation can occur only after the complete protected header fits.

## D5-05 — Progressive expansion — `BENCHMARK-GATED`

Progressive body expansion remains disabled by default. It may not become production behavior until representative D7/benchmark evidence proves no verified-quality or recall regression.

Policy, user constraints, exact citations/source IDs and critical error/code fragments must survive transformations where exactness is required.

---

# D6 — Small-first deterministic routing and escalation

## D6-01 — Deterministic route reason codes — `DONE`

TaskContract model policy is projected into auditable reason-coded `MODEL` or `NO_LLM` decisions without reading raw task content.

## D6-02 — `NO_LLM` route — `DONE`

Verified deterministic local retrieval executes through the real TaskContract/validator path with no model client construction and zero inference telemetry.

## D6-03 — Failure-driven escalation controller — `DONE`

Retry/escalation limits are bound from the immutable TaskContract, persist task-wide in SQLite across stages/restarts, and are atomically reserved before fallback model invocation.

## D6-04 — Security monotonicity — `DONE`

Model-tier changes cannot expand source/tool/network/write/cache/logging authority. Unauthorized stronger-model transitions fail before budget consumption, telemetry or model invocation.

## D6-05 — Learned router — `BENCHMARK-GATED`

A learned router may be evaluated only after the deterministic baseline and D7 evaluation evidence exist. It may recommend a route but cannot grant capability or weaken TaskContract authority.

---

# D7 — Evaluation lab and promotion gates

## D7-01 — Versioned Golden corpus — `DONE`

Repository-owned deterministic control-plane expectations are versioned and content-addressed.

## D7-02 — Replay corpus — `DONE`

`workspace-eval` replays golden expectations through the production TaskContract compiler and deterministic route planner under exact Git lineage.

## D7-03 — Regression corpus — `DONE` baseline

Versioned regression cases protect production-critical routing, write scope, cache/logging and model-locality behavior.

## D7-04 — Adversarial/security corpus — `DONE` baseline

Versioned reject cases require fail-closed handling for forbidden public-web, NO_LLM scope expansion, web-gateway misuse and unknown tool authority.

## D7-05 — Edge/large-context corpus — `EVIDENCE-PENDING`

Versioned repository profile and strict external-result adapter are implemented. The profile covers protected spans, atomic provenance, many-source pressure, adversarial-near-critical-span and exact source-ID preservation. External holdout labels and real representative results are intentionally not committed.

## D7-06 — Efficiency/cache/concurrency corpus — `EVIDENCE-PENDING`

Versioned repository profile and strict result adapter are implemented for fixed-task quality, structured-output concurrency, measured resource benefit, cache trust-domain isolation, execution-budget concurrency and cache-measurement honesty. Real RTX/concurrency results remain pending.

## D7-07 — Metric versioning — `DONE`

D3-01..D3-07 semantics are bound to `workspace-d3-core-metrics-v1` with a canonical registry fingerprint. New benchmark lineage records the exact metric registry; legacy payloads cannot retroactively claim it.

## D7-08 — Promotion pipeline — `DONE` infrastructure

`workspace-promotion` requires all six mandatory evidence classes, exact baseline/candidate/rollback lineage, current metric registry, security PASS, holdout commitments/attestation where required and no waiver path. Missing D7-05/D7-06/replay evidence intentionally keeps real production promotion blocked.

Security is a hard constraint. Optimizers must not see holdout labels and production changes require regression/adversarial evidence plus rollback lineage.

---

# D8 — Context compression experiment — `BENCHMARK-GATED`

Prerequisites: D3 + D5 + D7 representative evidence.

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
- D9-03 TTFT/TPOT/throughput/VRAM/GPU-time
- D9-04 structured-output reliability under representative concurrency
- D9-05 trust-domain prefix-cache isolation
- D9-06 one primary production server selected by ADR
- D9-07 external cache layer only when native cache is insufficient and net value is positive

No framework accumulation. One primary stack wins. A D4 `SERVING_CACHE_BENCHMARK_ELIGIBLE` result permits only a benchmark, not production migration.

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

# Definition of Done for each checklist item

An item may move to `DONE` only when all applicable evidence exists:

1. implementation merged on exact `main` SHA;
2. focused unit/regression tests PASS;
3. security invariants PASS;
4. behavior is observable with metadata-only telemetry where relevant;
5. docs/config are updated;
6. benchmark-gated items include before/after representative measurements;
7. no new dependency/framework is accepted without evidence that existing code/runtime cannot provide the same outcome more simply.

`EVIDENCE-PENDING` means the implementation/profile portion is complete but condition 6 or an equivalent external/holdout evidence requirement has not yet been satisfied.

# Immediate execution queue

```text
D7 deterministic/evaluation/promotion infrastructure — DONE
        ↓
Run real dual-RTX5090 fixed benchmark:
  legacy_v1 / 48000
  quality_ranked_v1 / 48000
  quality_ranked_v1 / 40000
  quality_ranked_v1 / 32000
        ↓
Materialize representative D7-05 edge/large-context external results
and D7-06 efficiency/cache/concurrency benchmark results
        ↓
Quality acceptance first:
  Verified Task Success must not decrease
  First-Pass Verified Success must not decrease
  Evidence Coverage must not decrease
  exact required-validator success must not decrease
  critical-span loss must remain zero where applicable
        ↓
Only then compare tokens/context proxies/latency/retries/escalations/tool calls/resource usage
        ↓
Close deterministic control-plane debt:
  D0-03 unified Capability Broker
  D0-04 remaining step/tool/wall-time hard stops
  D0-05 authoritative failure taxonomy
        ↓
Run D4 representative reuse report on real workload telemetry
        ↓
Evaluate D5-02 near-duplicate/diversity and D5-05 progressive expansion only through D7 gates
```

Do not promote 40k/32k context budgets without benchmark evidence. Do not begin D9 production migration unless D4 representative evidence permits its benchmark. Do not begin D8/D10/D11/D12 production integration before their prerequisite gates are satisfied.
