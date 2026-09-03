# WorkSpace Master Implementation Checklist

## Status legend

- `DONE` — implemented and covered by repository evidence/tests.
- `DONE baseline` — required baseline is enforced; later optimization may still be evaluated behind gates.
- `PARTIAL` — meaningful foundation exists but the doctrine is not fully enforced end-to-end.
- `TODO` — required work remains and can be executed locally now.
- `EXTERNAL-BLOCKED` — repository implementation is complete, but a real external evaluator/holdout/attestation is required; WorkSpace must not fabricate it.
- `NO-GO` — representative evidence exists and the tested candidate was rejected; keep the candidate disabled/unpromoted.
- `BENCHMARK-GATED` — production integration is prohibited until a future representative benchmark justifies it.
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

The following work packages are complete in the current implementation lineage:

- D1 Handoff Trust Boundaries — `DONE`
- D2 Structured Output + Semantic Validation — `DONE`
- D3 Verified Work Metrics foundation — `DONE`
- Evidence Packing Rank v1 — `DONE`
- Authoritative Packing Receipt v1 — `DONE`
- Runtime Validator Bridge — `DONE` when its exact-head CI and merge evidence are green
- Benchmark Isolation v1 — `DONE`

The next benchmark work is **fixed-task benchmark execution + quality acceptance gating**. Isolation is not to be reimplemented.

---

# Current authoritative closure

Repository closure lineage before this checklist sync:

`efe382a7313076f1fe642255a241e0485533231a`

Representative hardware evidence was collected against exact product source:

`5472ebbad650d8c466ae0353c3f99408680a770d`

Evidence boundary:

- GitHub Actions run `33267084880` — PASS;
- artifact `9719019837`;
- artifact ZIP SHA-256 `sha256:9b41d5a0e07b347625869f79d32d77fcf73fa34cfbb0b1d156bdf93bfe389edf`;
- benchmark verification SHA-256 `sha256:1e5df3ccf00665d78f8d85ba4a20507ec7c4a0127d2675a3ca623c97f20dc520`;
- D7-06 observation SHA-256 `sha256:f6d7208c67dee7631ace778bcdfb1e864b7df127094e4d658355eb9e2a6e10ac`;
- durable metadata-only receipt: `evaluation/representative_hardware_closure_20260830.json`.

The independent benchmark evidence verifier passed. That means the evidence set was internally consistent and recomputable; it does **not** mean any optimization candidate passed promotion.

Exact promotion result:

| Variant | Result |
| --- | --- |
| `legacy_v1 / 48000` | reference baseline |
| `quality_ranked_v1 / 48000` | `NO-GO` |
| `quality_ranked_v1 / 40000` | `NO-GO` |
| `quality_ranked_v1 / 32000` | `NO-GO` |

Therefore the current production context behavior remains unchanged. No 48k-ranked/40k/32k promotion is authorized.

The same run completed D7-06 precursor hardware observation: 8/8 structured requests passed deterministic semantics, concurrency 4 was observed, execution-budget concurrency passed, and WorkSpace reuse-opportunity trust-domain isolation passed. Backend cache isolation, measured resource benefit, authoritative GPU-active time and external evaluator attestation remain absent. Positive D7-06 promotion evidence is therefore **not admissible** from this run.

---

# PICO — PicoLM-derived resource discipline

## PICO-01 — Explicit per-task budgets — `DONE`

TaskContract owns hard input/retrieval/tool-output/output, step, tool-call, retry, escalation and wall-time limits. Model output cannot increase them.

## PICO-02 — Lazy context expansion — `PARTIAL / BENCHMARK-GATED`

Structural map-before-body retrieval is implemented. Progressive/targeted expansion remains disabled until a future representative candidate preserves required validators, verified quality, evidence coverage, recall and critical spans.

## PICO-03 — Lazy model/tool acquisition — `DONE baseline`

Deterministic NO_LLM routing, typed TaskCapabilityAuthority and persistent monotonic revocation are enforced at live boundaries.

## PICO-04 — Deterministic-before-LLM short circuit — `DONE baseline`

Policy, TaskContract, DLP, schema, resource and validator decisions are deterministic; verified local retrieval can finish with zero model inference.

## PICO-05 — Constrained known syntax — `DONE`

Structured generation uses JSON Schema plus deterministic local post-validation. Probabilistic JSON repair is prohibited. Ollama transport compatibility may narrow decoder grammar keywords, but the authoritative full schema still governs post-validation.

## PICO-06 — Metadata-only inference telemetry — `DONE`

No raw prompt/response is required for inference telemetry.

## PICO-07 — Reuse-before-recompute fingerprint — `DONE baseline`

Stable-prefix opportunity is measured across process restarts and trust domains without claiming backend cache hits.

## PICO-08 — Verified work per resource — `DONE baseline`

Resource efficiency is normalized by verified work, not request count.

---

# D0 — Deterministic control-plane completeness — `DONE baseline`

- **D0-01 Task Contract compiler/schema — `DONE`**: deterministic authority, budgets, validators and policy projection.
- **D0-02 Data/network policy boundary — `DONE`**: confidential-local and public-research trust zones are separated.
- **D0-03 Capability Broker semantics — `DONE baseline`**: typed capability/resource/effect checks plus persistent monotonic revocation.
- **D0-04 Bounded minimal loop — `DONE`**: persistent steps/tool/retry/escalation/wall-time limits fail closed.
- **D0-05 Failure taxonomy — `DONE`**: versioned deterministic failure classes drive bounded recovery; unknown/security/budget failures cannot be relabeled retryable by model content.
- **D0-06 Validator Bus / Runtime Validator Bridge — `DONE`**: immutable TaskContract + deterministic validator ledger required before DONE.

---

# D1 — Handoff trust boundaries — `DONE`

- **D1-01 Research → Presentation sanitizer — `DONE`**
- **D1-02 Tool/Retrieval → Research sanitizer — `DONE`**
- **D1-03 Activity/Artifact → Daily Report sanitizer — `DONE`**
- **D1-04 Typed handoff security metadata — `DONE`**
- **D1-05 End-to-end adversarial handoff CI — `DONE`**

Untrusted content can never grant policy, tool, model, network, write or validator authority.

---

# D2 — Task-specific structured schemas and semantic validators — `DONE`

- **D2-01 Research structured schema — `DONE`**
- **D2-02 Presentation structured schema — `DONE`**
- **D2-03 Daily Report structured schema — `DONE`**
- **D2-04 Semantic validators after schema — `DONE`**
- **D2-05 Schema IDs + validation receipts — `DONE`**

Schema validity alone never authorizes unsupported evidence, unknown references or security fields.

---

# D3 — Verified-work and context metrics — `DONE foundation`

- **D3-01 Verified Task Success Rate — `DONE`**
- **D3-02 First-Pass Verified Success — `DONE`**
- **D3-03 Tokens per Verified Task — `DONE`**
- **D3-04 Tool calls/retries/escalations per Verified Task — `DONE`**
- **D3-05 Evidence Coverage — `DONE`**
- **D3-06 Context Precision Proxy — `DONE`**
- **D3-07 Context Recall Proxy — `DONE`**
- **D3-08 Unified `workspace metrics` snapshot — `DONE`**
- **D3-09 GPU-seconds per Verified Task — `TODO / instrumentation-blocked`**
- **D3-10 Metadata privacy boundary — `DONE baseline`**
- **D3-11 Optimization Acceptance Gate — `DONE`**

D3-09 remains intentionally unimplemented because authoritative GPU-active-time instrumentation is not yet available. Task wall time, model request duration and ordinary utilization snapshots must not be mislabeled GPU seconds.

---

# Benchmark foundation after D3

## Evidence Packing Rank v1 — `DONE`

`legacy_v1` and `quality_ranked_v1` are deterministic and fingerprinted.

## Authoritative Packing Receipt v1 — `DONE`

Metadata-only source accounting is authoritative when present; partial/tampered receipts fail closed.

## Benchmark Isolation v1 — `DONE`

Variants have isolated DB, artifacts, inference/resource telemetry and audit sinks.

## Fixed-task Benchmark Execution + Required-validator Acceptance v1 — `DONE representative execution`

The real dual-RTX5090 benchmark has been executed on the fixed task set. Evidence verification passed; all tested ranked context candidates were rejected by the promotion gate.

Important observed decisions:

- `ranked-48k` — `NO-GO`;
- `ranked-40k` — `NO-GO`; verified-task/first-pass success regressed and tokens per verified task worsened;
- `ranked-32k` — `NO-GO`; aggregate optimization metrics were acceptable, but a required schema-validator PASS was lost, so required-validator acceptance correctly blocked promotion.

A verified negative result is a completed engineering decision. Do not repeatedly rerun the same unchanged candidate expecting a different governance outcome.

---

# D4 — Persistent prefix/reuse measurement — `DONE baseline`

- **D4-01 Durable reuse-observation aggregate — `DONE`**
- **D4-02 Representative-period report — `DONE` implementation**
- **D4-03 Decision gate — `DONE`**

A future D9 benchmark requires representative real-workload reuse/prefill evidence. The current D7-06 observation proves only WorkSpace reuse-opportunity trust-domain isolation; it does not prove backend cache hits or backend cache isolation.

---

# D5 — Context map/rank/deduplicate/hard pack

## D5-01 — Bounded structural first view — `DONE baseline`

Structural mapping precedes body retrieval and remains metadata-observable.

## D5-02 — Rank + deduplicate — `PARTIAL / BENCHMARK-GATED`

Deterministic lexical ranking and exact deduplication remain available. The current ranked context candidates are `NO-GO`; near-duplicate/diversity behavior must not be enabled in production from this evidence.

## D5-03 — Hard context packer — `DONE baseline`

Complete rendered output is charged to the hard budget.

## D5-04 — Critical-span protection — `DONE baseline`

Protected provenance/data-boundary headers are preserve-whole-or-skip.

## D5-05 — Progressive expansion — `BENCHMARK-GATED / KEEP DISABLED`

The representative benchmark did not authorize progressive expansion. Any future implementation must return through D7 quality/security gates.

---

# D6 — Small-first deterministic routing and escalation

- **D6-01 Deterministic route reason codes — `DONE`**
- **D6-02 Verified NO_LLM route — `DONE`**
- **D6-03 Failure-driven escalation controller — `DONE`**
- **D6-04 Security monotonicity — `DONE`**
- **D6-05 Learned router — `BENCHMARK-GATED`**

A learned router may recommend but can never grant authority or bypass immutable retry/escalation/model limits.

---

# D7 — Evaluation lab and promotion gates

- **D7-01 Versioned Golden corpus — `DONE`**
- **D7-02 Deterministic replay — `DONE`**
- **D7-03 Regression corpus — `DONE baseline`**
- **D7-04 Adversarial/security corpus — `DONE baseline`**
- **D7-05 Edge/large-context corpus — `EXTERNAL-BLOCKED`**
- **D7-06 Efficiency/cache/concurrency corpus — `NO-GO for current tested candidates`**
- **D7-07 Metric versioning — `DONE`**
- **D7-08 Promotion pipeline — `DONE infrastructure`**

### D7-05 exact blocker

Repository profile and strict result adapter are complete. A positive result requires real external holdout labels, their SHA-256 commitment, exact baseline/candidate refs, every required check, security PASS and external evaluator attestation. WorkSpace must not generate the hidden labels or self-attest them.

### D7-06 exact state

Representative dual-RTX5090 precursor evidence now exists. Structured-output concurrency, execution-budget concurrency and WorkSpace reuse-opportunity trust isolation passed. Positive promotion remains inadmissible because:

- all current tested context candidates are not promotion eligible;
- measured resource benefit is absent;
- actual backend cache isolation is absent;
- authoritative GPU-active time is absent;
- external evaluator attestation is absent.

This is not `EVIDENCE-PENDING` in the old sense of “nothing has been run.” It is a representative **NO-GO** for the current candidate set plus explicit evidence gaps for any future positive D7-06 result.

---

# D8 — Context compression experiment — `BENCHMARK-GATED`

Prerequisites remain D3 + D5 + representative D7 evidence. No production compression is authorized. Protected/security/citation-critical context must never be compressed merely to improve token metrics.

---

# D9 — Serving/cache benchmark — `BENCHMARK-GATED`

A D9 benchmark may begin only when D4 real-workload telemetry proves sufficient reuse/prefill opportunity. Production migration remains prohibited until one serving stack wins representative quality, reliability, trust-isolation and resource gates.

---

# D10 — Model-architecture optimization — `BENCHMARK-GATED`

Speculative decoding, quantization or architecture changes require equal-or-better verified quality/security plus material measured resource or latency benefit.

---

# D11 — Edge PicoLM / BitNet lane — `R&D`

PicoLM remains a production design philosophy; edge runtime work stays isolated R&D until target CPU memory/latency/power/correctness gates pass.

---

# D12 — Specialist model / prompt internalization — `BENCHMARK-GATED`

Only evaluate after a stable high-volume repetitive task family exists. Authorization, DLP, network, tenant, retention and incident controls always remain outside model weights.

---

# Definition of Done

An item may move to positive `DONE` only when all applicable evidence exists:

1. implementation merged on exact `main` lineage;
2. focused unit/regression tests PASS;
3. security invariants PASS;
4. behavior is metadata-observable where relevant;
5. docs/config are updated;
6. benchmark-gated items have representative before/after measurements;
7. required validators and verified quality do not regress;
8. no external attestation, holdout label, cache hit, GPU-active time or resource benefit is fabricated or inferred from a weaker proxy.

A `NO-GO` is also a valid closure outcome: preserve the safe baseline and do not promote the rejected candidate.

---

# Immediate execution queue after representative closure

```text
Deterministic control plane D0 — DONE baseline
        ↓
Representative dual-RTX5090 fixed benchmark — DONE
  ranked-48k = NO-GO
  ranked-40k = NO-GO
  ranked-32k = NO-GO
        ↓
Preserve current production context behavior
        ↓
D7-05 external holdout evaluation — EXTERNAL-BLOCKED
  only proceed when real independent labels/evaluator are available
        ↓
Future positive D7-06 evaluation — optional/new candidate only
  must measure resource benefit + actual backend cache isolation
  must obtain evaluator attestation
        ↓
D4 representative real-workload reuse report — run only from real metadata telemetry
  if reuse/prefill opportunity is insufficient, do not start D9
        ↓
D3-09 authoritative GPU-seconds — implement only when authoritative instrumentation exists
        ↓
D5-02 / D5-05 / D6-05 / D8 / D9 / D10 / D12 remain gated
D11 remains R&D
```

## Non-negotiable decisions

- Do **not** promote 48k-ranked, 40k or 32k from the 2026-08-30 evidence set.
- Do **not** enable progressive expansion from this result.
- Do **not** call reuse opportunity a backend cache hit.
- Do **not** infer GPU-active time from task wall time or request duration.
- Do **not** fabricate D7-05 holdout labels or evaluator attestation.
- Do **not** begin D9 production migration merely because concurrency observation passed.
