# WorkSpace D4 Prefix Reuse Measurement

## Purpose

D4 answers one question before WorkSpace considers any serving/cache migration:

> Does representative local traffic contain enough stable-prefix reuse opportunity, and is prompt prefill expensive enough, to justify a serving/cache benchmark?

D4 does **not** claim a backend cache hit. The current Ollama path does not expose an authoritative cache-hit metric, so WorkSpace reports repeated-prefix **opportunity** only.

## Reuse identity

A reusable observation is isolated by the full metadata key:

```text
model
+ trust domain
+ prompt template version
+ structured schema ID
+ stable-prefix SHA-256
```

The stable-prefix text itself is not stored or emitted by D4. A matching hash in a different trust domain is a different key and never contributes cross-domain reuse.

## Durable observation without another database

Inference telemetry is already append-only, metadata-only and persistent across process restarts. D4 deliberately reuses that log instead of introducing a second database/index that would duplicate state.

`workspace reuse-report` deterministically replays the selected telemetry period and rebuilds the aggregate from persisted events. It ignores the process-local `prefix_reuse_candidate` bit and computes repeated-prefix opportunity from the durable metadata key above.

This satisfies the cross-process/representative-period requirement while following the WorkSpace resource rule:

```text
avoid new state
→ reuse existing authoritative metadata
→ aggregate deterministically on read
```

If telemetry scale later makes replay materially expensive, a compact derived index may be benchmarked. It is not justified pre-emptively.

## Default operator command

```bash
workspace reuse-report
```

Defaults:

- window: 7 days;
- minimum valid events: 20;
- reuse opportunity planning threshold: 30%;
- telemetry path: `WORKSPACE_INFERENCE_TELEMETRY` when set, otherwise the configured artifact-root inference log.

Optional example:

```bash
workspace reuse-report \
  --days 14 \
  --min-events 50 \
  --reuse-threshold-pct 30 \
  --telemetry /var/lib/workspace/data/activity/inference.jsonl
```

The 30% threshold is the reviewed planning starting point, not a universal performance law. It may be recalibrated from WorkSpace's own traces.

## Reported metrics

Schema:

```text
workspace-prefix-reuse-report/v1
```

The report includes:

- valid metadata events in the selected period;
- distinct stable-prefix keys;
- keys observed more than once;
- repeated-prefix events;
- repeated-prefix opportunity rate;
- stable-prefix character-size p50/p95/max;
- prompt-eval duration share of measured model duration;
- per-trust-domain and per-model reuse opportunity;
- malformed/out-of-window/future event accounting;
- a deterministic D4 decision gate.

It deliberately reports:

```text
backend_cache_hits = null
backend_cache_hit_metric_available = false
```

## Decision gate

Schema:

```text
workspace-prefix-reuse-decision/v1
```

The gate is advisory for **what may be benchmarked next**. It never authorizes a production serving change.

Decision order:

```text
representative data sufficient?
  no  -> INSUFFICIENT_REPRESENTATIVE_DATA
  yes
   ↓
reuse opportunity >= configured threshold?
  no  -> REDESIGN_PROMPT_LAYOUT_FIRST
  yes
   ↓
prompt-eval duration >= 50% of measured total model duration?
  no  -> REUSE_HIGH_PREFILL_NOT_DOMINANT
  yes -> SERVING_CACHE_BENCHMARK_ELIGIBLE
```

`prompt_eval_duration_share >= 0.5` is used only to operationalize the word *dominates* for this gate. It is not a claim that 50% is universally optimal.

Even when the result is `SERVING_CACHE_BENCHMARK_ELIGIBLE`, the output explicitly keeps:

```text
production_serving_change_authorized = false
```

A later D9 benchmark must still preserve verified quality, security isolation and operational correctness before any serving-engine decision.

## Security and privacy

D4 reads only the metadata already emitted by `workspace-inference-telemetry/v2`:

- model identifier;
- trust domain;
- template version;
- schema ID;
- stable-prefix hash and size;
- timing/token metadata;
- timestamp.

It does not require or emit:

- raw system/user prompts;
- raw model responses;
- retrieved evidence bodies;
- tool output;
- credentials;
- confidential business content;
- stable-prefix text or prefix hashes in the report.

Unknown extra fields in telemetry are ignored. Malformed metadata remains visible in data-quality counters rather than being silently treated as valid reuse evidence.

## Relationship to D9

D4 is a prerequisite gate, not a serving recommendation.

```text
D4 low reuse
  -> improve prompt stability/layout first

D4 high reuse but prefill not dominant
  -> continue measurement / optimize elsewhere

D4 high reuse + prefill dominant
  -> D9 serving/cache benchmark is permitted
  -> production change still prohibited without benchmark evidence
```

No vLLM, SGLang, LMCache, HiCache or additional cache infrastructure is introduced by D4.
