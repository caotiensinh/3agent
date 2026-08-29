# WorkSpace D3 Metrics Contract

## Status

D3 is the deterministic measurement layer for WorkSpace efficiency and verified quality. The metrics are derived from TaskContract/Validator Ledger evidence, task-scoped inference telemetry, typed resource events and Research handoff accounting. Model self-reports and `TaskStatus.DONE` are never accepted as substitutes for verified success.

The unified operator surface is:

```bash
workspace metrics
workspace metrics --date YYYY-MM-DD
workspace metrics --task-id TASK-... --task-id TASK-...
```

`--date` and `--task-id` are mutually exclusive. The selected task IDs are resolved once and passed unchanged to every metric aggregator.

## D3-01 — Verified Task Success Rate

```text
verified tasks / attempted tasks
```

A task is verified only when it has an immutable TaskContract binding and every required validator's latest result is passing.

`TaskStatus.DONE`, workflow strings and model claims are excluded from the definition.

## D3-02 — First-Pass Verified Success Rate

```text
first-pass verified tasks / attempted tasks
```

A later retry may make a task finally verified, but it cannot rewrite first-pass history. This separates recovery effectiveness from initial execution quality.

## D3-03 — Tokens per Verified Task

```text
all attributable input/output tokens spent on selected attempted tasks
---------------------------------------------------------------------
                         verified tasks
```

Token spend from failed or unverified tasks stays in the numerator. Inference events without authoritative task scope are reported as unattributed and are never guessed from prompt text or timestamps.

## D3-04 — Resource Events per Verified Task

Typed events:

- `tool_call`
- `model_retry`
- `model_escalation`

Each count is divided by verified tasks. Failed/unverified task spend remains visible. Runtime metric events exclude raw URL, argv, exception message, prompt, response and evidence content.

## D3-05 — Evidence Coverage

```text
evidence-supported material claims
----------------------------------
material claims requiring evidence
```

The denominator contains only material claim candidates the current Research contract can classify deterministically: accepted verified facts/inferences, uncited fact/inference rejections and quantitative claims rejected by the numeric-evidence gate.

Generic unresolved prose, narrative conclusions, conflicts and request constraint gaps are not silently converted into claim labels.

## D3-06 — Context Precision Proxy

```text
source TEXT chars supplied to synthesis from cited sources
----------------------------------------------------------
         all source TEXT chars supplied to synthesis
```

This is explicitly a **source-level citation-character utilization proxy**, not true token/span context precision.

Rules:

- source cited many times is counted once for its supplied text;
- verified facts, inferences and conflicts can establish citation use;
- only source text that actually fits the existing synthesis packing budget is counted;
- prompt scaffolding, titles, URLs and source-suitability preview context are excluded from the reported text counters;
- `true_span_precision` is intentionally `null` in the metric output.

## D3-07 — Context Recall Proxy

```text
source TEXT chars actually supplied to synthesis
-----------------------------------------------
all source TEXT chars that passed suitability gate
```

This measures **retention under the synthesis context budget**. It is not semantic/token recall and does not claim every vetted character is equally relevant.

A low value means the suitability gate admitted more evidence than the synthesis context budget retained. `true_semantic_recall` is intentionally `null`.

## D3-08 — Unified Metrics Snapshot

D3-08 does not introduce another formula. It composes D3-01 through D3-07 into one versioned JSON snapshot using one exact task scope.

Top-level schema:

```text
workspace-unified-metrics/v1
```

Sections:

- `verified_work`
- `token_efficiency`
- `resource_efficiency`
- `evidence_coverage`
- `context_precision_proxy`
- `context_recall_proxy`

Each section preserves its own schema version and raw accounting counters so dashboards do not have to infer denominators.

## Interpretation rules

1. Never optimize a metric by excluding failed/unverified task cost from its numerator.
2. Never call D3-06 true span/token precision.
3. Never call D3-07 semantic recall.
4. Missing, malformed or unattributed telemetry must remain visible rather than being silently dropped.
5. Compare serving engines, model routes, context packing or caching only on the same task scope and verified-quality gate.
6. A cost reduction is not accepted as an improvement if Verified Task Success or required evidence quality regresses.

## Security boundary

The D3 layer is metadata/accounting only. It grants no network, shell, file, model, credential or mutation authority. Raw prompts, model responses, retrieved source bodies, tool output and secrets are not required for the unified snapshot.
