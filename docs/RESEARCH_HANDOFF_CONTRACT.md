# Research → Presentation Handoff Contract

## Purpose

The Research Agent is not only a search component. It is the factual quality gate for downstream presentation work.

Agent 2 must consume a compact, cleaned handoff rather than raw fetched page text.

## Pipeline

```text
raw web results
  -> canonicalize URLs
  -> remove duplicate URLs
  -> fetch pages
  -> remove script/style/navigation/footer/form boilerplate
  -> deduplicate extracted text fragments
  -> evidence-bounded LLM synthesis
  -> reject claims without valid source IDs
  -> deduplicate repeated claims
  -> merge valid source lineage
  -> assign confidence
  -> identify source conflicts
  -> quality gate
  -> TASK_handoff.json
  -> Agent 2
```

## Artifacts

For task `TASK-YYYYMMDD-NNNN`, Agent 1 writes:

```text
data/research/YYYY-MM-DD/TASK-YYYYMMDD-NNNN.json
    Full research and audit payload, including extracted evidence text.

data/research/YYYY-MM-DD/TASK-YYYYMMDD-NNNN.md
    Human-readable research report.

data/research/YYYY-MM-DD/TASK-YYYYMMDD-NNNN_handoff.json
    Compact downstream payload for Agent 2.
```

Raw extracted page text remains in the full research JSON for audit but is intentionally omitted from the handoff.

## Handoff schema V1

```json
{
  "schema_version": "1.0",
  "task_id": "TASK-...",
  "presentation_ready": true,
  "blockers": [],
  "objective": "...",
  "key_facts": [
    {
      "fact_id": "F001",
      "claim": "...",
      "source_ids": ["S1", "S2"],
      "confidence": "high"
    }
  ],
  "inferences": [],
  "conflicts": [],
  "unresolved_items": [],
  "conclusion": "...",
  "recommended_next_actions": [],
  "sources": [
    {
      "source_id": "S1",
      "title": "...",
      "url": "https://...",
      "fetch_status": "ok"
    }
  ],
  "quality_metrics": {
    "source_count": 0,
    "usable_source_count": 0,
    "verified_fact_count": 0,
    "high_confidence_fact_count": 0,
    "inference_count": 0,
    "conflict_count": 0,
    "critical_conflict_count": 0,
    "unresolved_count": 0
  }
}
```

## Deterministic rules

### Claim admission

A verified fact or inference is admitted only when it references at least one valid collected source ID.

Unknown, missing or fabricated source IDs cause the claim to be rejected from verified/inference output and recorded as unresolved evidence-validation failure.

### Deduplication

Claims are normalized for whitespace, punctuation and case before duplicate detection. Duplicate claims are collapsed and their valid source IDs are merged.

### Confidence

V1 confidence is transparent and deterministic:

- `high`: at least two collected source IDs support the normalized claim;
- `medium`: exactly one collected source ID supports the claim;
- unsupported: the claim is excluded from verified facts.

This confidence represents evidence coverage, not an assertion that any source is infallible.

### Conflict handling

A conflict requires at least two valid source IDs. Conflict severity is `low`, `medium`, or `critical`.

A critical source conflict blocks downstream presentation generation.

## Presentation-ready gate

The handoff is ready only when:

1. at least one usable fetched source exists;
2. at least one verified fact exists;
3. no critical source conflict remains.

Blocker codes:

- `NO_USABLE_SOURCE`
- `NO_VERIFIED_FACT`
- `CRITICAL_SOURCE_CONFLICT`

The handoff field `presentation_ready` is the authoritative permission for Agent 2.

## Agent 2 hard validation

Before generating anything, Agent 2 validates:

1. handoff file exists;
2. handoff `task_id` exactly equals the requested task;
3. `schema_version` is supported;
4. `presentation_ready` is exactly `true`;
5. `key_facts` is non-empty.

Failure moves the task to `WAITING_HUMAN`, records a blocked activity, and stops presentation generation.

## Non-goals of V1

V1 does not claim semantic near-duplicate detection across arbitrarily different wording, automatic truth determination from source reputation, or automatic resolution of contradictory primary sources. Those can be added later without changing the handoff boundary.
