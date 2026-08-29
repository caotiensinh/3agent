# D7-08 — Fail-Closed Production Promotion Gate

## Purpose

Production optimization changes must not be promoted from one successful benchmark or one green unit-test lane. D7-08 requires independent evidence across every mandatory evaluation class and binds that evidence to exact source lineage, the current metric registry and a rollback point.

## Mandatory classes

The v1 production gate requires all six classes with no waiver path:

1. `golden`
2. `replay`
3. `regression`
4. `adversarial_security`
5. `edge_large_context`
6. `efficiency_cache_concurrency`

Missing evidence for any class makes `accepted=false`.

## Repository-owned evidence

Golden, regression and adversarial/security evidence is built from two successful `workspace-eval` reports produced against the same corpus identity:

- one report for the exact baseline Git SHA;
- one report for the exact candidate Git SHA.

`workspace-promotion replay-evidence` stores only compact hashes and lineage. It does not copy replay case bodies or actual policy payloads into the promotion evidence file.

At final promotion time the gate re-opens the repository-owned corpus files and recomputes their canonical corpus SHA. A stale or substituted evidence receipt therefore fails `REPOSITORY_CORPUS_LINEAGE_MISMATCH`.

## External replay and holdout isolation

Representative replay and edge/large-context classes require evaluator attestation and a SHA-256 commitment to holdout labels. Raw labels are never accepted by the evidence schema and are never emitted in promotion receipts.

Efficiency/cache/concurrency evidence requires evaluator attestation but no holdout-label commitment in v1.

## Metric identity

Every evidence receipt must match:

- metric registry ID `workspace-d3-core-metrics-v1`;
- the exact current `DEFAULT_METRIC_REGISTRY.sha256`.

If metric semantics change, old evidence stops being promotion-compatible automatically.

## Lineage and rollback

Every evidence receipt must bind the same exact 40-hex:

- `baseline_ref`;
- `candidate_ref`.

The v1 `rollback_ref` must exactly equal `baseline_ref`. There is no inferred or floating rollback branch.

## Security and privacy

Promotion evidence accepts metadata-only fields and compact evidence references. Unknown fields fail closed. This prevents raw prompts, model responses, evidence text, credentials or business content from being smuggled into the promotion receipt.

## Current readiness rule

D7-08 infrastructure can be implemented before D7-05 and D7-06 are complete. In that state the gate is intentionally non-promotable because edge/large-context and efficiency/cache/concurrency evidence is missing. Infrastructure readiness is not production-promotion readiness.
