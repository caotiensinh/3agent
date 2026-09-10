# D7 — Evaluation Lab and Promotion Gate v1

## Purpose

D7 turns WorkSpace optimization evidence into a fail-closed production admission process. It does not create benchmark results and it does not allow missing evidence to be replaced by assumptions.

## Versioned corpus contract

`evaluation/corpus_manifest_v1.json` declares six mandatory evaluation classes:

1. `golden`
2. `replay`
3. `regression`
4. `adversarial_security`
5. `edge_large_context`
6. `efficiency_cache_concurrency`

Every class is required for production promotion. The current fixed benchmark task set is reused where it is already suitable; replay, adversarial and large-context evidence may be produced externally so production data or holdout labels do not need to be committed to the repository.

The manifest itself is versioned and canonical-hashed. Promotion evidence must identify the exact corpus ID/hash it evaluated.

## Holdout isolation

Holdout labels are not stored in the optimizer view and are not required in promotion receipts.

For corpus classes with `external_holdout_required`, promotion evidence contains only:

- a SHA-256 commitment to the externally evaluated holdout label set;
- an attestation flag that a holdout evaluator produced the evidence;
- compact evidence references/hashes;
- pass/fail checks.

Raw holdout labels remain unavailable to the optimizer path.

## Metric versioning

D7 v1 pins `workspace-evaluation-metrics/v1` plus a deterministic hash of metric definitions. Evidence from a different metric definition set is rejected even if the metric names happen to match.

Quality hard gates remain:

- Verified Task Success must not decrease;
- First-Pass Verified Success must not decrease;
- Evidence Coverage must not decrease where applicable;
- exact required-validator success must not decrease.

Efficiency metrics are evaluated only after quality/security evidence passes in their producing benchmark/evaluation lane.

## Promotion pipeline

`workspace-eval promotion-check` requires:

- exact baseline Git SHA;
- exact candidate Git SHA;
- exact rollback Git SHA;
- one evidence receipt for every mandatory corpus class;
- matching corpus and metric lineage;
- required checks PASS;
- security PASS;
- holdout commitment/evaluator evidence where required.

For v1, `rollback_ref` must exactly equal `baseline_ref`. This makes rollback lineage explicit and prevents a promotion receipt from naming an unrelated fallback commit.

Missing replay/adversarial/edge/holdout evidence is a normal fail-closed result, not a reason to waive the class.

## Metadata-only evidence

Evaluation receipts accept only compact evidence IDs, paths and hashes. Raw prompts, raw evidence bodies, credentials and business content do not belong in promotion artifacts.

The final promotion receipt contains only lineage, corpus/metric hashes, per-class gate outcomes, compact evidence references and the decision.

## Operational commands

Validate the versioned corpus without exposing holdout labels:

```bash
workspace-eval validate-corpus \
  --corpus evaluation/corpus_manifest_v1.json
```

Run a production promotion check after all six class receipts exist:

```bash
workspace-eval promotion-check \
  --corpus evaluation/corpus_manifest_v1.json \
  --baseline-ref <40-hex-baseline> \
  --candidate-ref <40-hex-candidate> \
  --rollback-ref <same-40-hex-baseline> \
  --evidence <golden.json> \
  --evidence <replay.json> \
  --evidence <regression.json> \
  --evidence <adversarial.json> \
  --evidence <edge.json> \
  --evidence <efficiency.json> \
  --output promotion-receipt.json
```

No evidence receipts are pre-generated in the repository because doing so would falsely imply that real replay/holdout/adversarial evaluations have already run.

## Current D7 boundary

This change establishes the corpus schema, metric version, holdout-isolation contract and deterministic promotion gate. It does **not** claim representative external replay, holdout or large-context evidence exists yet. Those evidence populations remain required before any real production promotion can return PASS.
