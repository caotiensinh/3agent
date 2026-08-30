# D5-02a Representative Exact-Body Dedupe Benchmark

## Purpose

This benchmark is the representative promotion lane for D5-02a exact-body duplicate suppression. It is intentionally separate from the generic context-packing benchmark because the generic fixed corpus does not guarantee that two distinct sources contain the same cleaned evidence body.

The benchmark does not authorize D5-02a merely because the feature is implemented or because characters can be removed in a synthetic unit test.

## One manual authorization

The GitHub Actions workflow is:

```text
benchmark-d502a-exact-dedupe
```

It is `workflow_dispatch` only, requires `confirm=BENCHMARK`, has `contents: read`, checks out an exact 40-hex source SHA with persisted credentials disabled, and runs only on the self-hosted Linux/X64/RTX5090 lane.

One authorized run executes both configurations serially on the same fixed task set and exact source checkout:

```text
baseline-legacy-48k
  legacy_v1
  48000 chars
  exact_body_dedupe = false

exact-dedupe-legacy-48k
  legacy_v1
  48000 chars
  exact_body_dedupe = true
```

No other packing mode or context-budget change is introduced into this comparison.

## Representative duplicate corpus

The task set is:

```text
benchmarks/d502a_exact_body_dedupe_task_set_v1.json
```

Every case includes both:

```text
benchmarks/fixtures/d502a_exact_mirror_a.md
benchmarks/fixtures/d502a_exact_mirror_b.md
```

Those files have different source identities but must remain byte-identical and non-trivial in size. The runner fails closed if the bytes differ, either fixture is missing, or any D5-02a benchmark case stops containing the mirror pair.

KnowledgeGateway preserves the decoded document body independently from filename/title metadata, so these two fixtures become distinct source identities with equal cleaned evidence bodies. This exercises the actual D5-02a equality boundary rather than assuming duplicate opportunity exists.

## Promotion decision

The normal WorkSpace optimization gate is recomputed for the candidate. D5-02a adds one stricter rule:

```text
measured token reduction must be > 0.0%
```

There is no invented arbitrary performance threshold. Zero measured reduction is not treated as a useful optimization simply because the generic optimization gate permits a 0% minimum by default.

Promotion therefore requires all of the following:

1. required validator acceptance remains PASS;
2. Verified Task Success does not decrease;
3. First-Pass Verified Success does not decrease;
4. verified task count does not decrease;
5. Evidence Coverage does not decrease;
6. the generic optimization gate accepts the comparison;
7. measured total tokens per verified task are strictly lower than baseline.

A large token reduction never overrides a correctness or validator regression.

## Evidence and independent recomputation

The benchmark runner writes:

```text
suite.json
d502a-decision.json
baseline-legacy-48k/benchmark.json
baseline-legacy-48k/isolation.json
exact-dedupe-legacy-48k/benchmark.json
exact-dedupe-legacy-48k/isolation.json
```

The verification pass then reloads the persisted evidence and independently recomputes:

- source SHA lineage;
- task-set identity;
- exact mirror equality;
- baseline/candidate isolation policy;
- configuration fingerprint separation;
- fixed task IDs and fixture corpus consistency;
- required-validator acceptance;
- optimization acceptance;
- strict positive token benefit;
- final D5-02a promotion decision.

It writes:

```text
d502a-verification.json
```

The published GitHub artifact contains metadata-only receipts/manifests. Variant databases, research artifacts, raw prompts, raw evidence, inference telemetry, resource telemetry and audit logs are not uploaded by the workflow.

## Interpretation

`promotion_eligible=true` means the exact tested source SHA, model, task set and representative mirror corpus satisfied the D5-02a gate. It does not authorize fuzzy/semantic deduplication, embeddings, source-authority merging, progressive expansion or any other D5 candidate.

`promotion_eligible=false` is a valid completed engineering result. Keep `WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE=false` and do not rerun the unchanged candidate repeatedly in search of a favorable sample. A new run is justified only by a meaningful implementation, model, workload or benchmark-contract change.
