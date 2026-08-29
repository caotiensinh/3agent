# WorkSpace Benchmark Isolation v1

## Purpose

Benchmark variants must not share mutable runtime state. A 48k baseline and a 40k/32k context candidate are not comparable if they append into the same task database, artifact tree, inference telemetry, resource telemetry or gateway audit files.

WorkSpace therefore treats isolation as a prerequisite to optimization measurement rather than as an optional cleanup step.

## Isolation boundary

Each benchmark variant receives its own sandbox:

```text
<benchmark-root>/<variant>/
├── isolation.json
├── benchmark.json
├── state/
│   └── tasks.db
└── data/
    ├── activity/
    │   ├── inference.jsonl
    │   ├── resource_events.jsonl
    │   ├── internet.jsonl
    │   └── execution.jsonl
    ├── research/
    ├── presentations/
    ├── daily_reports/
    └── workflow_runs/
```

The typed `AppConfig` passed to the variant is cloned so the database, artifact root and gateway audit logs point into that sandbox. The operator's production paths remain unchanged.

## Runtime environment isolation

The following optimization/telemetry environment values are variant-scoped and restored after execution:

- `WORKSPACE_INFERENCE_TELEMETRY`
- `WORKSPACE_RESOURCE_TELEMETRY`
- `WORKSPACE_EVIDENCE_PACKING_MODE`
- `WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS`

These values are process-global, so benchmark variant activation is serialized. Concurrent activation in one process fails closed instead of racing environment state.

## No implicit cleanup

WorkSpace never deletes or silently reuses a non-empty benchmark sandbox. If a variant root already contains data, preparation fails and the operator must choose a new root/label or explicitly archive/remove the old run outside the runtime.

This prevents accidental accumulation such as:

```text
baseline run #1 telemetry
+ baseline run #2 telemetry
+ candidate artifacts
= invalid comparison
```

## Configuration lineage

Storage locations themselves are intentionally excluded from `effective_config_fingerprint()`. Two clean sandboxes running the same model/security/optimization configuration should have the same configuration hash.

Optimization controls remain fingerprinted. For example:

```text
legacy_v1 + 48000 chars  !=  quality_ranked_v1 + 40000 chars
```

Therefore isolation removes measurement contamination without hiding the configuration change being evaluated.

## Fixed-task execution harness

`workspace-benchmark` executes the repository-owned `benchmarks/fixed_task_set_v1.json` against exactly these variants:

```text
baseline-legacy-48k = legacy_v1 + 48000
ranked-48k          = quality_ranked_v1 + 48000
ranked-40k          = quality_ranked_v1 + 40000
ranked-32k          = quality_ranked_v1 + 32000
```

The task set uses repository fixtures as local evidence. Benchmark execution refuses public-search authority, `test_mode_full_access`, allow-all Internet policy, public/public-research confidentiality mode, direct egress, a dirty tracked Git checkout, or a `source_ref` that differs from checkout `HEAD`.

Fixture uploads are admitted through the normal `KnowledgeGateway` security parser, then re-keyed inside the isolated benchmark sandbox to deterministic content-derived upload IDs. This keeps `upload://` evidence identifiers stable across variants without changing the production upload API.

Every variant must execute the same case order and produce the same runtime task IDs and fixture-corpus digest. A mismatch fails closed instead of producing a comparison.

The benchmark invokes the real production `WorkflowRunner`, `RuntimeValidatorBridge`, `TaskContract`, `ValidatorLedger`, Research Agent and Presentation Agent. The date-wide Daily Report model call is replaced by a benchmark no-op because Daily Report is not a task-specific validator and its changing date-wide activity text would contaminate a context-packing measurement.

Run from a clean checkout whose HEAD is the exact candidate/main SHA:

```bash
workspace-benchmark \
  --source-ref <EXACT_40_HEX_SHA> \
  --root /var/lib/workspace-benchmarks/run-001 \
  --repo-root . \
  --task-set benchmarks/fixed_task_set_v1.json \
  --config config/workspace.secure.json
```

The suite writes metadata-only `suite.json` plus one lineage-bound `benchmark.json` per variant. Raw task text remains in the versioned task-set file and is not duplicated into the suite summary.

## Required-validator acceptance

Optimization metrics alone cannot authorize promotion. For every fixed case the candidate must preserve the exact TaskContract-required validator set and may not lose any validator PASS achieved by the baseline.

The suite therefore applies two independent quality layers:

1. `workspace-required-validator-acceptance/v1` — exact required-validator set + per-case PASS non-regression;
2. `workspace-optimization-acceptance/v1` — Verified Task Success, First-Pass Verified Success, Evidence Coverage and token-efficiency acceptance.

Efficiency diagnostics, including suite latency and context/resource proxy deltas, are considered only after both required-validator and verified-quality checks pass. `ranked-40k` and `ranked-32k` remain non-promotable unless their comparison says `promotion_eligible=true`.

## Security properties

Benchmark Isolation grants no additional network, shell, Git, credential, model or file authority. It only redirects already-authorized mutable outputs into a fresh local sandbox.

The isolation and suite manifests contain configuration class, hashes, validator state and packing metadata only. They do not contain raw prompts, source bodies, model responses, credentials or secrets.

Public Research and confidential WorkSpace Core retain their existing zone boundaries. A benchmark sandbox does not merge those zones or weaken egress policy.

## Acceptance sequence

The optimization sequence is:

```text
1. freeze exact source SHA and require clean checkout
2. freeze fixed task set and local fixture corpus
3. create clean baseline sandbox
4. run baseline through real runtime validators
5. capture lineage-bound metrics
6. run each candidate in a separate clean sandbox
7. require identical task scope + corpus
8. require exact validator-set parity and validator PASS non-regression
9. require Verified Task Success / First-Pass / Evidence Coverage non-regression
10. only then evaluate tokens, context proxies, latency and resource diagnostics
11. promote only a candidate with promotion_eligible=true
```

Context precision/recall proxies remain diagnostics. A lower token count cannot compensate for a regression in verified correctness.
