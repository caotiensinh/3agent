# WorkSpace Benchmark Isolation v1

## Purpose

Benchmark variants must not share mutable runtime state. A 48k baseline and a 40k/32k context candidate are not comparable if they append into the same task database, artifact tree, inference telemetry, resource telemetry or gateway audit files.

WorkSpace therefore treats isolation as a prerequisite to optimization measurement rather than as an optional cleanup step.

## Isolation boundary

Each benchmark variant receives its own sandbox:

```text
<benchmark-root>/<variant>/
├── isolation.json
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

## Security properties

Benchmark Isolation grants no additional network, shell, Git, credential, model or file authority. It only redirects already-authorized mutable outputs into a fresh local sandbox.

The isolation manifest contains configuration class/packing metadata only. It does not contain raw prompts, source bodies, model responses, credentials or secrets.

Public Research and confidential WorkSpace Core retain their existing zone boundaries. A benchmark sandbox does not merge those zones or weaken egress policy.

## Acceptance sequence

The intended optimization sequence is:

```text
1. freeze exact source SHA
2. freeze fixed task set
3. create clean baseline sandbox
4. run baseline
5. capture lineage-bound metrics
6. create clean candidate sandbox
7. run candidate on the same task set
8. capture lineage-bound metrics
9. run Optimization Acceptance Gate
10. promote only if verified quality/evidence do not regress and the cost target is met
```

Context precision/recall proxies remain diagnostics. A lower token count cannot compensate for a regression in Verified Task Success, First-Pass Verified Success or required Evidence Coverage.
