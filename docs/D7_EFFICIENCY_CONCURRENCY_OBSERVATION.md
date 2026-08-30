# D7-06 Efficiency / Cache / Concurrency Observation

WorkSpace has two metadata-only representative-hardware measurement tools for D7-06:

```text
workspace-eval-efficiency-observe
python3 -m three_agent.resource_benefit_observer
```

The first measures structured concurrency, persistent execution-budget concurrency, and WorkSpace reuse-opportunity trust-domain isolation. The second measures the same structured workload serially versus concurrently with token telemetry and aggregate `nvidia-smi` resource sampling.

Neither tool is a promotion evaluator. Neither can set `evaluator_attested=true` or emit production `PromotionEvidence`.

## Current hardware workflow

Manual workflow: `.github/workflows/evaluate-efficiency-concurrency.yml`.

Inputs:

- `confirm=EVALUATE`;
- exact `source_ref`;
- preinstalled local model;
- concurrency 2..32;
- samples 2..128 and not lower than concurrency.

Runner:

```text
[self-hosted, Linux, X64, rtx5090]
```

The workflow checks out and verifies the exact SHA, installs that WorkSpace source with `pip --no-deps -e .`, captures readiness, runs both D7-06 observers, and publishes only metadata evidence.

Current artifact set:

```text
environment.json
observation.json
resource-benefit.json
```

The final job fails unless readiness, concurrency observation, and resource-benefit observation all complete successfully. The workflow does not download missing models, install GPU drivers, create a cache service, or widen runtime network authority.

## Concurrency observation

Schema: `workspace-efficiency-concurrency-observation/v1`.

### Structured output

A bounded set of local `generate_json` requests uses one fixed JSON Schema and deterministic semantic postconditions. The receipt records attempted/successful counts, semantic-match count, maximum in-flight requests, compact failure types, latency statistics, and aggregate metadata-only Ollama usage counters. Raw prompts and responses are not persisted.

### Execution budgets

Synthetic internal tasks race concurrent reservations against the real persistent `TaskExecutionBudgetState` for tool calls, model retries, and model escalations. A dimension passes only when the immutable limit is reserved exactly, excess reservations fail with the expected reason code, and the final persisted counter equals the contract limit.

### WorkSpace reuse-opportunity isolation

The observer repeats one stable prefix across two trust domains:

```text
domain A first     -> no reuse candidate
domain B same text -> no reuse candidate
domain A repeated  -> reuse candidate
```

This verifies only WorkSpace's reuse-opportunity key isolation. It does **not** prove a serving backend's native KV/prefix-cache isolation and does not claim an actual cache hit.

## Resource-benefit observation

Schema: `workspace-resource-benefit-observation/v1`.

After one warm-up request it runs the same structured sample set serially and concurrently on the same exact source, model, prompt template, and output schema.

It can measure wall duration, throughput speedup, prompt + output tokens, aggregate utilization-weighted GPU seconds, estimated energy from sampled aggregate power draw, and peak aggregate VRAM.

`utilization_weighted_gpu_seconds` is a sampling proxy for A/B comparison. It is **not** exact GPU active time. Valid receipts therefore keep:

```text
gpu_active_time_measured = false
backend_cache_isolation_measured = false
backend_cache_hit_claimed = false
evaluator_attested = false
promotion_evidence_emitted = false
```

`resource_benefit_measured=true` means the comparison is complete, not that the candidate is automatically better.

## Privacy boundary

Representative artifacts contain no raw prompts, model responses, internal business data, hostname, username, IP address, GPU UUID/serial, GPU process lists, or credentials.

## External evaluation

The repository profile remains `workspace-efficiency-cache-concurrency-v1`. A positive production candidate still requires fixed-task quality non-regression, structured-output non-regression, measured resource benefit, execution-budget concurrency, cache-claim honesty, actual backend cache/trust-domain isolation, and external evaluator attestation.

The local measurement tools cannot satisfy backend-cache or external-attestation requirements by themselves.

The exact evidence-binding step is:

```text
workspace-eval-efficiency-handoff
```

See `docs/D7_EFFICIENCY_EVALUATOR_HANDOFF.md`.

## Historical representative closure — 2026-08-30

The historical representative run for source `5472ebbad650d8c466ae0353c3f99408680a770d` was collected **before** the resource-benefit companion measurement was added.

Historical evidence:

- GitHub Actions run `33267084880` — PASS;
- artifact `9719019837`;
- artifact ZIP SHA-256 `sha256:9b41d5a0e07b347625869f79d32d77fcf73fa34cfbb0b1d156bdf93bfe389edf`;
- concurrency observation SHA-256 `sha256:f6d7208c67dee7631ace778bcdfb1e864b7df127094e4d658355eb9e2a6e10ac`.

That run observed structured output 8/8 success, requested concurrency 4 with max in-flight 4, execution-budget concurrency PASS, and WorkSpace reuse-opportunity trust-domain isolation PASS.

That historical run did **not** measure backend cache isolation, backend cache hits, resource benefit, exact GPU active time, or external evaluator attestation, and it emitted no promotion evidence.

The fixed-task candidates tested in that closure (`ranked-48k`, `ranked-40k`, `ranked-32k`) were all not promotion-eligible, so the durable decision remains **NO-GO** for those exact historical candidates.

`evaluation/representative_hardware_closure_20260830.json` remains the authoritative historical receipt. New tooling does not retroactively change its claims.
