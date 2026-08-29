# D7-06 Efficiency / Cache / Concurrency Observation v1

WorkSpace now has a metadata-only observation harness for representative D7-06 hardware runs:

`workspace-eval-efficiency-observe`

Schema:

`workspace-efficiency-concurrency-observation/v1`

This harness is deliberately **not** a promotion evaluator and cannot emit `evaluator_attested=true` or production promotion evidence.

## What it measures

Given an exact Git SHA, a valid dual-RTX5090 readiness receipt and a preinstalled local Ollama model, the observer records three precursor evidence groups.

### 1. Structured output under concurrent requests

The harness issues a bounded set of concurrent local `generate_json` calls using one fixed JSON Schema and deterministic postconditions. It records only:

- request count;
- successful schema-valid count;
- deterministic semantic-match count;
- maximum concurrent requests observed by the client harness;
- compact failure-type counts;
- min/p50/p95/max request latency;
- aggregate metadata-only Ollama usage counters already exposed by WorkSpace telemetry.

Raw prompts and model responses are not copied into the observation receipt.

### 2. Persistent execution-budget concurrency

The harness creates synthetic internal analysis tasks in temporary isolated SQLite stores and races bounded reservations against the real `TaskExecutionBudgetState` for:

- tool calls;
- model retries;
- model escalations.

A dimension passes only when exactly the immutable contract limit is reserved, all excess reservations fail with the expected exhaustion reason code, no unexpected failure type appears, and the final persisted counter equals the immutable limit.

This is direct evidence that concurrent callers cannot oversubscribe those TaskContract execution dimensions.

### 3. Trust-domain reuse-opportunity isolation

The harness writes synthetic metadata-only inference events with the same stable prefix in two different trust domains and then repeats the first domain.

Expected sequence:

- first domain: no reuse candidate;
- second domain with same prefix: no reuse candidate;
- first domain repeated: reuse candidate.

This verifies WorkSpace's **reuse-opportunity telemetry key** remains trust-domain scoped.

It does **not** claim that Ollama or any future serving backend's native KV/prefix cache is isolated. Backend cache isolation remains a separate representative measurement.

## Claims that are always forbidden

Every valid observation receipt must keep these fields `false`:

- `backend_cache_isolation_measured`
- `backend_cache_hit_claimed`
- `resource_benefit_measured`
- `gpu_active_time_measured`
- `evaluator_attested`
- `promotion_evidence_emitted`

Changing any of them to `true` invalidates the receipt.

Therefore this harness cannot satisfy D7-06 by itself. It supplies auditable precursor observations to an external evaluator.

## Privacy boundary

The published observation artifact contains no:

- raw prompt;
- raw model response;
- internal business data;
- hostname;
- username;
- IP address;
- GPU UUID or serial.

The receipt references the already validated hardware readiness receipt only through its canonical SHA-256 fingerprints and local model identifier.

## Hardware workflow

Manual workflow:

`.github/workflows/evaluate-efficiency-concurrency.yml`

Required inputs:

- `confirm=EVALUATE`
- exact `source_ref`
- preinstalled `model`
- `concurrency` between 2 and 32
- `samples` between 2 and 128 and not lower than concurrency

Runner:

`[self-hosted, Linux, X64, rtx5090]`

The workflow does not download a missing model, install GPU drivers or widen network authority. It installs the exact checked-out WorkSpace source with `pip --no-deps -e .`, creates `environment.json`, runs the observation harness and publishes only:

- `environment.json`
- `observation.json`

The final job fails unless both readiness and the observation complete successfully, while `always()` artifact publication preserves metadata evidence from a failed run when files exist.

## Relationship to D7-06

The repository profile `workspace-efficiency-cache-concurrency-v1` still requires representative external evaluation for:

- fixed-task quality before efficiency;
- structured-output non-regression under concurrency;
- measured resource benefit;
- actual cache/trust-domain isolation;
- execution-budget concurrency;
- no unmeasured cache-hit claims.

This observer directly supplies structured-concurrency and execution-budget observations and verifies WorkSpace's own reuse-opportunity trust-domain boundary. It intentionally leaves actual backend cache isolation, before/after resource benefit and evaluator attestation unresolved.

## Representative hardware closure — 2026-08-30

A representative exact-source run has now been collected for `5472ebbad650d8c466ae0353c3f99408680a770d` on self-hosted Linux x64 hardware with two RTX 5090 GPUs and local `qwen3:30b`.

Evidence boundary:

- GitHub Actions run `33267084880` — PASS;
- artifact `9719019837`;
- artifact ZIP SHA-256 `sha256:9b41d5a0e07b347625869f79d32d77fcf73fa34cfbb0b1d156bdf93bfe389edf`;
- observation SHA-256 `sha256:f6d7208c67dee7631ace778bcdfb1e864b7df127094e4d658355eb9e2a6e10ac`.

Observed results:

- structured output: 8/8 requests succeeded and matched deterministic semantics;
- requested concurrency 4, maximum in-flight observed 4;
- execution-budget concurrency PASS for tool calls, retries and escalations;
- WorkSpace reuse-opportunity trust-domain isolation PASS;
- backend cache isolation remains unmeasured;
- resource benefit remains unmeasured;
- authoritative GPU-active time remains unmeasured;
- evaluator attestation remains false;
- promotion evidence emitted remains false.

The same closure run independently verified the fixed-task benchmark evidence, but `ranked-48k`, `ranked-40k` and `ranked-32k` were all **not promotion eligible**. Therefore the representative result is a **NO-GO for the tested context-budget candidates**, not a positive D7-06 promotion result.

The durable metadata-only decision receipt is `evaluation/representative_hardware_closure_20260830.json`.

D7-06 should therefore be read as **representative observation collected / positive promotion not admissible**. A future positive result still requires all profile checks, measured resource benefit, actual backend cache isolation and external evaluator attestation.
