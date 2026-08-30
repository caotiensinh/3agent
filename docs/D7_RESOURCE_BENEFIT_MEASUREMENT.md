# D7 Resource-Benefit Measurement v1

## Purpose

WorkSpace must not promote concurrency, cache, context, or serving changes merely because a GPU looks busy. D7 resource-benefit measurement compares the same structured workload in a serial baseline and a concurrent candidate on the same exact source, model, prompt template, output schema, and sample count.

This evaluator is manual/benchmark-only. It is not on the production request path and adds no production daemon, database, package, model, cache, or external service.

## Experiment

The evaluator:

1. verifies the exact Git SHA and benchmark-readiness receipt;
2. sends one warm-up structured request so model-load startup is not counted as the serial baseline;
3. runs the fixed request set serially;
4. runs the same request set concurrently;
5. records existing metadata-only Ollama token/duration telemetry;
6. samples aggregate GPU utilization, power draw, and memory use with the already-installed `nvidia-smi`;
7. emits a fingerprinted metadata-only receipt.

The evaluator never records prompts, responses, business data, hostname, username, IP address, GPU UUID/serial, or process lists.

## Measured fields

The receipt can measure:

- serial and concurrent wall duration;
- throughput speedup;
- prompt + output tokens for the same sample count;
- aggregate GPU-utilization-weighted GPU-seconds;
- estimated energy in joules from sampled aggregate power draw;
- peak aggregate VRAM used.

`utilization_weighted_gpu_seconds` is a sampling-based resource proxy:

```text
mean(sum(per-GPU utilization %)) / 100 * wall_seconds
```

It is useful for A/B comparison on the same hardware, but it is **not exact GPU active time**. Therefore the receipt must keep:

```text
gpu_active_time_measured = false
```

This semantic distinction is fail-closed in receipt validation.

## Cache honesty

The evaluator does not have authoritative backend cache-hit telemetry. It therefore must keep:

```text
backend_cache_isolation_measured = false
backend_cache_hit_claimed = false
```

A repeated prefix may be a reuse opportunity; that is not evidence of a backend cache hit.

## Meaning of `resource_benefit_measured`

`resource_benefit_measured=true` means the A/B comparison has complete semantic, token, and aggregate GPU measurements. It does **not** mean the concurrent candidate is better.

An external evaluator still decides whether the measured deltas satisfy the `efficiency_cache_concurrency` promotion checks. The observer cannot set `evaluator_attested` or emit production-promotion evidence.

## Fail-closed conditions

The measurement remains incomplete when any of these are missing or invalid:

- exact source/readiness binding;
- structured-output semantic success in either mode;
- expected telemetry event count;
- prompt/output token counts;
- aggregate `nvidia-smi` sampling.

No missing resource metric is silently converted into a PASS.

## Weak-hardware principle

This measurement exists so WorkSpace can prefer the cheapest verified configuration. Concurrency is accepted only when evidence shows useful throughput/resource benefit without quality or security regression. Higher GPU occupancy alone is not a success metric.
