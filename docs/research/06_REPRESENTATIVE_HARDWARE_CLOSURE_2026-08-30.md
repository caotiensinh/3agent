# Representative Hardware Closure — 2026-08-30

## Exact evidence boundary

This closure records representative local hardware evidence for WorkSpace source:

`5472ebbad650d8c466ae0353c3f99408680a770d`

Execution evidence:

- GitHub Actions run: `33267084880`
- evidence artifact: `9719019837`
- artifact ZIP SHA-256: `sha256:9b41d5a0e07b347625869f79d32d77fcf73fa34cfbb0b1d156bdf93bfe389edf`
- runner class: self-hosted Linux x64 with two RTX 5090 GPUs
- local model: `qwen3:30b`
- fixed task set: `workspace-reasoning-core-v1`

The machine-readable metadata-only receipt is:

`evaluation/representative_hardware_closure_20260830.json`

## Fixed-task benchmark verdict

The independent benchmark evidence verifier passed. This means the readiness, artifact set, task-set lineage, fixture corpus, metric registry, variant isolation, required-validator recomputation, optimization recomputation and privacy checks were internally consistent and recomputable.

It does **not** mean an optimization candidate passed promotion.

Exact promotion eligibility was:

| Variant | Promotion eligible |
| --- | --- |
| `quality_ranked_v1 / 48000` | **NO** |
| `quality_ranked_v1 / 40000` | **NO** |
| `quality_ranked_v1 / 32000` | **NO** |

Therefore WorkSpace must not promote ranked 48k, 40k or 32k from this evidence set.

The 40k candidate materially regressed verified-task and first-pass verified success and also worsened tokens per verified task. The 32k candidate preserved aggregate quality metrics in the optimization calculation but lost a required schema-validator PASS for a fixed case, so the required-validator acceptance gate correctly blocked promotion.

## D7-06 hardware observation

The same exact-source closure run also completed the metadata-only D7-06 precursor observer:

- structured output: 8 attempted / 8 succeeded / 8 semantic matches;
- requested concurrency: 4;
- maximum in-flight observed: 4;
- execution-budget concurrency: PASS;
- WorkSpace reuse-opportunity trust-domain isolation: PASS;
- backend cache-hit measurement: **not measured**;
- backend cache isolation: **not measured**;
- before/after resource benefit: **not measured**;
- authoritative GPU-active time: **not measured**;
- external evaluator attestation: **not present**;
- promotion evidence emitted: **false**.

Consequently the observation is valid representative precursor evidence, but it cannot satisfy the complete `workspace-efficiency-cache-concurrency-v1` profile or mint D7-08 promotion evidence.

## Closure decisions

1. **Context-budget promotion: NO-GO.** Keep the current production context behavior unchanged.
2. **D5-02 near-duplicate/diversity changes: remain benchmark-gated.** The current evidence does not authorize additional recall-changing behavior.
3. **D5-05 progressive expansion: remain disabled.** No production enablement is authorized.
4. **D7-06: representative hardware observation collected, promotion not admissible.** External evaluation plus measured resource benefit and actual backend cache isolation remain required for a future positive result.
5. **D7-05: external holdout evidence still required.** Repository code must not manufacture hidden labels, expected answers or evaluator attestation.
6. **D3-09 GPU-seconds: not measured.** Do not infer GPU-active time from task wall time, request duration or ordinary utilization snapshots.
7. **D8/D9/D10/D11/D12 production integration remains blocked by their existing prerequisite gates.** A negative optimization result is a completed decision, not permission to bypass the gate.

## Security and privacy

This closure stores hashes, IDs, booleans, aggregate counts and decisions only. It does not persist raw prompts, model outputs, business evidence, credentials, runner hostname, GPU UUIDs or serial numbers.

The evidence result is intentionally asymmetric: WorkSpace may deterministically record a **NO-GO** from verified negative evidence, but it may not convert precursor observations into a positive promotion claim without the stronger evidence required by the evaluation profile and promotion policy.
