# D7-05 / D7-06 — External Evaluation Profiles

## Design rule

The repository owns **what must be tested**, not the hidden answers or fabricated benchmark outcomes.

WorkSpace therefore separates:

```text
repository profile
  -> external evaluator/result
  -> deterministic result adapter
  -> metadata-only promotion evidence
  -> D7-08 promotion gate
```

No PASS result, holdout answer, model response or production prompt is committed by this layer.

## D7-05 Edge / Large-context profile

`evaluation/edge_large_context_profile_v1.json` defines versioned test dimensions for:

- protected spans distributed across long context;
- atomic provenance at hard budget boundaries;
- many-source recall pressure;
- adversarial text adjacent to critical spans;
- exact source-ID/citation preservation.

The profile requires external holdout labels. Those labels and their commitment are deliberately absent from the optimizer-facing repository profile. A result cannot become promotion evidence without:

- the exact repository profile SHA;
- exact baseline and candidate Git SHAs;
- current metric-registry fingerprint;
- exact case-set coverage;
- every required case check passing;
- evaluator attestation and compact evaluator evidence reference;
- a SHA-256 commitment to the external holdout labels.

## D7-06 Efficiency / Cache / Concurrency profile

`evaluation/efficiency_cache_concurrency_profile_v1.json` defines versioned scenarios for:

- fixed-task quality before efficiency;
- structured-output reliability under concurrency;
- measured resource benefit;
- cache trust-domain isolation;
- retry/escalation budget behavior under concurrency;
- cache-measurement honesty (no unmeasured backend-hit claim).

This profile does not use hidden holdout labels. Results still require evaluator attestation, exact baseline/candidate lineage, current metric-registry identity, exact case coverage and compact evidence references.

`RESOURCE_BENEFIT_MEASURED=true` is an evaluator claim backed by referenced benchmark artifacts; this module does not invent the measurement. The real dual-RTX5090 fixed-task benchmark remains a separate execution requirement.

## Representative evidence status — 2026-08-30

The real dual-RTX5090 fixed-task benchmark has now been executed and independently verified for exact source `5472ebbad650d8c466ae0353c3f99408680a770d` in GitHub Actions run `33267084880`.

The evidence verifier passed, but all tested context candidates were rejected by the promotion gate:

- `quality_ranked_v1 / 48000` — not promotion eligible;
- `quality_ranked_v1 / 40000` — not promotion eligible;
- `quality_ranked_v1 / 32000` — not promotion eligible.

The same run collected a complete D7-06 precursor hardware observation. Structured-output concurrency, execution-budget concurrency and WorkSpace reuse-opportunity trust-domain isolation passed. However the observation correctly states that backend cache isolation, resource benefit and authoritative GPU-active time were not measured and that evaluator attestation is absent.

Therefore:

- D7-06 is no longer waiting for the first representative hardware observation;
- the tested optimization candidates are a **NO-GO**;
- D7-06 cannot emit positive promotion evidence from this run;
- a future positive D7-06 result still requires a separately attested exact baseline/candidate result satisfying every profile check;
- D7-05 remains dependent on external holdout labels and evaluator attestation and must not be fabricated inside the repository.

The durable metadata-only closure receipt is `evaluation/representative_hardware_closure_20260830.json`.

## `workspace-eval-profile`

Without `--result`, the command emits an optimizer-safe profile view containing only test dimensions and required checks.

With an external result, it validates the full profile/result contract and emits a `workspace-promotion-evidence/v1` file only when every required check passes. Unknown result fields fail closed, so raw prompts, answers or other content cannot be smuggled into the adapter payload.

## Promotion boundary

The generated evidence uses:

- the profile ID as `corpus_id`;
- canonical profile SHA as `corpus_sha256`;
- current `workspace-d3-core-metrics-v1` fingerprint;
- exact baseline/candidate refs;
- evaluator/artifact references only.

A representative observation or a verified negative benchmark is sufficient to record a **NO-GO** decision, because that narrows deployment choices. It is not sufficient to create positive promotion evidence.

D7-05/D7-06 profile infrastructure does not mean all positive promotion evidence exists. Production promotion remains blocked until a real external result satisfies every required check and is admitted by D7-08.
