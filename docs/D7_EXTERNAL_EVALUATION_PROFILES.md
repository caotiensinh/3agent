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

D7-05/D7-06 profile infrastructure does not mean representative evidence has already been collected. Production promotion remains blocked until real external results are materialized and admitted by D7-08.
