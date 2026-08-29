# D7-05 External Evaluator Handoff

## Purpose

`workspace-eval-handoff` issues a fail-closed, metadata-only D7-05 handoff before any external edge/large-context evaluation is admitted to the existing profile-result adapter.

The handoff is a contract, not an evaluation result. It never creates external evaluator attestation, holdout labels, a holdout-label commitment, a benchmark PASS, or promotion evidence.

## Exact profile

The handoff is intentionally limited to:

- profile ID: `workspace-edge-large-context-v1`
- corpus class: `edge_large_context`
- current canonical profile SHA-256
- current `workspace-d3-core-metrics-v1` registry ID and canonical SHA-256
- exact baseline Git SHA
- exact candidate Git SHA
- the exact profile case set and every required check

A baseline and candidate must be distinct exact 40-hex Git SHAs.

## Create the handoff

```bash
workspace-eval-handoff create \
  --profile evaluation/edge_large_context_profile_v1.json \
  --baseline-ref <EXACT_BASELINE_GIT_SHA> \
  --candidate-ref <EXACT_CANDIDATE_GIT_SHA> \
  --output /secure/operator/d705-handoff.json
```

The generated file uses schema `workspace-external-evaluator-handoff/v1`.

It contains only repository-controlled metadata and requirement descriptors. In particular, it does **not** contain an `evaluator_attested` claim or `label_commitment_sha256` value.

## External evaluator result

A real external evaluator must independently return a `workspace-evaluation-profile-result/v1` result that includes:

- the same exact profile ID and profile SHA-256;
- the same current metric registry ID and SHA-256;
- the exact handoff baseline and candidate Git SHAs;
- `security_passed=true`;
- an external evaluator identity/reference;
- `evaluator_attested=true`, asserted by that external evaluator;
- a `sha256:<64-hex>` commitment to the external holdout labels;
- the exact profile case set;
- every required check for every case;
- compact evaluator/artifact evidence references only.

The external result must not contain raw prompts, raw expected answers, raw model responses, embedded holdout labels, confidential/internal business content, credentials, arbitrary evidence blobs, or unknown fields. The deterministic result parser rejects unknown fields and non-compact evidence references.

## Validate a returned result against the exact handoff

```bash
workspace-eval-handoff validate-result \
  --profile evaluation/edge_large_context_profile_v1.json \
  --handoff /secure/operator/d705-handoff.json \
  --result /secure/operator/external-result.json
```

A successful validation only means the returned metadata is admissible to the existing deterministic profile-result adapter for the exact handoff. It is not a promotion PASS and this command does not emit `PromotionEvidence`.

The existing adapter remains authoritative for conversion into metadata-only promotion evidence:

```text
external evaluator
  -> external result
  -> exact D7-05 handoff binding validation
  -> existing workspace-eval-profile deterministic result adapter
  -> metadata-only PromotionEvidence
  -> D7-08 promotion gate
```

## Fail-closed boundary

The implementation rejects:

- missing or false external evaluator attestation;
- missing edge/large-context holdout-label commitment;
- wrong profile fingerprint;
- wrong metric-registry identity/fingerprint;
- baseline equal to candidate;
- external result lineage that differs from the handoff;
- missing or extra cases;
- any failed required check;
- unknown result/case/handoff fields;
- raw-content fields or non-compact evidence references.

No WorkSpace-generated handoff can satisfy the external evidence requirement by itself.

Until a real external evaluator supplies admissible holdout evidence:

`EXTERNAL_EVIDENCE_REQUIRED`
