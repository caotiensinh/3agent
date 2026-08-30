# D7-06 External Efficiency Evaluator Handoff

## Purpose

`workspace-eval-efficiency-handoff` binds the exact evidence an independent evaluator must inspect before an `efficiency_cache_concurrency` result is admissible to the existing profile-result adapter.

It is a contract/evidence-binding step. It is **not** an evaluator, never sets `evaluator_attested=true`, and never emits `PromotionEvidence`.

No runtime service, database, cache layer, framework, model, or network authority is added.

## Why this layer exists

D7-06 now has three evidence families:

1. fixed-task benchmark manifests;
2. structured-output / execution-budget / WorkSpace reuse-opportunity observations;
3. serial-versus-concurrent resource-benefit observations.

A schema-valid external result is insufficient if it is unclear which exact measurements were evaluated. The handoff hashes and binds all three families to exact baseline and candidate Git SHAs.

## Required inputs

Creation requires:

- current `workspace-efficiency-cache-concurrency-v1` profile;
- exact and distinct baseline/candidate Git SHAs;
- baseline/candidate `workspace-benchmark-snapshot/v1` manifests;
- baseline/candidate `workspace-efficiency-concurrency-observation/v1` receipts;
- baseline/candidate `workspace-resource-benefit-observation/v1` receipts.

Raw unified metrics are rejected because they do not carry exact source/configuration lineage.

## Deterministic prechecks

Before a handoff is emitted WorkSpace verifies:

- both benchmark manifests bind the requested exact SHAs;
- both use the current metric registry;
- both use the exact same fixed task scope;
- verified-task success does not regress;
- first-pass verified success does not regress;
- verified task count does not regress;
- evidence coverage does not regress;
- both concurrency receipts validate as complete;
- structured output, execution-budget concurrency, and WorkSpace reuse-opportunity isolation can be re-derived from receipt sections;
- both resource receipts validate as complete;
- all four representative measurements use the same model;
- baseline/candidate resource experiments use identical sample/concurrency settings;
- concurrency observations match those settings.

Resource deltas are recorded for external evaluation; the handoff does not convert them into a positive optimization verdict.

## Cache boundary

Local WorkSpace evidence proves only the WorkSpace reuse-opportunity trust-domain boundary. It does not prove a serving backend's native KV/prefix-cache isolation.

Therefore the handoff fixes:

```text
backend_cache_isolation_measured = false
backend_cache_hit_claimed = false
```

For `cache-trust-domain-isolation`, the external result must include independent external evidence in addition to the handoff reference. Local reuse receipts alone cannot satisfy `CACHE_TRUST_ISOLATION_PASS`.

## Metadata-only schema

Schema:

```text
workspace-efficiency-evaluator-handoff/v1
```

The handoff contains only profile/metric fingerprints, exact Git SHAs, evidence hashes, benchmark-lineage hashes, deterministic precheck summaries, model/sample/concurrency identity, numeric resource-comparison metadata, exact profile cases/checks, evaluator requirements, and a canonical handoff SHA-256.

It contains no prompts, model responses, benchmark task bodies, business content, hostname, username, IP address, GPU UUID/serial, credentials, cache contents, or holdout labels.

## Create

```bash
workspace-eval-efficiency-handoff create \
  --profile evaluation/efficiency_cache_concurrency_profile_v1.json \
  --baseline-ref <EXACT_BASELINE_SHA> \
  --candidate-ref <EXACT_CANDIDATE_SHA> \
  --baseline-benchmark /secure/baseline-benchmark.json \
  --candidate-benchmark /secure/candidate-benchmark.json \
  --baseline-observation /secure/baseline-observation.json \
  --candidate-observation /secure/candidate-observation.json \
  --baseline-resource /secure/baseline-resource-benefit.json \
  --candidate-resource /secure/candidate-resource-benefit.json \
  --output /secure/d706-handoff.json
```

## External evaluator result

The independent evaluator returns existing schema `workspace-evaluation-profile-result/v1` and must:

- match exact profile/hash/metric registry;
- match exact baseline/candidate refs;
- set `security_passed=true`;
- set `evaluator_attested=true`;
- keep `label_commitment_sha256=null`;
- contain exactly the profile case set;
- contain exactly each case's required checks, all `true`;
- reference the handoff SHA in every case;
- reference the bound local evidence hashes required by each case;
- include independent external backend-cache evidence for `cache-trust-domain-isolation`.

Unknown/raw-content fields remain rejected by the existing result schema.

## Validate returned result

```bash
workspace-eval-efficiency-handoff validate-result \
  --profile evaluation/efficiency_cache_concurrency_profile_v1.json \
  --handoff /secure/d706-handoff.json \
  --result /secure/external-result.json
```

Success means only `accepted_for_profile_adapter=true`. It is not production promotion PASS.

The chain remains:

```text
external evaluator result
  -> D7-06 exact handoff validation
  -> workspace-eval-profile
  -> metadata-only PromotionEvidence
  -> D7-08 production promotion gate
```

## Security invariant

Neither the benchmark runner nor this handoff command can manufacture external attestation or backend-cache evidence. Missing evidence remains missing; no proxy metric is silently upgraded into a stronger claim.
