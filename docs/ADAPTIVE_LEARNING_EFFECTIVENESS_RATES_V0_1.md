# Adaptive Learning Effectiveness Rates V0.1

Status: implementation contract for WorkSpace Skill lifecycle M-03.

## Goal

Expose deterministic normalized success, failure, and validator-pass rates for exact reused knowledge versions without changing the existing Phase 4H effectiveness snapshot schema, snapshot hash, advisory thresholds, or authority model.

This is an observational projection only. It does not claim causality and grants no promotion, curation, revision, archive, rollback, model, tool, network, credential, or execution authority.

## Compatibility boundary

The canonical `workspace-learning-effectiveness/v1` payload remains byte-compatible:

- existing `KnowledgeEffectivenessSignal.to_payload()` fields are unchanged;
- existing `LearningEffectivenessSnapshot.to_payload()` fields are unchanged;
- new validator counters are internal signal fields and are not inserted into the v1 payload;
- normalized rates use a separate schema: `workspace-learning-effectiveness-rates/v1`.

This keeps existing Phase 4H/4I snapshot hashes and consumers stable while exposing an explicit new projection API.

## Why integer basis points

Rates are represented as:

```json
{
  "numerator": 1,
  "denominator": 3,
  "basis_points": 3333
}
```

No binary floating point is stored or hashed.

- `10000` basis points = 100.00%
- rounding is deterministic to the nearest basis point
- denominator `0` produces `basis_points: null`, not a misleading 0%
- numerator and denominator are retained so downstream consumers never lose the exact ratio

## Outcome denominators

### Verified-success rate

```text
verified_success_after_reuse
---------------------------------------------
verified_success + failed + done_unverified
```

### Failure rate

```text
failed_after_reuse
---------------------------------------------
verified_success + failed + done_unverified
```

`WAITING_HUMAN` and `PENDING` are intentionally excluded from these final-outcome denominators. They remain visible in the existing raw counters but are not converted into failures before the task reaches a final outcome.

`DONE_UNVERIFIED` remains in the denominator but is neither success nor failure. Therefore success rate + failure rate is not required to equal 100%.

## Validator-pass denominator

The validator-pass rate uses only validator slots that have resolved to `passed` or `failed` in the authoritative `ValidatorLedger`:

```text
resolved passed validator slots
--------------------------------
passed slots + failed slots
```

Missing validators are excluded from the denominator until they resolve. This prevents pending work from being silently counted as validator failure.

The analyzer obtains these counts from canonical `TaskVerificationState.passed_validators` and `failed_validators`; no new validator ledger or telemetry source is introduced.

## Confounded versus isolated projections

Every exact knowledge signal exposes both:

- overall rates across all observed tasks where that knowledge version was available;
- isolated rates across tasks where no other knowledge version was simultaneously available.

A confounded task contributes to overall rates but not isolated rates. If no isolated denominator exists, the isolated basis-point rate is `null`.

This preserves the existing Phase 4H non-causal interpretation and makes confounding explicit rather than hiding it inside one percentage.

## Projection fields

`KnowledgeEffectivenessRateProjection` binds:

- `item_id`
- exact `knowledge_sha256`
- domain
- finalized task observation count
- isolated finalized task observation count
- resolved validator observation count
- isolated resolved validator observation count
- verified-success rate
- failure rate
- validator-pass rate
- isolated verified-success rate
- isolated failure rate
- isolated validator-pass rate
- interpretation
- deterministic `projection_sha256`

## Non-goals

V0.1 does not:

- change Phase 4H advisory thresholds;
- reinterpret `WAITING_HUMAN` or `PENDING` as failure;
- treat missing validators as failed validators;
- change `workspace-learning-effectiveness/v1` snapshot bytes;
- feed rate percentages directly into promotion authority;
- add persistence, background jobs, or a second effectiveness analyzer;
- infer causal benefit from observational reuse.

Future maintenance/UI consumers may use the projection as reviewed metadata, but any policy transition remains behind the existing deterministic curation and authenticated promotion boundaries.
