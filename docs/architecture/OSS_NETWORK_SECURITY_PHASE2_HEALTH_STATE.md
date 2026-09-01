# Phase 2 health-state and hysteresis evidence

Implementation scope: `feature/security-monitoring-phase1`, Phase 2.

## Purpose

Phase 2 adds deterministic interpreted health state on top of existing durable `ObservationRecord` evidence. It does not change collector authority, network scope, approved inventory rules, packet-capture policy, remediation rights, or model authority.

## State semantics

The fixed interpreted states are:

- `unknown`
- `healthy`
- `degraded`
- `unreachable`
- `maintenance`
- `data_gap`

An observation remains raw evidence. A health state is a separate deterministic interpretation and must retain the evidence references used for its evaluation.

## Hysteresis policy

Thresholds are supplied by `HealthPolicyConfig`; they are not model output. The policy bounds failure, unreachable, recovery, and data-gap thresholds.

A single failed sample does not promote a healthy asset to an alert state. Consecutive evidence is required. `unreachable` requires the hard-failure threshold. Recovery also requires consecutive successful evidence.

State escalation is preserved across evaluations:

```text
UNKNOWN -> HEALTHY
HEALTHY -> DEGRADED
DEGRADED -> UNREACHABLE
UNREACHABLE -> HEALTHY
```

`DATA_GAP` is distinct from failure. Fresh evidence must satisfy the configured thresholds before the asset is reclassified. `MAINTENANCE` requires explicit maintenance evidence.

## Determinism and evidence lineage

Evaluation performs no I/O. Inputs are validated, bounded, sorted deterministically, and rejected when they contain a mismatched asset or future timestamp.

Every actual transition records:

- asset identifier;
- previous and current state;
- transition timestamp;
- evaluation and observation evidence references;
- reason code;
- policy fingerprint.

Replay fixtures execute the same bounded observation sequence twice and require byte-identical serialized state and transition receipts.

## Public integration

The stable package exports include the health states, policy contract, state/transition records, evaluation result and deterministic evaluator. Existing observation, storage, correlation, finding, incident and policy contracts remain unchanged.

## Acceptance evidence

Phase 2 is accepted only when targeted health contract, hysteresis and replay tests pass together with the repository's full unit-test matrix and enterprise verification gates on the exact validation tree before promotion.
