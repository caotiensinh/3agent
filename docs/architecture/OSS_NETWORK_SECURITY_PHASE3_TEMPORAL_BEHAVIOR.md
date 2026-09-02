# Phase 3 temporal behavior engine evidence

Implementation scope: `feature/security-monitoring-phase1`, Phase 3.

## Purpose

Phase 3 extends the existing WorkSpace behavior-analysis path with bounded temporal buckets and deterministic scenario evaluation. It reuses normalized `CorrelationEvent` evidence and the existing `BehaviorStoreReader`; it does not create a second ingestion pipeline.

## Separation of responsibilities

The runtime boundary is intentionally staged:

```text
existing parser / normalization
        |
        v
CorrelationEvent + entity context
        |
        v
bounded temporal bucketization
        |
        v
deterministic scenario evaluation
        |
        v
TemporalScenarioAssessment (advisory only)
```

A temporal assessment is not a `FindingRecord` and is not a response action. Finding generation, incident correlation and any exceptional response capability remain separate existing stages with their own policy boundaries.

## Deterministic temporal semantics

Temporal windows are bounded and canonicalized to UTC. Bucket order derives only from event timestamps and stable event IDs. Input order, filesystem order and worker scheduling cannot change bucket serialization or fingerprints.

Events outside the requested temporal window fail closed instead of being silently accepted. Exact duplicate events are deduplicated; conflicting duplicate event IDs are rejected.

## Scenario semantics

A scenario specifies only deterministic matching data:

- stable scenario ID;
- one normalized correlation stage;
- one typed entity scope role;
- minimum events per bucket;
- minimum matching buckets;
- consecutive or non-consecutive bucket semantics;
- severity metadata.

Scenarios cannot grant network, packet-capture, scan, shell, firewall or remediation authority. Scenario and assessment authority is fixed to `advisory`.

Matching is performed per typed entity scope. Evidence from different assets/users/IPs/services is never combined merely because timestamps are close.

## Evidence lineage and bounds

Every emitted assessment carries the exact event IDs, durable evidence references, selected bucket indices, scope entity reference, first/last observation time and scenario fingerprint. Missing durable evidence on a matched signal fails closed.

Event, bucket, assessment and per-assessment evidence counts are bounded. Exceeding a bound raises a deterministic contract error instead of silently truncating a security signal.

## Existing behavior-store integration

`BehaviorStoreReader` exposes a read-only temporal path that reads only the current `[start, end)` events needed by temporal evaluation. It does not load historical DNS features when they are unnecessary. This follows the WorkSpace constraint-first rule: avoid work before increasing concurrency or compute.

Existing behavior-baseline analysis remains unchanged and can continue independently.

## Acceptance evidence

Phase 3 requires:

- deterministic bucket tests including shuffled replay and out-of-window failures;
- positive and negative temporal scenario fixtures;
- cross-scope isolation tests;
- missing-evidence and authority fail-closed tests;
- behavior-store integration equivalence tests;
- full repository unit-test matrix and EV-01..EV-10 on the exact validation tree before atomic promotion.
