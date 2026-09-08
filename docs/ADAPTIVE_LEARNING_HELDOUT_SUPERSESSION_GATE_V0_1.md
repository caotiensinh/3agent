# Held-out Lane 5 — Phase 4K Supersession Gate Proof v0.1

## Goal

Bind the complete held-out evaluation evidence to the exact Phase 4K skill revision
before production supersession is allowed.

This module is evidence-only. The actual production mutation remains owned by
`CandidateSkillSupersessionManager` and will consume this proof only after the
upstream held-out contracts are canonical on `main`.

## Inputs

The gate builder accepts four exact proofs:

1. existing Phase 4K `RevisionEvaluationPackage` with `result=PASS`;
2. exact current-production subject payload;
3. exact revision-candidate subject payload;
4. exact same-benchmark regression-comparison payload.

The builder recomputes the content SHA-256 of all three held-out payloads instead of
trusting their supplied digest fields.

## Required bindings

- production source candidate ID/SHA == Phase 4K base candidate ID/SHA;
- revision candidate ID/SHA == Phase 4K candidate ID/SHA;
- candidate knowledge, item, base knowledge, domain and Phase 4K evaluation SHA match;
- comparison baseline subject == production subject;
- comparison revision subject == candidate subject;
- strict release PASS is true;
- regression count is zero;
- revision passes every held-out case;
- no regression reason/case may remain.

## Output

`HeldOutSupersessionGateProof` content-addresses:

- Phase 4K base/revision lineage;
- exact production and revision skill SHA-256 values;
- exact held-out subject SHA-256 values;
- benchmark/run/comparison identities;
- strict release counts;
- deterministic `gate_sha256`.

## Authority boundary

The proof grants no direct mutation authority. It cannot stage, promote, activate,
materialize, supersede, rollback, execute tools, access credentials or widen network
scope.

## Mandatory integration

This branch intentionally separates proof construction from the final production
consumer change. The consumer wiring must be reconciled after L1-L4 merge so the
supersession manager imports the canonical contracts rather than duplicating them.
The lane is not counted complete until that wiring and exact-head CI are merged.
