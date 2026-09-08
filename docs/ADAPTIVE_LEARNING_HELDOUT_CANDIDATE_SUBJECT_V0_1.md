# Held-out Lane 2 — Exact Revision Candidate Evaluation Subject v0.1

## Goal

Define the exact staged skill revision identity that may enter held-out evaluation.
The subject is not caller-constructed from loose metadata: it must be bound to an
already-PASS Phase 4K `RevisionEvaluationPackage` and the exact immutable
`KnowledgeCandidate` referenced by that package.

## Canonical reuse

- `KnowledgeCandidate` remains the revision object.
- `RevisionEvaluationPackage` remains the Phase 4K safety/lineage package.
- production rendering reuses the same candidate-skill helpers already used by
  `CandidateSkillSupersessionManager`.

## Required bindings

The candidate must match the package on:

- candidate ID and candidate SHA-256;
- item ID;
- base knowledge SHA-256;
- domain;
- `kind=skill` and `action=patch`;
- Phase 4K result `PASS`.

The output binds the exact rendered skill SHA-256 and size plus the exact Phase 4K
evaluation SHA-256 into a deterministic `subject_sha256`.

## Authority boundary

Evaluation identity only. This module cannot stage, promote, activate, materialize,
rollback, execute tools, access credentials or widen network authority.

This lane does not resolve the current production baseline and does not execute or
score held-out cases.
