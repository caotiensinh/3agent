# Adaptive Learning Quarantine Recommendation V0.1

## Purpose

This document defines the M-07 quarantine recommendation boundary for adaptive learned skills.

The implementation closes only the remaining recommendation gap. It does **not** introduce a quarantine store, automatically disable a production skill, archive learning state, alter the production registry, or grant any new runtime authority.

## Canonical input

The projector consumes only a validated `AdaptiveLearningMaintenanceReceipt` emitted by the canonical bounded Phase 4H -> Phase 4I maintenance advisor.

A skill becomes eligible for a quarantine recommendation only when the existing maintenance recommendation type is:

`domain_revision_or_retirement_review`

That type is already produced only from canonical `DOMAIN_REVIEW_RECOMMENDED` effectiveness evidence for the `network` or `security` domains.

No new effectiveness threshold is introduced by M-07.

## Recommendation semantics

The emitted recommendation carries:

- exact source maintenance receipt SHA-256;
- exact Phase 4I proposal ID;
- exact adaptive-learning `item_id`;
- exact active `knowledge_sha256`;
- exact candidate SHA-256;
- active approval level;
- domain;
- source advisory signal and curation action;
- proposed disposition `quarantined`;
- mandatory human review;
- mandatory domain review;
- deterministic reason codes;
- deterministic recommendation ID.

`recommended_disposition = quarantined` means only:

> An operator/domain reviewer should consider isolating this exact active version while deciding revision, retirement, rollback, or continued use.

It does not mean that the skill has been mutated or disabled.

## Authenticated state binding

Before emitting any recommendation the projector:

1. validates the maintenance receipt;
2. verifies the current authenticated learning checkpoint;
3. requires exact checkpoint sequence, checkpoint SHA-256, and state SHA-256 equality with the source maintenance receipt;
4. resolves the current active learning item;
5. requires exact knowledge SHA, candidate SHA, active level, and domain equality;
6. verifies the checkpoint again after projection;
7. fails if state changed during the read-only operation.

This prevents stale or independently fabricated recommendation metadata from targeting a different current skill version.

## Fail-closed policy

Projection fails when:

- source maintenance receipt is not `RECOMMENDATIONS_READY`;
- checkpoint/state binding is stale;
- a quarantine-eligible target is no longer active;
- exact active identity changed;
- the recommendation is not a domain revision/retirement review;
- human/domain review requirements are absent;
- the domain is not `network` or `security`;
- identifiers, hashes, reason codes, sorting, or recommendation identities are malformed;
- authenticated learning state changes during projection.

## Authority boundary

Authority string:

`recommendation_only_no_learning_or_runtime_mutation`

The projector exposes no API for:

- archive;
- disable;
- rollback;
- promotion;
- staging;
- materialization;
- production supersession;
- tool execution;
- model invocation;
- filesystem/network/credential access.

Existing operator and production lifecycle boundaries remain the only paths that may mutate state.

## Privacy boundary

The recommendation is metadata-only. It contains no:

- learned procedure body;
- task request text;
- query text;
- model output;
- evidence bytes;
- credentials/secrets;
- tool output;
- filesystem paths.

## M-07 acceptance

M-07 is complete when tests prove:

1. canonical network/security domain-review evidence projects a `quarantined` recommendation;
2. ordinary analyst revision/retirement review does not project quarantine;
3. stale checkpoint receipts fail closed;
4. forged target identity fails closed even if receipt metadata is internally well formed;
5. output is deterministic and metadata-only;
6. the projector has no mutation surface;
7. disabled/not-ready maintenance receipts cannot act as quarantine sources.

Revision/retirement recommendations remain owned by the existing Phase 4H/4I maintenance pipeline. M-07 adds only the quarantine recommendation projection required by the self-evolution checklist.
