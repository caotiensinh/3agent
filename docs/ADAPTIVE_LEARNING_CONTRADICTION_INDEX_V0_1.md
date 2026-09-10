# Adaptive Learning Contradiction Index v0.1

## Goal

Close the persistent contradiction-tracking portion of Skill lifecycle M-05
without creating a second learning store, a second promotion path, or any
automatic production mutation authority.

PR #401 already added exact `last_verified_at` / `last_isolated_verified_at`.
This phase adds the missing bounded persistent contradiction index over the
canonical `AdaptiveLearningStore`.

## Canonical reuse

This design reuses:

- `ContradictionRecord` from `adaptive_learning_contract.py`;
- `AdaptiveLearningStore` and its immutable candidate/version rows;
- the canonical learning ledger integrity verification;
- `LearningCheckpointAuthority` for authenticated canonical store state;
- exact `candidate_id + candidate_sha256 + item_id + knowledge_sha256`
  identity.

No new learning DB, production registry, telemetry DB, or approval authority is
introduced.

## Storage boundary

`learning_contradiction_events` is created in the same SQLite database used by
`AdaptiveLearningStore`.

The table is append-only under normal operation:

- `UPDATE` is rejected by a SQLite trigger;
- `DELETE` is rejected by a SQLite trigger;
- every row includes `previous_entry_sha256`;
- every row includes a deterministic `entry_sha256`;
- sequence gaps, hash-chain drift, candidate-binding drift, malformed
  lifecycle transitions, and row tampering fail closed.

The index is tamper-evident metadata. It is not a replacement for the
authenticated learning checkpoint. Every read/write first requires the
canonical store checkpoint to verify successfully.

## Metadata-only persistence

The contradiction index MUST NOT persist:

- contradiction summary text;
- evidence reference IDs;
- evidence bytes;
- evidence paths;
- task request/prompt content;
- model output;
- credentials/secrets;
- skill body/content.

Instead it persists bounded commitments:

- `evidence_count`;
- `evidence_set_sha256`;
- `summary_sha256`;
- `record_sha256`;
- exact candidate/knowledge SHA-256;
- lifecycle status and canonical timestamps;
- controlled actor/reason identifiers;
- source authenticated checkpoint SHA-256.

The full `ContradictionRecord` exists only as the validated input to
`record(...)`; persistence and projections remain metadata-only.

## Lifecycle semantics

Allowed transitions are:

```text
open -> resolved (terminal)
open -> dismissed (terminal)
```

Rules:

1. a contradiction must be opened before it can become terminal;
2. a second `open` event for the same contradiction is rejected;
3. terminal transitions must preserve candidate identity, evidence commitment,
   summary commitment, and original `created_at`;
4. `resolved_at` must be canonical UTC and cannot predate `created_at`;
5. an exact duplicate terminal event is idempotent only when actor/reason
   metadata is also identical.

No hidden wall clock is used.

## Concurrency and exact binding

Every write requires:

- `expected_candidate_sha256`;
- `expected_history_head_sha256`.

The operation fails closed if either the canonical candidate identity or the
contradiction history head changed before the transaction.

This prevents stale callers from silently appending against a different
candidate snapshot or a concurrently advanced contradiction index.

## Bounds

Hard bounds:

- maximum total contradiction events: `10,000`;
- maximum open contradictions per candidate: `128`;
- maximum candidate groups in statistics projection: `128`.

`events(max_events=...)` fails closed rather than returning a misleading
partial scan when the stored event count exceeds the requested bound.

## Statistics projection

`statistics()` emits deterministic metadata only:

- total contradiction count;
- open count;
- resolved count;
- dismissed count;
- last contradiction timestamp;
- last resolution timestamp;
- exact candidate and knowledge SHA-256;
- deterministic `statistics_sha256`.

It does not infer root cause, quality, trust, or production disposition.

## Security boundary

This module does not expose:

- stage;
- promote;
- archive;
- rollback;
- materialize;
- tool/model invocation;
- shell execution;
- network access;
- credential access;
- deployment;
- production registry mutation.

Contradiction tracking is maintenance evidence only.

An open contradiction may be consumed by existing policy/review code, but this
index itself never creates a revision candidate and never changes production
state.

## Explicit non-goals

This phase does **not** close:

- E-03 automatic revision candidate trigger from verified contradictions;
- E-10 complete contradiction-to-resolution-to-revision lineage;
- held-out benchmark policy;
- vendor/device observed drift;
- automatic quarantine/retirement;
- automatic rollback.

Those remain separate phases because they require additional authoritative
inputs or review policy.

## Regression coverage

Focused tests cover:

- open -> resolve lifecycle;
- restart persistence;
- deterministic statistics;
- metadata-only storage/projection;
- wrong candidate SHA rejection;
- stale history-head rejection;
- terminal-without-open rejection;
- second-open rejection;
- transition commitment tamper rejection;
- chronology fail-closed;
- stored-row tamper detection;
- bounded scans without partial results;
- authenticated checkpoint requirement;
- absence of production mutation methods;
- exact duplicate terminal idempotence.

## Checklist interpretation

After this phase is merged:

- M-05 can be marked complete because PR #401 supplies exact last-verified
  freshness and this phase supplies persistent contradiction tracking;
- E-03 remains open;
- E-10 remains partial until contradiction resolution is bound through the
  controlled candidate-revision lifecycle.
