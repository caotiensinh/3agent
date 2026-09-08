# Adaptive Learning Stale Skill Review V0.1

Status: implementation contract for WorkSpace Skill lifecycle M-08.

## Goal

Detect active approved/enterprise learned skills whose **exact active knowledge version** has not been reused for an operator-owned interval and emit a bounded human-review recommendation.

This policy is recommendation-only. It does not archive, quarantine, revise, promote, materialize, mutate the learning store, invoke a model, use tools, access credentials, execute shell commands, or perform network activity.

## Why this is separate from effectiveness failure

Staleness and poor effectiveness are different signals:

- **stale**: an active exact skill version has not been reused recently;
- **poor effectiveness**: a skill is being reused but authoritative outcomes are adverse.

Phase 4H/4I already handles the second case. V0.1 closes only the first gap and therefore never converts “not used” into a synthetic failure signal.

## Canonical inputs

The implementation reuses existing trusted state only:

1. `AdaptiveLearningStore` authenticated by `LearningCheckpointAuthority`;
2. the append-only learning ledger for active exact-version identity and current activation/rollback tenure;
3. `learning_reuse_observed` activities produced by canonical `record_learning_reuse(...)`;
4. `LearningReuseReceipt` validation for exact `(item_id, knowledge_sha256)` binding;
5. `TaskStore.activities` only as the existing metadata ledger.

There is no new database, registry, active pointer, or capability authority.

## Freshness rule

For one current active skill version:

```text
activation_at = latest activate / enterprise / rollback event
                whose after_sha256 == current active knowledge_sha256

last_reuse_at = latest valid learning_reuse_observed receipt
                for the same item_id + knowledge_sha256
                occurring during the current active tenure

freshness_anchor = max(activation_at, last_reuse_at)

stale when:
    as_of - freshness_anchor >= stale_after_days
```

Important rollback rule: reuse from an older tenure of the same immutable knowledge version is ignored after rollback/reactivation. A new active tenure starts a new freshness clock.

## Explicit time boundary

Enabled scans require caller-supplied `as_of` in UTC. There is no hidden wall-clock read inside the policy. This keeps review receipts reproducible and makes the exact evaluation boundary auditable.

`as_of` earlier than the active freshness anchor is rejected rather than guessed.

## Operator-owned bounds

`StaleSkillReviewConfig` controls:

- `stale_after_days` — default 90, valid 1..3650;
- `max_active_skills` — default 64, hard maximum 128;
- `max_reuse_receipts` — default 2048, hard maximum 10,000;
- `enabled` — default false.

If an active-skill or reuse-receipt bound is exceeded, the scan emits **zero partial reviews** and returns a limit status.

## Recommendation semantics

A stale recommendation is bound to:

- `item_id`;
- exact active `knowledge_sha256`;
- exact active `candidate_sha256`;
- active level;
- domain;
- activation timestamp;
- last reuse timestamp, if any in the current tenure;
- freshness anchor;
- explicit `as_of`;
- threshold and exact age in seconds.

Every recommendation requires human review. `network` and `security` domains additionally require domain review.

The recommendation grants no capabilities and exposes no mutation method.

## Privacy

Receipts intentionally exclude:

- skill title/body/procedure content;
- candidate content;
- task request/prompt;
- evidence bytes;
- model input/output;
- search query text;
- credentials, paths, or secret values.

Only exact identifiers, hashes, timestamps, counts, policy bounds, reason codes, and checkpoint hashes are retained.

## Integrity and concurrency

One enabled scan:

1. verifies the authenticated learning checkpoint;
2. verifies the append-only learning ledger;
3. resolves each active item through canonical `AdaptiveLearningStore.active(...)`;
4. validates every canonical reuse receipt before trusting it;
5. produces metadata-only recommendations;
6. verifies the authenticated learning checkpoint again;
7. fails if checkpoint sequence/hash/state changed during the scan.

Malformed reuse receipts or task/receipt binding mismatches fail closed.

## Status values

- `DISABLED`
- `NO_STALE_SKILLS`
- `REVIEWS_READY`
- `ACTIVE_SKILL_LIMIT_EXCEEDED`
- `REUSE_RECEIPT_LIMIT_EXCEEDED`

## Non-goals for V0.1

V0.1 does not:

- automatically archive or quarantine stale skills;
- create revision candidates;
- define vendor/version drift policy;
- interpret stale state as failure;
- replace Phase 4H/4I effectiveness curation;
- add background scheduling by itself;
- change runtime skill selection.

A scheduler may call this read-only policy as one bounded maintenance step, but mutation remains behind the existing authenticated operator/reviewer boundaries.
