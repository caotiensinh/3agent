# Adaptive Learning Verification Freshness V0.1

Status: implementation contract for the last-verified portion of WorkSpace Skill lifecycle M-05.

## Goal

Project the most recent authoritative verified timestamp for each exact reused adaptive-knowledge version without creating a second effectiveness analyzer, telemetry ledger, learning store, contradiction store, or mutation path.

This slice intentionally closes only **last verified date**. `ContradictionRecord` already exists as a canonical validation/promotion contract, but there is not yet a canonical persistent contradiction index suitable for system-wide maintenance statistics. Contradiction tracking therefore remains a separate open portion of M-05.

## Canonical sources

The projector reuses existing sources only:

1. `DeterministicLearningEffectivenessAnalyzer.snapshot()` for authoritative exact-version outcome counts;
2. canonical metadata-only `LearningReuseReceipt` rows in `TaskStore.activities`;
3. current `Task.status` and `Task.updated_at`;
4. current `ValidatorLedger.evaluate(task_id)` state;
5. latest required-validator result timestamps from the existing validator ledger.

No new activity row or database table is written.

## What `last_verified_at` means

An exact knowledge version receives a verified timestamp only when all of these are true:

- that exact `item_id + knowledge_sha256 + domain` was recorded in a canonical reuse receipt for the task;
- the task's current status is `DONE`;
- `ValidatorLedger.evaluate(task_id).verified` is true;
- every currently required validator has a latest `passed` result;
- the resulting verification timestamp is not earlier than the reuse observation.

The timestamp for one verified task is the later of:

- the task's current `updated_at` timestamp representing the final status transition; and
- the latest current required-validator result timestamp.

All timestamps are projected to canonical UTC. No filesystem mtime and no hidden wall-clock read is used.

## Overall versus isolated freshness

The projection exposes both:

- `last_verified_at`: latest verified task where the exact knowledge version was available, including observationally confounded tasks;
- `last_isolated_verified_at`: latest verified task where no other knowledge version was simultaneously available.

The matching counters are also exposed:

- `verified_task_observations`;
- `isolated_verified_task_observations`.

A confounded verified task may therefore advance `last_verified_at` without advancing `last_isolated_verified_at`.

## Exact Phase 4H binding

The projector first computes the canonical Phase 4H effectiveness snapshot. It independently derives timestamp metadata, then requires its verified counts to equal:

- `KnowledgeEffectivenessSignal.verified_success_after_reuse`;
- `KnowledgeEffectivenessSignal.isolated_verified_success`.

Any mismatch fails closed. This prevents the timestamp projection from silently becoming a second outcome-counting authority.

Every projection carries the exact `source_effectiveness_snapshot_sha256` and a deterministic `projection_sha256`. The enclosing snapshot has its own deterministic hash.

## Chronology safety

A verified timestamp earlier than the earliest canonical reuse observation for the exact task/version is invalid and fails closed with:

`VERIFICATION_FRESHNESS_VERIFICATION_PRECEDES_REUSE`

Duplicate identical reuse receipts are deduplicated by canonical receipt identity and retain the earliest observed timestamp. A duplicate row therefore cannot move freshness forward.

## Privacy and authority

The output is metadata-only. It contains no:

- skill body;
- task request;
- task ID;
- prompt/model output;
- evidence bytes or evidence references;
- credentials;
- filesystem paths.

The projector has no `stage`, `promote`, `archive`, `rollback`, `materialize`, model, tool, network, credential, shell, deployment, or runtime-execution authority.

## Non-goals

V0.1 does not:

- claim causal effectiveness;
- create or resolve contradictions;
- persist a contradiction index;
- auto-retire or quarantine a skill;
- change Phase 4H counters, normalized rates, or advisory thresholds;
- change `workspace-learning-effectiveness/v1` payload/hash semantics;
- alter learning checkpoints or production skill state.

## M-05 status after this slice

After merge, M-05 should remain **partial**, but the wording should change from "last-verified maintenance projection is not complete" to reflect that last-verified projection is complete while persistent contradiction statistics remain open.
