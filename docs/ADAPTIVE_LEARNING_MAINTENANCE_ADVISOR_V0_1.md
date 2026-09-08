# Adaptive Learning Maintenance Advisor V0.1

## Purpose

Close the orchestration gap between canonical Phase 4H effectiveness analysis and
canonical Phase 4I curation proposals without adding a second learning,
recommendation, promotion, archive, rollback, runtime, or model subsystem.

The advisor performs exactly one bounded `run_once()` tick:

1. read metadata-only reuse receipts and authoritative TaskStore / ValidatorLedger outcomes through `DeterministicLearningEffectivenessAnalyzer`;
2. obtain the deterministic Phase 4H `LearningEffectivenessSnapshot`;
3. enforce an operator-owned maximum signal count;
4. compile the exact snapshot through `DeterministicCurationProposalCompiler`;
5. return a metadata-only maintenance receipt containing review recommendations.

## Canonical ownership

This module does **not** replace any existing canonical component.

- Reuse telemetry: `adaptive_learning_effectiveness.py`
- Effectiveness policy/signals: `DeterministicLearningEffectivenessAnalyzer`
- Active learning integrity: `AdaptiveLearningStore`
- Checkpoint/state authenticity: `LearningCheckpointAuthority`
- Curation action mapping: `adaptive_learning_curation.py`
- Curation proposal identity: `DeterministicCurationProposalCompiler`
- Revision approval/model isolation: Phase 4J
- Revision safety/activation/rollback: Phase 4K
- Production materialization/supersession: candidate-skill production boundaries

## Authority boundary

The maintenance advisor is recommendation-only.

It has no method or authority to:

- stage a candidate;
- validate or promote learning;
- archive or rollback learning;
- materialize or supersede production skills;
- invoke a model;
- use network, shell, credentials, tools, adapters, or device control;
- edit source code, Git state, deployment state, or runtime authority.

The receipt declares:

`recommendation_only_no_learning_or_runtime_mutation`

## Recommendation mapping

The advisor does not invent a second policy vocabulary. It projects exact Phase 4I
actions into compact operator-facing recommendation types:

| Phase 4I action | Maintenance recommendation |
| --- | --- |
| `OBSERVE_MORE` | `observe_more` |
| `KEEP_ACTIVE_REVIEW` | `keep_active_review` |
| `REVISE_OR_ARCHIVE_REVIEW` | `revision_or_retirement_review` |
| `DOMAIN_REVISE_OR_ARCHIVE_REVIEW` | `domain_revision_or_retirement_review` |

These labels are advisory projections only. They do not authorize revision,
retirement, quarantine, archive, or promotion.

## Bounded execution

`AdaptiveLearningMaintenanceConfig.max_signals` is hard-bounded to `1..128`.

If a snapshot contains more signals than configured capacity, the tick returns
`SIGNAL_LIMIT_EXCEEDED` with **zero partial recommendations**. This is deliberate:
partial deterministic curation could hide a higher-risk item merely because of
ordering. The operator must increase the reviewed bound or split the operational
scope outside this module.

No daemon/background loop is created. Scheduling cadence remains parent/operator
policy.

## Checkpoint safety

For an enabled tick:

1. verify the authenticated learning checkpoint before analysis;
2. run Phase 4H metadata analysis;
3. compile Phase 4I proposals only when within capacity;
4. verify the learning checkpoint again;
5. reject if sequence, checkpoint SHA, or state SHA changed.

The existing Phase 4I compiler independently re-verifies the checkpoint around
active-state reads. The advisor therefore adds orchestration-level stability
without weakening canonical verification.

## Failure semantics

Fail closed when:

- reuse receipt integrity is invalid;
- TaskStore/ValidatorLedger effectiveness analysis is invalid;
- an observed knowledge SHA is no longer the exact active version;
- the curation compiler rejects domain/state binding;
- learning checkpoint/state changes during the tick;
- configured signal capacity is exceeded.

Capacity excess is represented as a valid metadata receipt with zero
recommendations. Integrity/state failures raise an explicit maintenance error.

## Privacy and evidence policy

Maintenance receipts contain metadata only:

- item ID;
- exact knowledge/candidate SHA;
- domain and active level;
- advisory signal;
- curation action;
- review requirements;
- canonical reason codes;
- snapshot/proposal/checkpoint hashes.

They do not contain:

- learned procedure content;
- raw task request;
- model output;
- evidence bytes;
- credentials;
- file paths;
- source artifacts.

## V0.1 acceptance tests

The focused suite must prove:

1. disabled mode is an exact no-op;
2. one failed network reuse produces domain revision/retirement review;
3. two isolated analyst failures produce revision/retirement review;
4. three isolated verified successes produce keep-active review;
5. signal-capacity excess yields zero partial recommendations;
6. stale knowledge SHA is rejected by canonical Phase 4I binding;
7. repeated unchanged runs produce an identical metadata-only receipt;
8. the advisor exposes no learning/runtime mutation method.

## Non-goals

V0.1 does not implement:

- automatic revision creation;
- automatic quarantine;
- automatic retirement/archive;
- automatic promotion;
- automatic production publication;
- persistent maintenance queues;
- cron/daemon scheduling;
- model-based quality judgments;
- causal claims from observational reuse outcomes.

Those operations remain behind their existing human/domain-review and canonical
learning authority boundaries.
