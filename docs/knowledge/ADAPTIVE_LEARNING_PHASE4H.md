# Adaptive Learning Phase 4H — measured reuse outcomes and safe curation signals

## Status

Phase 4H closes the first deterministic feedback loop between **reused approved knowledge** and later **authoritative task outcomes**. It is observational only. It does not let the model rate itself, mutate knowledge, promote candidates, archive items, remediate systems, or rewrite WorkSpace policy.

Prerequisites remain authoritative:

- Phase 3/3.1 immutable authenticated learning storage;
- Phase 4A deterministic verified-experience admission;
- Phase 4B isolated proposal-only Reflection;
- Phase 4C/4D checkpoint-verified production retrieval;
- Phase 4E authenticated human promotion;
- Phase 4F explicit operator bootstrap;
- Phase 4G bounded default-off background Reflection scheduling.

## Core invariant

> A task succeeding after knowledge reuse is an observation, not proof that the knowledge caused the success.

Phase 4H therefore uses `observed_after_reuse` terminology and marks every snapshot `observational_non_causal`.

## Flow

```text
Phase 4C/4D LearningContext
        |
        | exact task + query hash + domain + sensitivity
        | exact (item_id, knowledge_sha256)
        v
LearningReuseReceipt
(metadata only, deterministic ID)
        |
        v
existing TaskStore activity ledger
        |
        +------------------------------+
        |                              |
        v                              v
TaskStore task status          fresh ValidatorLedger.evaluate()
        |                              |
        +---------------+--------------+
                        v
DeterministicLearningEffectivenessAnalyzer
                        |
                        +--> isolated observations
                        +--> confounded observations
                        +--> verified success / failed / waiting / pending
                        +--> DONE-but-unverified integrity signal
                        v
advisory curation signal only
                        |
                       STOP
```

## Reuse receipt

`workspace-learning-reuse-receipt/v1` contains only:

- deterministic `receipt_id`;
- authoritative `task_id`;
- retrieval `query_sha256` — never raw query text;
- trusted retrieval `domain`;
- exact TaskContract sensitivity;
- sorted exact `(item_id, knowledge_sha256)` references.

It does **not** contain:

- learned title/content/scope;
- raw task request or compiled prompt;
- model output;
- validator evidence bytes or evidence paths;
- local filesystem paths;
- URLs;
- credentials, tokens, secrets, OAuth/session data;
- promotion/reviewer authority.

The Research path records the receipt **before** learned reference data is exposed to local synthesis. If an exact receipt cannot be bound to the current TaskContract, learned context is withheld for that run rather than being reused without an auditable observation.

## Anti-self-reinforcement

Repeated retrieval must not inflate effectiveness.

Phase 4H applies two layers of deduplication:

1. exact duplicate `receipt_id` values count once;
2. for per-knowledge effectiveness, one task contributes at most one outcome observation to an exact `knowledge_sha256`, even when the task performs multiple distinct retrieval queries.

This prevents a looping task from making one knowledge item appear strongly validated merely by retrieving it repeatedly.

## Confounding

If more than one exact knowledge version was made available anywhere in the same task, the task is **confounded for every reused item**.

Example:

```text
Task T1
  -> K1
  -> later K1 + K2
  -> verified success
```

T1 is not isolated evidence for K1 because K2 was also available during the task. Both K1 and K2 receive a confounded success observation; neither receives `isolated_verified_success` credit.

Even a single-item observation remains non-causal. “Isolated” means only that WorkSpace did not observe another adaptive knowledge version in the same task.

## Authoritative outcomes

Task outcome is resolved from current local authoritative state:

- `DONE` + fresh `ValidatorLedger.evaluate().verified=true` → `VERIFIED_SUCCESS_OBSERVED_AFTER_REUSE`;
- `DONE` without fresh complete verification → `DONE_UNVERIFIED_OBSERVED_AFTER_REUSE`;
- `FAILED` → `FAILED_OBSERVED_AFTER_REUSE`;
- `WAITING_HUMAN` → `WAITING_HUMAN_OBSERVED_AFTER_REUSE`;
- all other task states → `PENDING_OBSERVED_AFTER_REUSE`.

A model message, candidate text, learning title, retrieval rank, or usage count cannot manufacture verified success.

## Advisory curation signals

Phase 4H produces only advisory metadata:

- `INSUFFICIENT_EVIDENCE`;
- `SUPPORT_OBSERVED`;
- `REVIEW_RECOMMENDED`;
- `DOMAIN_REVIEW_RECOMMENDED`.

Current conservative v1 rules are deterministic:

- three or more isolated verified-success observations, with no isolated failure, unverified-DONE, or unresolved/waiting observation → `SUPPORT_OBSERVED`;
- Analyst/General: two isolated failure/unverified-DONE observations or three isolated waiting-human observations → `REVIEW_RECOMMENDED`;
- Network/Security: one isolated failure/unverified-DONE observation or two isolated waiting-human observations → `DOMAIN_REVIEW_RECOMMENDED`;
- otherwise → `INSUFFICIENT_EVIDENCE`.

These are **review signals, not lifecycle transitions**. Retrieval popularity alone never creates support. Confounded observations never satisfy isolated support/adverse thresholds.

## Why Network/Security is stricter

For Network Monitoring and Security Analysis, a bad reusable procedure can increase false positives, hide incidents, or encourage unsafe conclusions. Phase 4H therefore recommends domain review after fewer isolated adverse observations.

This still does not authorize:

- firewall changes;
- account changes;
- device quarantine;
- packet injection;
- scanning;
- process termination;
- automatic archive/delete;
- automatic rollback;
- automatic promotion.

Existing human/domain reviewer gates remain authoritative.

## Persistence

Phase 4H deliberately reuses the existing `TaskStore.activities` ledger. It adds no new database, service, daemon, vector store, queue, or network dependency.

The activity is metadata-only and uses a strict JSON schema so corrupted/tampered receipt rows fail closed during analysis instead of silently skewing metrics.

## Snapshot

`workspace-learning-effectiveness/v1` is deterministic for unchanged TaskStore/ValidatorLedger state. It contains per exact knowledge version:

- unique task observations;
- unique exact reuse receipts;
- isolated and confounded task counts;
- verified-success, failed, waiting-human, pending, and DONE-unverified observations;
- isolated subsets used by the advisory policy;
- advisory signal;
- `observational_non_causal` interpretation.

The snapshot has a deterministic SHA-256 and contains no learned content or raw task/evidence data.

## Authority boundary

`DeterministicLearningEffectivenessAnalyzer` has read/aggregate authority only. It has no methods or dependencies for:

- `stage`;
- `promote`;
- `archive`;
- `rollback`;
- `delete`;
- `rotate_key`;
- checkpoint/witness signing;
- remediation;
- shell/subprocess;
- Internet/LAN access;
- Git/deployment;
- credential access;
- model invocation.

A future curation phase may consume these advisory signals, but any lifecycle mutation must still pass a separate deterministic policy and existing authenticated human/domain authority.

## Acceptance

Phase 4H tests require:

1. deterministic metadata-only exact-version reuse receipts;
2. exact TaskContract sensitivity binding;
3. duplicate receipts and repeated queries do not inflate task observations;
4. DONE without fresh validator verification is not counted as verified success;
5. three isolated verified successes may emit observational `SUPPORT_OBSERVED`, never promotion;
6. multi-item reuse is always confounded;
7. later multi-item reuse keeps the whole task confounded even if an earlier retrieval was single-item;
8. Network/Security review threshold is stricter than Analyst/General;
9. waiting and pending states remain distinct;
10. tampered receipt data fails closed;
11. snapshots are deterministic and metadata-only;
12. Phase 1–4G regression and deployment gates remain green on the same exact PR head.

## Non-goals

Phase 4H does not attempt causal A/B testing, automatic policy optimization, online model-weight training, reinforcement learning from model self-judgment, or autonomous knowledge lifecycle control. Those would require separate evidence and security designs.
