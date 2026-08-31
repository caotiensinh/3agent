# Adaptive Learning Phase 3 — Local Version Store, Audit Ledger, and Rollback

Status: IMPLEMENTED STORAGE FOUNDATION / NO BACKGROUND LEARNER

Phase 3 adds the persistent local storage boundary required before WorkSpace is allowed to run an LLM reflection worker.

## Components

- `src/three_agent/adaptive_learning_store.py`
  - isolated local SQLite store for learner-managed knowledge;
  - immutable candidate/version snapshots;
  - staged `candidate -> validated` lifecycle;
  - active `approved` / `enterprise` knowledge;
  - append-only hash-chained audit ledger;
  - archive and exact-version rollback;
  - stale base-hash protection for patch/supersede;
  - metadata-only ledger records.
- `tests/test_adaptive_learning_store.py`
  - storage, promotion, rollback, immutability, reviewer-gate, and tamper tests.

## Architecture

```text
ExperienceRecord
      |
      v
KnowledgeCandidate
      |
      v
STAGE
      |
      +---- immutable candidate snapshot
      |
      v
candidate
      |
      | validation receipt + Phase 1 policy
      v
validated
      |
      | human/domain review where required
      v
approved
      |
      +---- becomes active knowledge
      |
      v
enterprise
```

The Phase 3 store does not provide a direct `write_active()` path.

Active state is derived from append-only ledger events. It is not controlled by a mutable "active" flag or pointer.

```text
stage -> validate -> activate -> enterprise
                         |
                         +-> archive
                         |
                         +-> rollback
```

## Two different hashes

Phase 3 keeps two identities separate.

### Candidate SHA

Binds the complete candidate, including provenance and evidence references.

It answers:

> What exact proposal, produced from what exact experience/evidence lineage, was reviewed?

### Knowledge SHA

Binds the reusable knowledge content/version without folding task-specific evidence lineage into the content identity.

It answers:

> Is this the exact same reusable knowledge version?

A patch/supersede candidate must bind `base_item_sha256` to the exact active Knowledge SHA. Stale-base writes fail closed.

## Append-only audit

Every transition appends a metadata-only ledger event containing:

- sequence;
- event ID/type;
- item/candidate IDs;
- candidate SHA;
- knowledge SHA;
- before/after SHA;
- validation receipt SHA;
- source experience hashes;
- evidence hashes;
- actor ID;
- reason code;
- timestamp;
- previous ledger-entry SHA;
- current ledger-entry SHA.

The ledger intentionally does **not** contain:

- raw logs;
- raw packet captures;
- raw prompts;
- credentials;
- raw source evidence;
- full candidate/procedure content.

Candidate content is stored only in the local immutable version table.

SQLite triggers reject UPDATE and DELETE against both the version snapshots and audit ledger. The ledger also forms a SHA-256 chain so forged/out-of-chain rows are detectable by `verify_ledger()`.

## Ownership boundary

Phase 3 accepts only:

```text
ownership=learner_managed
```

A learner cannot claim that its own candidate is `user_team` or `system` knowledge.

Adoption or creation of team/system-owned enterprise knowledge requires a separate operator-governed feature and is intentionally not implemented here.

## Network and Security boundary

Phase 3 reuses `AdaptiveLearningPolicy`.

Therefore storage cannot bypass the Phase 1 rules:

- open contradiction blocks promotion;
- failed validation receipt blocks promotion;
- candidate/receipt hash mismatch blocks promotion;
- evidence lineage mismatch blocks promotion;
- Network/Security approval requires human review;
- Network/Security approval requires domain review;
- enterprise promotion requires human review.

The store grants no network, shell, credential, remediation, deployment, or Git capability.

## Enterprise baseline protection

If an item is already active at `enterprise`, a new patch reaching only `approved` is kept staged and does not displace the enterprise baseline.

Only after the patch independently reaches `enterprise` can it replace that active baseline.

This prevents an ordinary approved candidate from silently downgrading enterprise-approved knowledge.

## Rollback

Rollback does not accept arbitrary replacement content.

It can target only an exact Knowledge SHA that already exists as a previously promoted active snapshot.

The caller must also bind the expected current Knowledge SHA (or `None` when restoring an archived item). This makes rollback fail closed on concurrent/stale state.

## Persistence and file boundary

The store is local-only and has no networking code.

The SQLite database is created with restrictive file permissions where the platform supports POSIX modes.

This does not replace host filesystem/RBAC controls. Deployment policy remains responsible for ensuring only the authorized WorkSpace service account and operators can read the confidential learning database.

## Acceptance tests

Phase 3 tests cover at minimum:

1. staged candidate is not active;
2. validated candidate remains staged;
3. approved candidate becomes active;
4. failed receipt blocks promotion;
5. Network/Security reviewer gates are enforced;
6. learner cannot self-claim team/system ownership;
7. stale patch base hash is rejected;
8. promoted patch can roll back to the exact prior version;
9. archive preserves history and can be restored;
10. unknown/unpromoted rollback targets are rejected;
11. enterprise baseline is not displaced by approved-only patch;
12. audit export contains hashes, not raw procedure/evidence content;
13. SQL UPDATE/DELETE of ledger/version snapshots is rejected;
14. hash-chain verification detects injected forged rows;
15. state and ledger survive store reopen/restart;
16. active/version reads recompute candidate and knowledge identity and fail closed on version-table tamper.

## Still intentionally absent

Phase 3 still does **not** implement:

- background LLM reflection;
- automatic candidate generation after every task;
- automatic promotion;
- automatic active-knowledge mutation;
- autonomous curation;
- core source self-modification;
- Network/Security remediation;
- public/cloud synchronization of confidential learning.

Those capabilities must not be added merely because a persistent store now exists.

## Phase 3.1 gate before Reflection

Phase 3's unkeyed SHA-256 chain is tamper-evident, but it is not an authenticated freshness guarantee. A principal with unrestricted database rewrite authority could rebuild a complete internally consistent DB and hash chain.

Therefore Phase 3.1 is required before Phase 4. It adds:

```text
Phase 3 store
   |
   v
authenticated checkpoint journal
   |
   v
trusted current-head witness
   |
   v
stage-only learner gateway
```

The checkpoint key and witness-write authority remain outside learner authority. The witness provides an independently protected newest-generation anchor so replaying an older valid DB+journal pair fails closed.

See `ADAPTIVE_LEARNING_PHASE3_1.md`.

## Phase 4 boundary

Only after the Phase 3.1 boundary is deployed may Phase 4 add a constrained Reflection Worker:

```text
completed task/evidence summary
        |
        v
constrained reflection
        |
        v
KnowledgeCandidate
        |
        v
Phase 1 contract
        |
        v
Phase 2 offline/domain validation
        |
        v
Phase 3.1 STAGE-ONLY GATEWAY
```

The first Reflection Worker has proposal authority only. It does not receive promotion, checkpoint signing, witness writing, shell, network, credential, remediation, deployment, or Git authority.
