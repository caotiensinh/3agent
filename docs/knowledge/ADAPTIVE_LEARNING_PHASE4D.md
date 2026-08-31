# Adaptive Learning Phase 4D — trusted production retrieval bootstrap

## Status

Phase 4D wires the Phase 4C read-only retrieval gateway into the real WorkSpace `Orchestrator` construction path. It does not add learning authority. It only makes an already-authenticated, operator-prepared learning generation consumable by Research as local untrusted reference data.

Prerequisites remain authoritative:

- Phase 3 immutable append-only learning store;
- Phase 3.1 authenticated checkpoint journal and independent trusted-head witness;
- Phase 4A deterministic verified-experience admission;
- Phase 4B isolated stage-only Reflection;
- Phase 4C checkpoint-verified capability-free retrieval and TaskContract-bound sensitivity.

## Core invariant

> Production retrieval may open existing approved knowledge read-only. It may never create or repair trust.

Phase 4D does **not**:

- initialize or bootstrap a learning store;
- generate or rotate keys;
- create a checkpoint or witness;
- rebaseline stale state;
- stage, promote, archive, or rollback knowledge;
- run Reflection;
- add a daemon, network service, shell, subprocess, embeddings, or vector database.

## Production flow

```text
trusted local WorkSpace config
        |
        v
runtime_retrieval.enabled ?
        |
   +----+----+
   |         |
 false      true
   |         |
   |         +--> reject public-research zone/mode
   |         +--> validate exact trusted domain
   |         +--> require existing private learning DB
   |         +--> load existing private key file(s)
   |         +--> bind existing journal + witness + store_id
   |         +--> verify exact authenticated store state
   |         +--> construct LearningRetrievalGateway
   |         `--> inject gateway into ResearchAgent
   |
   `--> no adaptive-learning filesystem access
```

## Disabled behavior

`enabled=false` is the default.

When disabled:

- no adaptive-learning DB is opened or created;
- no journal/witness/key path is read;
- `Orchestrator.learning_retrieval` is `None`;
- `ResearchAgent.learning_retrieval` is `None`;
- existing WorkSpace behavior is preserved.

This keeps Windows and all existing deployments compatible without requiring a checkpoint key provider.

## Enabled behavior

Enabled mode is explicit operator intent and therefore strict.

The runtime requires:

1. an **existing** Phase 3 SQLite learning store;
2. an **existing** Phase 3.1 checkpoint journal;
3. an **existing** independent trusted-head witness;
4. one or more **existing** private checkpoint key files;
5. the exact `store_id`, active key ID, and trusted retrieval domain.

If any required element is missing, malformed, stale, replayed, permission-unsafe, or cryptographically mismatched, WorkSpace startup fails closed. It does not silently disable retrieval and does not create a replacement trust state.

## Read-only database boundary

Production consumption uses `ReadOnlyAdaptiveLearningStore`, a Phase 4D adapter over the existing Phase 3 schema.

It:

- requires an existing regular non-symlink DB file;
- requires private POSIX permissions;
- opens SQLite with `mode=ro`;
- enables `PRAGMA query_only=ON`;
- does not call `AdaptiveLearningStore.initialize()`;
- does not chmod or otherwise repair the store.

The normal Phase 3 `AdaptiveLearningStore` remains the write-side store for trusted staging/promotion workflows. Phase 4D does not change that mutation contract.

## Key provider

Phase 4D reuses `HmacCheckpointKeyring.from_files()`.

Current properties:

- POSIX-only;
- regular file only;
- symlink rejected;
- group/world permissions rejected;
- key must meet the existing minimum entropy/length contract;
- key bytes are never stored in WorkSpace JSON configuration.

A future Windows production key provider requires a separate reviewed DPAPI/CNG/TPM design. Phase 4D does not invent one. Enabling the current provider on a non-POSIX host fails closed.

## Configuration

Secure configuration defaults to disabled:

```json
"adaptive_learning": {
  "runtime_retrieval": {
    "enabled": false
  }
}
```

A reviewed POSIX deployment may enable it with paths to existing trust material:

```json
"adaptive_learning": {
  "runtime_retrieval": {
    "enabled": true,
    "store_path": "/var/lib/workspace-learning/learning.db",
    "checkpoint_journal_path": "/var/lib/workspace-learning/checkpoint/journal.jsonl",
    "trusted_head_witness_path": "/var/lib/workspace-trusted-head/adaptive-learning.json",
    "store_id": "learning-store:workspace",
    "active_key_id": "key:v1",
    "key_files": {
      "key:v1": "/var/lib/workspace-secrets/adaptive-learning-v1.key"
    },
    "domain": "analyst"
  }
}
```

The witness must remain outside the learner/learning-DB rollback authority. A pathname alone cannot prove backup or administrative separation; deployment policy must preserve that independent freshness boundary.

## Domain and sensitivity

The configured retrieval `domain` is trusted operator configuration and must be one of the existing Phase 4C domains.

Task sensitivity is **not** configured here. Research continues to load it from the exact bound `TaskContract` for the current task immediately before retrieval. Missing, malformed, or task-ID-mismatched contracts disable learned context for that run.

## Public research separation

Phase 4D forbids enabled adaptive runtime retrieval when:

- `environment=public-research-zone`, or
- `confidentiality_mode=public-research`.

This preserves the WorkSpace zone boundary: public research does not mount the confidential adaptive-learning runtime store.

## Runtime authority

The Research Agent receives only `LearningRetrievalGateway`.

That gateway exposes retrieval, not:

- stage;
- promote;
- archive;
- rollback;
- bootstrap;
- key rotation/signing;
- checkpoint/witness write;
- shell;
- network;
- credentials;
- Git/deployment authority.

Learned content remains `untrusted_reference_data_only` and is attached only to local synthesis. Phase 4C still excludes it from query planning and public egress.

## Smoke / telemetry

`Orchestrator.smoke()` may report only:

- `adaptive_learning_retrieval_enabled`;
- `adaptive_learning_retrieval_domain` when enabled.

It must not report learning DB paths, journal/witness paths, key-file paths, key bytes, raw query text, or learned content.

## Acceptance

Phase 4D tests verify:

1. disabled configuration is a filesystem no-op;
2. a valid existing authenticated store wires into the real production `Orchestrator`/`ResearchAgent`;
3. approved knowledge is retrievable through that production-wired gateway;
4. the production store connection rejects writes;
5. a missing checkpoint is not automatically bootstrapped;
6. a missing store is not created;
7. a wrong key fails startup;
8. public-research zone/mode cannot mount adaptive runtime learning;
9. invalid domain fails before learning filesystem access;
10. smoke output excludes learning trust paths and key material;
11. the Research Agent receives no learning mutation authority;
12. Phase 1-4C regressions and deployment gates remain green.

## Operator preparation boundary

Creating the initial store, checkpoint, witness, and key remains a separate trusted operator/deployment task. Phase 4D intentionally supplies no convenience command for that operation because automatic bootstrap would collapse the distinction between **creating trust** and **consuming already-authenticated trust**.
