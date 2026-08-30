# Adaptive Learning Phase 3.1 — Authenticated Checkpoint Boundary

Status: IMPLEMENTED CHECKPOINT FOUNDATION / NO BACKGROUND LEARNER

Phase 3.1 closes the integrity gap that remains after Phase 3's local immutable version store and unkeyed SHA-256 ledger.

An unkeyed hash chain is useful for detecting partial corruption and inconsistent local state. It is not sufficient against a principal that can rewrite the complete learning database and recompute every unkeyed hash. Phase 3.1 therefore adds an authenticated checkpoint journal whose key authority is outside the learning database and outside learner-facing capability.

## Architecture

```text
learner / future Reflection Worker
          |
          | stage(candidate) only
          v
LearningStagingGateway
          |
          v
trusted checkpoint coordinator
          |
          | verify authenticated head
          v
AdaptiveLearningStore mutation
          |
          | recompute exact store state
          v
authenticated checkpoint append
          |
          v
external checkpoint journal
```

Operator-only actions use a separate `LearningOperatorGateway`.

```text
Operator Gateway
  |- verify
  |- rotate_key
  |- promote
  |- archive
  `- rollback
```

The learner-facing gateway deliberately exposes only `stage()`.

## What a checkpoint binds

Each checkpoint authenticates:

- trusted `store_id` supplied outside the learning database;
- store schema;
- ledger schema;
- exact ledger head SHA;
- ledger entry count;
- latest ledger event type, item ID, and candidate ID;
- exact immutable-version row count;
- canonical digest of every immutable version row;
- overall state SHA;
- checkpoint sequence;
- mutation kind;
- key ID;
- previous checkpoint SHA;
- UTC creation time.

The checkpoint journal contains hashes and identifiers only. It does not contain candidate procedure text, raw prompts, raw logs, packet captures, credentials, or raw evidence.

## Why version state is authenticated too

Signing only the ledger head is insufficient.

Phase 3 stores reusable candidate content in a separate immutable version table. An attacker that modifies that table while leaving the ledger untouched must still be detected. Therefore checkpoint capture re-parses every stored `KnowledgeCandidate`, recomputes its candidate SHA/item ID/knowledge SHA, and then computes a digest over the complete semantic version state.

```text
candidate_json
   -> strict candidate parser
   -> candidate SHA
   -> item ID
   -> knowledge SHA
   -> version-state digest
   -> store-state digest
   -> authenticated checkpoint
```

## Mutation protocol

Checkpointed mutations are serialized by the trusted coordinator:

```text
verify journal chain + latest HMAC
        |
        v
verify exact current learning-store state
        |
        v
perform one allowed store mutation
        |
        v
require expected ledger/version delta
        |
        v
recompute exact state
        |
        v
append + fsync authenticated checkpoint
        |
        v
verify again
```

Expected deltas are deterministic:

| Operation | Ledger delta | Version delta | Expected ledger event |
| --- | ---: | ---: | --- |
| stage | +1 | +1 | `stage` |
| promote | +1 | +1 | `validate`, `activate`, or `enterprise` |
| archive | +1 | 0 | `archive` |
| rollback | +1 | 0 | `rollback` |

Idempotent operations that do not change store state do not create a new checkpoint.

## Fail-closed crash boundary

SQLite mutation and external checkpoint append are intentionally separate trust/media boundaries. A power loss or I/O failure can therefore occur after the DB commits but before the checkpoint journal is durably appended.

WorkSpace must **not** automatically sign the unmatched newer DB state on restart. Doing so would turn recovery into an implicit integrity bypass.

Instead:

1. the next authenticated verification detects the state mismatch;
2. learner/operator mutation through the checkpoint gateway is blocked;
3. operator recovery must inspect the DB, audit evidence and last authenticated checkpoint;
4. restore the last known-good backup or use an explicitly reviewed recovery/rebaseline procedure.

This is availability loss by design rather than silent integrity loss.

## Key boundary

`HmacCheckpointKeyring` is a trusted-process primitive. It is not a learner tool.

For POSIX file-backed keys, the built-in loader:

- accepts regular files only;
- rejects symlinks;
- rejects group/world-readable or writable key files;
- requires at least 32 bytes of key material;
- never writes key bytes to the checkpoint journal.

The raw file provider intentionally refuses non-POSIX platforms. A Windows production deployment should use a higher-trust adapter backed by DPAPI/CNG, a privileged local signer service, TPM-backed material, or an equivalent OS-protected secret boundary.

Tests may instantiate an in-memory keyring because the test process is the trusted authority under test.

## Key rotation

Rotation is anchored, not history-rewritten.

```text
checkpoint N      signed by key:v1
      |
      v
checkpoint N+1    same verified store state
                  previous = SHA(checkpoint N)
                  signed by key:v2
```

Procedure:

1. load `key:v1` and `key:v2` into the trusted authority;
2. set `key:v2` active;
3. verify the current `key:v1` authenticated head;
4. append a `key_rotation` checkpoint signed by `key:v2`;
5. verify the new head;
6. a restarted authority may then retain only `key:v2`.

The new authenticated head anchors the complete prior checkpoint hash chain. Historical records remain tamper-evident even after the old secret is retired.

## Database rewrite and rollback detection

Because the authenticated checkpoint journal is outside the learning DB:

- replacing the DB with a newly generated valid database fails state comparison;
- restoring an older, internally valid database while keeping the newer checkpoint journal fails state comparison;
- rebuilding the internal unkeyed ledger is insufficient without the checkpoint key.

Backup/restore must therefore treat the learning database and authenticated checkpoint journal as one integrity generation, while key custody remains a separate higher-trust concern.

Do not casually roll the journal backward together with a database backup. High-assurance deployments should additionally anchor the latest checkpoint generation in TPM/HSM/OS monotonic state or another independently protected monotonic store.

## Threat boundary

Phase 3.1 is intended to resist accidental corruption and an attacker/principal that can rewrite the learning database but cannot rewrite the external authenticated checkpoint authority.

It does **not** claim to resist a fully privileged host administrator/root attacker that can simultaneously replace:

- learning database;
- checkpoint journal;
- trusted checkpoint executable/configuration;
- checkpoint secret or signer service state.

For that threat level, move signing and monotonic anchoring into a stronger OS/TPM/HSM/service boundary.

Python object privacy is also not a security sandbox. Before a background Reflection Worker is enabled, it must not run in the same trust context with direct access to checkpoint key material. It should receive only a narrow staging IPC/capability.

## Acceptance tests

Phase 3.1 tests cover:

1. valid store + authenticated checkpoint passes;
2. startup without an authenticated checkpoint fails closed;
3. partial ledger mutation fails;
4. candidate/version mutation fails even when the ledger is untouched;
5. complete database replacement without the checkpoint key fails;
6. rollback to an older internally valid DB is detected;
7. wrong and missing keys fail closed;
8. key rotation preserves verification after retiring the old secret;
9. historical checkpoint tamper is detected after old-key retirement;
10. learner gateway exposes only `stage()` and fixes learner actor/reason provenance;
11. journal does not contain raw candidate content, raw experience summary, or key material.

## Still intentionally absent

Phase 3.1 does not add:

- background LLM reflection;
- automatic candidate generation;
- automatic promotion;
- Network/Security remediation;
- shell execution;
- Internet access;
- credential access;
- Git mutation;
- arbitrary checkpoint signing by a model;
- automatic forward-signing during crash recovery.

## Gate before Phase 4

A real unattended Reflection Worker may be implemented only after deployment preserves this separation:

```text
Reflection identity/process
  -> stage-only IPC
  X no checkpoint key
  X no operator gateway
  X no learning DB direct write
  X no shell/network/credential/Git authority

Trusted checkpoint service/process
  -> verify current state
  -> serialize allowed mutation
  -> authenticate exact new state
```

Phase 4 remains proposal-only. `stage()` is the maximum autonomous persistence authority planned for its first release.
