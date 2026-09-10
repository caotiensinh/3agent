# Adaptive Learning Phase 4F — secure operator bootstrap and recovery lifecycle

## Status

Phase 4F closes the production initialization gap left intentionally by Phase 4D. Runtime retrieval remains disabled by default and never bootstraps itself.

## Core invariant

> Bootstrap is an explicit local operator ceremony, never a runtime or learner capability.

Phase 4F reuses the existing:

- `AdaptiveLearningStore` for fresh store creation;
- `HmacCheckpointKeyring.from_files()` for the private POSIX key-file provider;
- `LearningCheckpointAuthority.bootstrap()` for genesis checkpoint creation;
- `LearningCheckpointAuthority.verify()` for integrity/freshness verification;
- Phase 4D read-only runtime binding for later retrieval.

It does not add a second store format, signing primitive, checkpoint implementation, repair path, or rebaseline API.

## Bootstrap flow

```text
operator invokes workspace-learning-admin bootstrap
        |
        v
validate store-id / key-id / four distinct paths
        |
        v
require POSIX file-key provider
        |
        v
require every target absent before mutation
        |
        v
create private parent directory when new
        |
        v
create random private key atomically (0600)
        |
        v
create fresh AdaptiveLearningStore
        |
        v
load exact key through HmacCheckpointKeyring.from_files()
        |
        v
LearningCheckpointAuthority.bootstrap()
        |
        v
LearningCheckpointAuthority.verify()
        |
        v
metadata-only receipt
        |
        STOP
```

## No-overwrite rule

The store DB, checkpoint journal, trusted-head witness and key file must all be absent before the first mutation. If any target already exists, bootstrap fails before creating any other target.

There is deliberately no `--force`, reset, repair or rebaseline option.

A second bootstrap attempt against an existing generation fails closed and leaves the existing authenticated generation unchanged.

## Key boundary

The current Phase 3.1 provider is POSIX-only. Bootstrap therefore fails closed on non-POSIX platforms instead of inventing Windows key protection.

The generated HMAC key:

- comes from Python `secrets.token_bytes`, backed by the operating-system CSPRNG;
- is at least 32 bytes;
- is created using exclusive creation and `O_NOFOLLOW` where supported;
- is written with mode `0600` before it is loaded by the existing keyring;
- is never emitted in the receipt or normal output.

Windows DPAPI/CNG/TPM support remains a separate reviewed phase.

## Filesystem boundary

Phase 4F rejects colliding store/journal/witness/key targets.

When an immediate parent directory did not exist, it is created and set private (`0700`) on POSIX. Existing operator directories are not recursively chmodded.

Failure cleanup removes only ceremony target files that Phase 4F created. Pre-existing files are never deleted.

## Verification flow

`workspace-learning-admin verify` is read-only:

```text
existing private DB + key + journal + witness
        |
        v
ReadOnlyAdaptiveLearningStore
        |
        v
HmacCheckpointKeyring.from_files()
        |
        v
LearningCheckpointAuthority.verify()
        |
        v
metadata-only receipt
```

Verification never bootstraps, repairs, rotates a key, advances a checkpoint, restores a witness or changes active learning state.

Stale/tampered DB, journal, witness, wrong key or store-ID mismatch remains a hard failure.

## Receipt

Bootstrap/verify output contains only bounded metadata:

- schema version;
- store ID;
- active key ID;
- checkpoint sequence;
- checkpoint SHA-256;
- state SHA-256;
- ledger entry count;
- version count.

It contains no:

- key bytes;
- HMAC/MAC values;
- filesystem paths;
- raw candidate content;
- raw evidence;
- credentials;
- session/OAuth tokens;
- DB contents.

## Phase 4D compatibility

A generation created by Phase 4F can be explicitly referenced by the existing Phase 4D `adaptive_learning.runtime_retrieval` configuration. Runtime retrieval remains disabled unless the operator separately enables that configuration.

Normal `Orchestrator` construction does not call Phase 4F and no adaptive-learning filesystem path is touched when Phase 4D retrieval is disabled.

## CLI

Fresh bootstrap:

```bash
workspace-learning-admin bootstrap \
  --store /private/workspace-learning/learning.db \
  --journal /private/workspace-learning/checkpoint/journal.jsonl \
  --witness /private/workspace-learning/trusted-head/head.json \
  --key-file /private/workspace-learning/keys/checkpoint.key \
  --store-id learning-store:workspace \
  --key-id key:v1
```

Read-only verification:

```bash
workspace-learning-admin verify \
  --store /private/workspace-learning/learning.db \
  --journal /private/workspace-learning/checkpoint/journal.jsonl \
  --witness /private/workspace-learning/trusted-head/head.json \
  --key-file /private/workspace-learning/keys/checkpoint.key \
  --store-id learning-store:workspace \
  --key-id key:v1
```

These are operator commands. They are not exposed to the learner, Reflection Worker, Research Agent or normal runtime capability surface.

## Non-goals

Phase 4F does not implement:

- background learning or scheduling;
- automatic promotion/adoption;
- automatic remediation;
- model-weight training/fine-tuning;
- embeddings/vector DB;
- public/LAN learning egress;
- Windows DPAPI/CNG/TPM key provider;
- automatic backup restoration;
- stale-state rebaseline;
- runtime configuration mutation;
- Git/deployment authority;
- trusted-core mutation from learned content.
