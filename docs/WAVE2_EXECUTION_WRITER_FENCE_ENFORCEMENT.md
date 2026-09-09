# Wave 2 — Execution Writer-Fence Enforcement

## Status

Wave 2 strengthens the existing WorkSpace execution persistence boundary. It does **not** replace the execution architecture.

Existing components remain canonical:

- `ExecutionScheduler` remains the stateful dispatch coordinator.
- `RuntimeScheduler` remains the pure DAG/admission evaluator.
- `ExecutionCheckpointRepository` remains the canonical checkpoint storage model.
- `TaskStore` remains the SQLite persistence foundation.
- `RuntimeWriterLeaseRepository` remains the writer-generation authority introduced in Wave 1.

Wave 2 adds `WriterFencedExecutionCheckpointRepository`, a security adapter over the existing checkpoint repository.

## Design rule

> Preserve the working architecture. Strengthen the weakest trust boundary with the smallest deterministic control that closes the identified failure mode.

This wave therefore does not create another scheduler, another database, another checkpoint schema, or another capability authority.

## Threat being closed

Without writer-generation enforcement, an older process can remain alive after a newer run supersedes it and can still attempt to persist:

- a dispatch,
- an observation,
- a cancellation,
- or an idempotent replay of a previous write.

A simple pre-check is insufficient because it creates a check-then-use race.

## Enforcement model

Every protected checkpoint mutation executes under the existing SQLite `BEGIN IMMEDIATE` transaction:

1. validate task and plan scope;
2. validate the exact ACTIVE `RuntimeWriterLease` in the same transaction;
3. execute the existing checkpoint mutation;
4. append the existing canonical checkpoint event;
5. immediately append a `WRITER_FENCE_BOUND` receipt to the same tamper-evident event chain;
6. commit.

There is no gap between writer validation and persistence.

## Fence receipt

Each receipt uses schema:

`workspace-execution-writer-fence/v1`

and records only metadata:

- subject kind;
- writer run ID;
- monotonic writer generation;
- writer lease fingerprint.

It does not copy model prompts, outputs, credentials, packet payloads, or other confidential content.

## Dispatch settlement invariant

An observation may settle a dispatch only when its writer binding matches the dispatch binding exactly:

`run_id + generation + writer_lease_fingerprint`

Consequences:

- same ACTIVE run restarted after process failure can resume its own unfinished dispatch;
- stale run cannot write after supersession;
- newly superseding run cannot silently finish an older generation's in-flight dispatch;
- unresolved cross-generation work remains `RECOVERY_REQUIRED` and requires explicit reconciliation.

This is stricter than merely checking that the caller is the current writer.

## Event-chain invariant

For writer-fenced execution, every protected event must be followed immediately by its fence receipt:

```text
DISPATCH_RECORDED
WRITER_FENCE_BOUND

OBSERVATION_RECORDED
WRITER_FENCE_BOUND

CANCELLED
WRITER_FENCE_BOUND
```

Because both rows are inserted under the same SQLite write transaction, another writer cannot interleave a row between the protected event and its binding receipt.

`verify_writer_fence_bindings()` checks this structure in addition to the existing checkpoint hash chain.

## Legacy checkpoint policy

Pre-Wave-2 checkpoints do not contain writer bindings. They are not silently upgraded or guessed.

When a writer-fenced repository encounters an unfenced historical checkpoint, it fails closed with:

`EXECUTION_WRITER_FENCE_BINDINGS_INVALID`

Required handling is explicit migration/manual reconciliation. This prevents historical state with unknown writer provenance from being treated as generation-bound evidence.

## Compatibility

The adapter implements the same persistence protocol already consumed by `ExecutionScheduler`:

- `initialize()`
- `load()`
- `record_dispatch()`
- `record_observation()`
- `record_cancellation()`

Therefore `ExecutionScheduler` does not need a parallel implementation or architecture rewrite.

## Failure behavior

All persistence paths fail closed when:

- writer lease is stale;
- writer lease is released;
- writer task scope differs;
- writer plan scope differs;
- writer binding is missing;
- writer binding is malformed;
- event adjacency is broken;
- observation generation differs from dispatch generation;
- the existing checkpoint event chain is invalid.

## Migration sequence

1. Merge Wave 1 writer lease foundation.
2. Introduce the writer-fenced checkpoint adapter.
3. Prove scheduler compatibility and negative cases.
4. Move execution call sites to the writer-fenced repository.
5. Measure remaining direct uses of unfenced `ExecutionCheckpointRepository`.
6. Only after adoption is complete, consider folding enforcement into the canonical repository implementation.

The final fold-in must be evidence-driven and must not break existing recovery semantics.

## Non-goals

Wave 2 does not:

- replace `ExecutionScheduler`;
- change DAG semantics;
- change capability authority;
- widen tool permissions;
- add Internet access;
- change the Confidential Core trust boundary;
- auto-replay recovery-required work;
- migrate legacy checkpoints automatically;
- authorize a new generation to settle an old generation's unfinished dispatch.

## Acceptance gates

Wave 2 is not complete until CI proves at least:

- existing scheduler works unchanged with the fenced repository;
- stale writer observation is rejected;
- superseding generation cannot settle old dispatch;
- same ACTIVE run can restart and settle its own dispatch;
- stale writer idempotent replay is rejected;
- legacy unfenced checkpoint is rejected for manual migration;
- cancellation is generation-fenced;
- checkpoint hash-chain remains valid;
- writer-fence binding chain remains valid;
- Python 3.11 and 3.12 full harness regression is green;
- Internet-egress security gate remains green.
