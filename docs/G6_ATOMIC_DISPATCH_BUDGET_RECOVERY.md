# G6 Atomic Dispatch Budget Recovery

Status: implementation candidate

## Purpose

G6 closes one specific crash-consistency gap in the existing WorkSpace execution runtime:

```text
old path
runtime revalidation
  -> persistent step reservation
  -> dispatch checkpoint
```

A failure between the persistent step reservation and the dispatch checkpoint could consume a task step even though no durable dispatch existed. A retry could then consume another step.

G6 does not replace the scheduler, checkpoint model, TaskStore, capability authority, writer lease, or execution budget. It strengthens the existing production composition boundary.

## Canonical transaction

For a new production dispatch, one SQLite `BEGIN IMMEDIATE` transaction now contains:

```text
current RuntimeWriterLease revalidation
  -> canonical task_execution_budget_usage step check/update
  -> execution_dispatch_budget_reservations insert
  -> execution_dispatch_checkpoints insert
  -> DISPATCH_RECORDED event
  -> WRITER_FENCE_BOUND event
  -> COMMIT
```

Any exception before commit rolls back every mutation above.

`task_execution_budget_usage` remains the only source of truth for execution-budget limits and counters. `execution_dispatch_budget_reservations` is only a deterministic idempotency/audit index. It cannot grant or enlarge budget authority.

## Scheduler compatibility

`ExecutionScheduler` is intentionally unchanged.

The G6 production composition supplies a `DispatchBudgetPreflightGuard`. Its `reserve(steps=1)` call performs only a non-mutating deadline/availability preflight. The authoritative step mutation occurs inside the writer-fenced checkpoint transaction.

Standalone scheduler users keep their existing `SchedulerBudgetGuard` behavior. Only the canonical production composition receives G6 atomic semantics.

## Failure invariants

1. **Checkpoint failure cannot burn a step**
   - If budget update succeeds inside the transaction but checkpoint/event persistence fails, the step update and reservation roll back.

2. **Budget denial cannot create a dispatch**
   - Step exhaustion or wall-time expiry occurs before any durable dispatch state is committed.

3. **Exact replay is idempotent**
   - A repeated exact persisted ticket requires the exact existing G6 reservation and does not increment `steps_used`.

4. **Concurrent exact first-write converges**
   - SQLite writer serialization plus exact receipt comparison produces one dispatch checkpoint, one reservation, and one task-step charge.

5. **Writer fencing remains authoritative**
   - Stale writer generations are rejected in the same write transaction before budget/checkpoint mutation.

6. **Settlement is not a dispatch**
   - Observation persistence and cancellation do not consume dispatch-step budget.

7. **Restart never invents authority**
   - Same-run restart restores the durable dispatch as `RECOVERY_REQUIRED`; it does not replay work or reserve another step.

## Legacy G5 compatibility

A dispatch persisted by the pre-G6 writer-fenced repository has no G6 reservation row. G6 treats that state conservatively:

- normal checkpoint load/recovery remains allowed;
- late canonical observation settlement remains allowed under the same writer generation;
- no synthetic second step is charged;
- attempting to replay the old dispatch through the new G6 write boundary fails closed with `DISPATCH_BUDGET_RESERVATION_MISSING` rather than fabricating a reservation.

This preserves recovery without silently rewriting historical accounting.

## Metadata / confidentiality

A G6 reservation contains only:

- schema version;
- task ID;
- plan fingerprint;
- node ID;
- node fingerprint;
- authority fingerprint;
- fixed `steps=1`;
- reservation timestamp and content digest in the table record.

It does not store request text, prompts, model output, evidence bodies, credentials, secrets, or provider payloads.

## Ten-lane acceptance matrix

| Lane | Weight | Boundary | Acceptance evidence |
| --- | ---: | --- | --- |
| L1 | 10% | Canonical budget binding | Same TaskStore DB and same `TaskExecutionBudgetState`; no second budget counter system |
| L2 | 10% | Atomic dispatch adapter | Existing scheduler unchanged; production composition uses preflight + atomic writer-fenced repository |
| L3 | 10% | Crash rollback | Failure injected after budget mutation rolls back budget, reservation, checkpoint and event state |
| L4 | 10% | Restart/idempotency | Same run restart and exact ticket replay do not double-charge |
| L5 | 10% | Concurrency | Concurrent exact first-write converges to one charge/checkpoint/reservation |
| L6 | 10% | Cancellation | Cancellation persists without consuming a dispatch step |
| L7 | 10% | Observation settlement | Canonical late/normal observation settlement consumes no extra dispatch step |
| L8 | 10% | Fail-closed taxonomy/privacy | Exhaustion/deadline/conflict paths use compact reason codes and reservation metadata excludes request text |
| L9 | 10% | Backward compatibility | G5 checkpoint recovery/settlement works; historical reservation is never invented |
| L10 | 10% | Promotion gate | Exact-head CI, Python 3.11/3.12 runtime regression, live-main refresh and mergeability verification |

No lane earns completion credit for planning, code reading, waiting for CI, or an unverified branch.

## Promotion rule

G6 may move from draft to ready only when the exact PR head passes all applicable repository CI gates and the PR is re-evaluated against current `main`. If concurrent `main` changes alter the merge candidate, the candidate must be reconciled and re-tested; prior exact-head CI is not inherited by a changed head.
