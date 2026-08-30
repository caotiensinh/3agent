# Workflow V4 SQLite execution-budget concurrency

## Scope

Workflow V4 may execute independent lanes in parallel, but all child lanes share one authoritative SQLite task database and one aggregate parent execution budget. The model/research/presentation work remains parallel; only the short execution-budget bind/reserve transactions are serialized per database path.

## Failure that motivated this boundary

Windows clean-install/idempotent CI reproduced `sqlite3.OperationalError: database is locked` while two parallel Workflow V4 lanes attempted `BEGIN IMMEDIATE` against the shared `task_execution_budget_usage` table. The first clean install passed; the concurrent rerun exposed the write-contention race.

## Runtime contract

- `sqlite_budget_guard.run_budget_write()` is the single process-local guard for execution-budget write transactions.
- Distinct `TaskStore` objects resolving to the same database path share one re-entrant lock.
- `TaskExecutionBudgetState.from_bound_contract()` and `.reserve()` use the guard.
- `LinkedTaskExecutionBudgetState.reserve()` keeps parent + child projection/update in the same SQLite transaction and uses the same guard.
- SQLite `database is locked` / `database is busy` errors from another process receive only a bounded retry; unrelated `OperationalError` values are never retried.
- Exhaustion/deadline reason codes and immutable TaskContract limits are unchanged.
- This guard does not grant additional steps, tool calls, retries, escalations, wall time, model authority, network authority, or execution authority.

## Parallelism boundary

The guard does **not** serialize model inference or Workflow V4 lane execution. It serializes only the SQLite budget write critical section so two local lanes cannot race an aggregate budget transaction.

## Regression evidence

`tests/test_sqlite_budget_guard.py` covers:

1. separate `TaskStore` instances sharing the same database lock;
2. bounded retry only for SQLite lock/busy contention;
3. no retry for unrelated SQLite operational failures;
4. eight concurrent linked child reservations producing exactly eight parent step reservations and exactly one child step per child.

Windows deployment/idempotent CI remains a mandatory gate because Windows file/database locking has previously exposed lifecycle and concurrency failures that Linux did not.

## Live multi-turn acceptance config

The trusted self-hosted live acceptance workflow resolves its default config from the exact checked-out source:

```text
$GITHUB_WORKSPACE/config/workspace.secure.json
```

An explicit repository variable override remains supported. The workflow must not fall back to the runner service user's `$HOME`, and it does not print the configuration contents. The acceptance runner rewrites mutable data paths to its temporary sandbox and disables Internet/execution gateways before local-model evaluation.
