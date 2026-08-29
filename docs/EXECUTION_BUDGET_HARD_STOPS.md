# WorkSpace Complete Execution Budget Hard Stops v1

Status: **D0-04 baseline security boundary**

## Purpose

A `TaskContract` execution budget is authoritative only if every live runtime path consumes the same persistent task-wide state and cannot reset limits by changing stage or restarting the process.

WorkSpace v1 therefore enforces one SQLite-backed budget envelope for:

- workflow steps;
- tool/gateway calls;
- model retries;
- model escalations;
- wall-clock deadline.

The immutable source is always `TaskContract.execution_budget`:

```text
TaskContract
  -> persistent task_execution_budget_usage
  -> Research / Presentation / direct stage / NO_LLM step reservations
  -> tool-call reservations
  -> model retry/escalation reservations
  -> wall-time checks
  -> validator gate
  -> DONE only while deadline is still active
```

## Persistent limits and usage

The task-wide state stores:

- `max_steps` / `steps_used`;
- `max_tool_calls` / `tool_calls_used`;
- `max_retries` / `retries_used`;
- `max_escalations` / `escalations_used`;
- `max_wall_time_ms`;
- immutable `deadline_at` derived from the first budget bind;
- `bound_at` / `updated_at`.

All limits are read from the already-bound immutable TaskContract. Callers cannot supply a larger runtime limit.

Reservations run under `BEGIN IMMEDIATE`. All requested dimensions are checked before one update, so a failed multi-dimensional reservation cannot partially consume another dimension.

## Restart and migration behavior

Process restart does not reset counters or deadline.

Older D6 retry/escalation-only rows are forward-migrated in place. Their wall deadline is derived from the **original** `bound_at`, not from migration/restart time. Migration therefore cannot revive an expired task or silently extend its execution window.

## Step definition in v1

One top-level step is reserved before each currently controlled business execution stage:

- Research stage;
- Presentation stage;
- direct `workspace research` stage;
- direct `workspace presentation` stage;
- deterministic `NO_LLM` retrieval execution.

This keeps stage changes from resetting the task-wide step budget.

Daily Report remains intentionally outside the task-specific execution budget because it is date-wide reporting and is not a task validator or task-specific business execution stage.

## Tool-call definition in v1

The tool-call budget applies to authorized metered Internet and execution gateway invocations, which are the current side-effectful runtime capability boundaries.

Order is security-sensitive:

```text
capability authorization
  -> persistent tool-call reservation
  -> metadata-only tool telemetry
  -> inner gateway side effect
```

Consequences:

- an unauthorized capability attempt consumes no tool budget;
- an exhausted tool budget produces no inner side effect;
- an exhausted tool budget produces no misleading successful tool-call event.

Deterministic in-process map/search/packing operations are accounted as their enclosing top-level step in this baseline; they are not misrepresented as external gateway calls.

## Model behavior

Before the first scoped model invocation, WorkSpace checks the persistent wall-time deadline.

Retry and escalation reservations are also persistent and deadline-aware. A retry/escalation that would exceed any budget dimension is rejected before the secondary model invocation.

A stronger model cannot reset or increase the task execution budget.

## NO_LLM behavior

`NO_LLM` means zero model inference, not zero runtime governance.

Deterministic retrieval binds the same persistent TaskContract budget, reserves one step, checks the deadline after retrieval, and checks it again before final verification/DONE. It remains zero-inference while still obeying task-wide execution limits.

## Wall-time semantics and truthfulness boundary

`deadline_at` is absolute and does not reset on stage transitions or process restart.

Controlled model/tool/stage boundaries check the deadline before side effects, and final task completion checks it before `DONE`. Once the deadline is exhausted, no later authorized side effect or verified completion may proceed.

This baseline does **not** claim unsafe asynchronous thread termination or microsecond-precise preemption in the middle of an arbitrary CPU-bound Python function. Safe process-level isolation/preemption can be added later if representative workloads prove it necessary. Until then, the hard-stop guarantee is enforced at WorkSpace-controlled execution boundaries and completion gates.

## Typed exhaustion reasons

Normal budget exhaustion is surfaced as `ExecutionBudgetExceeded` with compact reason codes:

- `TASK_STEP_BUDGET_EXHAUSTED`;
- `TASK_TOOL_CALL_BUDGET_EXHAUSTED`;
- `TASK_WALL_TIME_BUDGET_EXHAUSTED`;
- `MODEL_RETRY_BUDGET_EXHAUSTED`;
- `MODEL_ESCALATION_BUDGET_EXHAUSTED`.

Malformed/corrupted persistent budget state remains a separate integrity error rather than being mislabeled as normal exhaustion.

## Security invariants

1. Budget maxima come only from immutable TaskContract state.
2. Stage changes and process restart cannot reset usage.
3. Deadline migration cannot extend the original wall-time window.
4. Multi-dimensional reservations are atomic.
5. Capability denial occurs before tool-budget consumption.
6. Tool-budget denial occurs before telemetry and side effects.
7. Initial model calls and fallback/escalation paths are deadline-aware.
8. NO_LLM retrieval cannot bypass execution budgets.
9. A task cannot be marked DONE after its wall-time deadline.
10. Budget metadata contains no prompt, response, evidence body, URL, argv or credential.
