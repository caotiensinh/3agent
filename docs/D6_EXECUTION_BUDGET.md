# D6-03 — Persistent Hard Retry / Escalation Budget

## Status

Implemented as the deterministic execution boundary for model fallback paths.

## Authority

The immutable bound `TaskContract.execution_budget` is the only source of:

- `max_retries`;
- `max_escalations`.

No model client, worker pool, prompt, environment variable or caller can increase these limits after contract binding.

## Persistent task-wide accounting

WorkSpace stores retry/escalation usage in the task SQLite database. The record is bound from the already-bound TaskContract and is idempotent across process restart.

The budget is task-wide, not stage-wide:

```text
TaskContract
    ↓
persistent TaskStore budget
    ↓
Research inference scope
    ↓
Presentation inference scope
```

Research and Presentation therefore consume the same counters. Restarting the process or constructing a new model client does not reset usage.

Daily Report is date-wide reporting, not a validator or execution stage of the task-specific Research → Presentation contract, and does not consume that task budget.

## Reserve-before-call rule

Every actual failure-driven model retry reserves one retry **before** the second model invocation.

A primary → stronger-model fallback reserves one retry plus one escalation atomically **before** the stronger model is invoked.

If reservation would exceed either limit:

- the reservation fails closed with `MODEL_RETRY_BUDGET_EXHAUSTED` or `MODEL_ESCALATION_BUDGET_EXHAUSTED`;
- no fallback model call occurs;
- no retry/escalation telemetry event is emitted for an invocation that did not happen;
- already consumed usage remains unchanged.

Planned deep-model selection based on deterministic routing is not counted as an escalation. Resource admission denial never creates an upward escalation.

## Isolation

Execution budget state is passed directly through the trusted `inference_scope` for the authoritative task. There is no process-global lookup by task ID. Two benchmark sandboxes may therefore contain the same deterministic task ID without sharing or colliding budget state.

## Privacy

Persistent budget rows and workflow manifests contain counters and limits only. They do not contain prompts, responses, evidence bodies, URLs, commands, credentials or business text.

## Regression requirements

Tests must prove:

1. budget cannot bind before TaskContract;
2. limits are derived from TaskContract rather than caller input;
3. usage survives TaskStore/wrapper reconstruction;
4. identical task IDs in separate databases remain isolated;
5. a budget wrapper cannot be attached to a different task scope;
6. exhausted escalation blocks the stronger model before invocation;
7. denied fallback does not manufacture resource telemetry;
8. Runtime Validator Bridge binds the persistent budget before recording policy PASS.
