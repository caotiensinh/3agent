# Persistent Capability Revocation v1

Status: **D0-03 / PICO-03 closure baseline**

WorkSpace capability authority is derived from an immutable TaskContract and may only become narrower after binding. This baseline adds persistent operator-driven revocation without adding any restore or privilege-expansion path.

## Authority order

```text
TaskContract allowed capability
  -> TaskCapabilityAuthority resource/effect decision
  -> persistent task-scoped revocation check
  -> execution/tool-call budget
  -> telemetry
  -> side effect
```

Revocation is a second deny layer. It cannot grant a capability that the TaskContract did not grant.

## Persistent state

`TaskCapabilityRevocationStore` persists one row per `(task_id, capability)` in the same task SQLite database.

A revocation:

- requires an already-bound TaskContract;
- may target only a capability present in that exact bound contract;
- is insert-only and idempotent;
- survives process restart;
- is task-scoped;
- contains only capability, compact reason code and timestamp;
- has no restore/unrevoke mutation in v1.

The default operator reason is `OPERATOR_REVOKED`.

## Live scope behavior

Production task scopes already carry `TaskExecutionBudgetState`, which holds the authoritative task store. The metered capability boundary reads revocation state on every scoped capability call.

This is intentionally a **live** check rather than a scope-start snapshot. If an operator revokes `run_tests` while Research is already running, the next `run_tests` gateway call fails with `CAPABILITY_REVOKED` before tool-budget consumption, telemetry or command execution.

Task-end expiry remains structural: task authority exists only for the exact task/scope. Persistent revocation rows do not create authority after the task is complete.

## Operator command

```text
workspace-capability revoke TASK_ID CAPABILITY
workspace-capability revoke TASK_ID CAPABILITY --reason INCIDENT_REVOKED
workspace-capability list TASK_ID
```

There is intentionally no `restore`, `unrevoke`, or `allow` command. A wider authority envelope requires a new task/contract, not mutation of the old one.

## Security invariants

1. Revocation can only narrow immutable TaskContract authority.
2. Revocation is effective across process restart.
3. Revocation is effective inside an already-active production scope on the next capability call.
4. Revoked calls consume no tool-call budget and emit no successful tool-call telemetry.
5. Revocation is task-scoped and cannot revoke the same capability globally by accident.
6. Raw prompts, tool argv, URLs, evidence and credentials are not stored in revocation state.
7. No model or retrieved content can invoke a restore path because no restore path exists.
