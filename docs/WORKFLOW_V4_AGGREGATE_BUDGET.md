# WorkSpace ver.0.0.1 Workflow V4 Aggregate Budget Contract

## Purpose

Workflow V4 permits one bounded two-lane parallel region. Parallelism may reduce wall-clock latency; it must never multiply execution authority.

The parent TaskContract remains the aggregate authority ceiling for the complete workflow. Child tasks exist for isolation, lineage and independent validation only. They do not receive additional aggregate compute, tool, retry or escalation authority.

## Required invariant

For every parallel child reservation:

`effective_allow = parent_budget_allows AND child_budget_allows`

A reservation updates parent and child counters in one SQLite `BEGIN IMMEDIATE` transaction. Both rows are validated before either row is changed. If either side rejects the reservation, the transaction rolls back and neither counter is partially consumed.

## Covered dimensions

The linked budget covers:

- workflow/model steps;
- tool calls;
- model retries;
- model escalations;
- wall-time validity.

The child keeps its own immutable TaskContract limits. The parent keeps the aggregate workflow limits. The effective limit is therefore always the stricter remaining allowance at the moment of reservation.

## Concurrency safety

Both V4 lane threads share the same parent budget row. SQLite serializes linked reservations with `BEGIN IMMEDIATE`, so two lanes cannot read the same stale parent counter and both advance beyond the parent maximum.

Example with one parent step remaining:

1. Lane A and Lane B request one step concurrently.
2. One transaction acquires the write reservation first and consumes the final step.
3. The other transaction reads the updated parent row and receives `TASK_STEP_BUDGET_EXHAUSTED`.
4. The rejected child row remains unchanged.

## Runtime binding

The production `chat_gateway_v17` application instantiates `BudgetedWorkflowStateMachineV4Controller`. Gateway v17 layers on the current `chat_gateway_v16` deterministic multi-turn context service rather than replacing it.

When a lane starts, the controller binds:

- the parent persistent execution budget;
- the child canonical execution budget;
- the child model authority;
- a linked budget object exposed through the normal inference scope.

Because the linked object is the inference-scope execution budget, existing metered model and gateway code automatically charges parent + child for tool calls, retries and escalations. The model cannot bypass this relationship through prompt content.

## Failure behavior

Aggregate parent exhaustion is a runtime failure for the affected child lane. The child is marked failed. The deterministic parallel aggregate validator therefore produces `failed`, and the admitted V4 graph may only follow the terminal failed output branch. Daily report or approval-side downstream work cannot be reached from that failed branch.

No automatic replay is introduced.

## Explicit non-authority

This change does not add:

- more parallel lanes;
- dynamic fan-out;
- nested parallelism;
- scheduler or event triggers;
- new tools;
- new network authority;
- new model tiers;
- new retry/escalation capacity;
- shell or credential authority;
- additional conversation-history authority.

The purpose is solely to close budget multiplication while preserving the existing `ver.0.0.1` bounded-parallel topology and the current reference-gated multi-turn context boundary.
