# WorkSpace Workflow V4 Security Contract

## Scope

Workflow V4 extends the hardened V3 manual low-risk state machine with one bounded parallel DAG region while preserving the current deterministic multi-turn context boundary from `chat_gateway_v16`. The production composition lives in `chat_gateway_v17`.

It does not add scheduler/event authority, arbitrary condition execution, shell authority, credential authority, new network paths, or a second general-purpose orchestrator.

The executable `ver.0.0.1` slice is deliberately bounded:

- trigger: `manual` only;
- risk: `low` only;
- active confidentiality zone must exactly match workflow `data_class`;
- at most one executable parallel region;
- exactly two parallel lanes and two orchestration workers;
- each lane is fixed to `research -> presentation`;
- exactly one deterministic `parallel_join`;
- join is followed immediately by a deterministic `passed|failed` decision;
- all parallel children must complete and verify for the aggregate outcome to pass;
- any unverified child forces the terminal failed output branch;
- nested parallelism and dynamic fan-out are prohibited;
- interrupted active parallel regions are not automatically replayed.

## Aggregate execution-budget authority

Parallelism may reduce wall-clock latency, but it must not multiply authority. The parent TaskContract remains the aggregate execution ceiling for the complete workflow. Each parallel child also has its own immutable canonical TaskContract for isolation and independent validation, but every child reservation is charged to both its child budget and the parent budget.

Charged dimensions are steps, tool calls, model retries, model escalations and wall-time validity.

Parent and child rows are read and validated inside one SQLite `BEGIN IMMEDIATE` transaction before either counter is updated. If the parent or child rejects the reservation, the transaction rolls back and no partial counter consumption is committed. This prevents two worker threads from racing beyond the aggregate cap.

A child model/tool path receives the linked budget through the ordinary inference scope, so existing metered model and gateway code charges the aggregate parent without trusting prompt/model output.

## Multi-turn context compatibility

`chat_gateway_v16` remains the independently tested reference-gated context layer. `chat_gateway_v17` subclasses that handler and uses `ContextAwareProjectChatService` as the production chat service.

V4 therefore cannot silently widen conversation history use. The following v16 invariants remain in force:

- current request has precedence;
- prior context is reference-gated;
- only completed eligible history is injected;
- standalone requests do not receive history automatically;
- follow-up language continuity remains deterministic;
- missing referenced context is represented as unavailable rather than invented.

## Child isolation

Each lane receives a distinct child task ID. Child TaskContract, execution counters, model authority, validator results, status and artifacts remain scoped to that child. The parent does not share mutable validator state with either lane.

The join receives only compact child identity and verified/unverified metadata. Raw prompts, model responses and tool output are not copied into the parent join state.

## Deterministic join

The join is not an LLM operation. It evaluates authoritative child validation states only:

- all children verified -> aggregate `passed`;
- any child unverified or runtime-blocked -> aggregate `failed`.

The aggregate result is recorded into the parent Validator Ledger. The failed branch must terminate directly at an output node and cannot reach Daily Report or approval side effects.

## Approval and restart safety

The V3 durable approval checkpoint semantics remain authoritative after a successful join. The exact checkpoint fingerprint is required for resume, and consumed checkpoints cannot be replayed.

An active parallel region interrupted by process failure is deliberately not replayed automatically. This avoids duplicate side effects where the exact completion state of a child model/tool call is unknown.

## Versioning

The user-facing release is `ver.0.0.1`. Python package metadata uses the PEP 440 epoch form `1!0.0.1` so upgrades from the historical package line through `0.18.0` remain monotonic. The epoch is not shown as the product version.

## Explicit non-goals

`ver.0.0.1` does not authorize schedule/event execution, more than two parallel lanes, nested parallel regions, dynamic fan-out, arbitrary branch expressions, automatic replay of interrupted active parallel work, medium/high/critical-risk workflow execution, new tools/shell/credential access, additional network authority, additional model tiers, extra retry/escalation allowance created by child tasks, or unrestricted conversation-history injection.
