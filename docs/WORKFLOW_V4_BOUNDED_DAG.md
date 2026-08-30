# WorkSpace Workflow V4 — `ver.0.0.1`

## Scope

`ver.0.0.1` is the first release in the new WorkSpace product-version line. Workflow V4 adds one **bounded parallel DAG region** on top of the hardened V3 authorization, deterministic branching, durable approval checkpoint model, and the current reference-gated multi-turn chat context layer.

It does **not** add scheduler/event authority, arbitrary conditions, nested parallelism, shell execution, a new agent framework, an external API, a CDN, or a new network path.

## Executable V4 slice

```text
parallel_fork
  |-- Research A -> Presentation A --|
  |-- Research B -> Presentation B --| -> parallel_join -> decision
                                                     |-- passed -> approved serial path
                                                     |-- failed -> terminal output
```

Hard limits:

- manual trigger only;
- low-risk only;
- workflow data class must equal the active WorkSpace confidentiality zone;
- one connected acyclic workflow;
- at most one executable parallel region;
- exactly two parallel lanes and at most two orchestration workers;
- each lane is exactly `research -> presentation`;
- one deterministic `parallel_join` barrier;
- join flows directly into deterministic `passed|failed` decision;
- failed branch terminates directly at output;
- approval checkpoints exist only outside the parallel region;
- nested forks/joins, arbitrary conditions, scheduler and event execution are blocked.

V3-compatible serial workflows remain executable under the V4 controller and retain existing restrictions.

## Authority model

```text
Diagram
  -> V4 deterministic admission
  -> parent TaskContract + aggregate budget
  -> exact ADMIN AUTHORIZE
  -> bounded state machine
  -> two isolated child TaskContracts
  -> linked parent+child reservations
  -> child validators
  -> deterministic aggregate validator result
  -> passed/failed branch
  -> optional durable approval
  -> verified output
```

A fork/join is a control primitive only. It never grants a model, tool, network, filesystem, credential, secret, or conversation-history capability.

## Child-task isolation and aggregate budget

The two lanes use distinct child tasks so they do not race on one status, validator history or artifact lineage. Each child keeps its own canonical TaskContract, model authority, inference scope, validator ledger and artifacts.

Execution authority is different: child counters are **linked** to the parent aggregate budget. Every steps/tool-calls/retries/escalations reservation must pass both parent and child limits and is committed atomically to both rows. Parent wall-time and child wall-time must both remain active.

Thus child isolation does not create extra aggregate compute/retry authority.

## Join semantics

`parallel_join` is an all-lanes deterministic barrier. It is not verified merely because both worker functions returned.

- `passed` — every child lane completed and independently verified;
- `failed` — at least one child is unverified, failed, or budget-blocked.

A failed aggregate result cannot enter Daily Report or approval. Admission requires the post-join failed branch to terminate directly at output.

## Concurrency and resource control

V4 uses a standard-library bounded worker pool with `max_workers=2`. Existing WorkSpace resource/model controls remain authoritative and may serialize or route actual model generation when GPU/RAM/VRAM policy requires it.

SQLite `BEGIN IMMEDIATE` serializes linked budget reservations so concurrent lanes cannot race past the parent's remaining authority.

## Multi-turn compatibility

Production gateway `chat_gateway_v17` layers V4 on the current `chat_gateway_v16` context service. Current-request precedence, reference-gated completed history, bounded context size, no history injection for standalone requests, follow-up language continuity, and missing-context fail-safe behavior remain unchanged.

## Failure and restart behavior

Human approval checkpoints retain V3 durable pause/resume semantics and exact checkpoint fingerprints.

If the process is interrupted after a parallel region is marked `starting` or `running`, WorkSpace does **not** automatically replay it. Re-running an active lane could duplicate side effects or create ambiguous artifact lineage. A fresh operator-controlled attempt is required.

## Explicit non-goals for `ver.0.0.1`

- schedule or event execution;
- cron/event daemon;
- more than two parallel lanes or one parallel region;
- nested parallelism or dynamic fan-out;
- approval inside a running parallel lane;
- arbitrary business-condition evaluation;
- medium/high/critical-risk workflow execution;
- automatic replay of interrupted active parallel work;
- new tool/capability creation from diagram labels;
- unrestricted prior-conversation injection.
