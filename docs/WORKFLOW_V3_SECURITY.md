# WorkSpace Workflow V3 Security Contract

## Scope

Workflow V3 adds durable pause/resume and deterministic branching to the existing
Workflow Studio and Dispatch boundary. It does not add a scheduler, event listener,
new agent framework, shell authority, arbitrary tool execution, credentials, or a
new network path.

The executable V3.0 slice is deliberately bounded:

- trigger: `manual` only;
- risk: `low` only;
- active confidentiality zone must exactly match the workflow `data_class`;
- graph: one input root, connected, acyclic, no branch joins;
- exactly one Research, Presentation and Daily Report capability;
- executable actions: `input`, `research`, `validate`, `human_approval`,
  `presentation`, `daily_report`, `output`;
- decision branches: exact `passed` / `failed` only;
- approval branches: exact `approved` / `rejected` only;
- `failed` and `rejected` branches terminate directly at output;
- all other natural-language conditions remain design-only;
- every executable branch terminates at an output node.

## Authority model

The authority chain is:

`Diagram -> V3 Admission -> TaskContract -> Initial ADMIN AUTHORIZE -> State Machine -> Validator/Approval Branch -> Verified Output`

A diagram is intent only. Node labels and model-generated text are data and cannot
become commands, capabilities, conditions, network authority, filesystem authority,
or credentials.

The V3 TaskContract is derived from the canonical low-risk analysis contract. The
runtime bridge compares the complete authority envelope against that canonical
baseline. Allowed sources, tools, write scope, network scope, context/generation
budgets, validators, model policy, cache policy, logging policy and output schema
must remain identical. Step, tool-call, retry and escalation limits must also remain
identical. The only permitted difference is `max_wall_time_ms`, which may extend
from the canonical value to no more than 24 hours for a human checkpoint wait.
There is no unlimited pause.

## Persistent checkpoint

When an approval node is reached, V3:

1. persists the exact current node and completed-node set;
2. records the pre-pause TaskStatus;
3. derives a checkpoint fingerprint from task ID, workflow SHA-256,
   TaskContract SHA-256, approval node ID, state revision and completed-node hash;
4. changes the task to `WAITING_HUMAN`;
5. returns `paused` without executing downstream nodes.

A checkpoint can resume only when an administrator supplies the exact current
fingerprint and explicitly confirms `APPROVE` or `REJECT`. A consumed checkpoint
cannot be replayed. The approver is stored as a SHA-256 reference, not a raw user
identifier.

Both decisions consume the human checkpoint and restore the exact pre-pause
TaskStatus. `APPROVE` resumes only from the `approved` branch. `REJECT` selects only
the terminal `rejected` output branch and never grants approved-branch authority.

## Deterministic branching

V3 does not interpret free-form conditions with an LLM.

A `decision` node may branch only on the latest authoritative WorkSpace validator
result:

- `passed` -> the child whose condition is exactly `passed`;
- `failed` -> the terminal output child whose condition is exactly `failed`.

An `approval` node may branch only on the explicit human decision:

- `APPROVE` -> `approved`;
- `REJECT` -> terminal `rejected` output.

Unknown, duplicated, ambiguous or unsupported conditions fail admission before any
runtime action occurs.

## Runtime reuse

V3 reuses the existing:

- TaskContract compiler and immutable binding;
- execution budget counters;
- model-authority envelope;
- inference scopes;
- Research Agent;
- research evidence validator;
- Presentation Agent;
- presentation schema/lineage validator;
- Daily Report Agent;
- Validator Ledger;
- Prompt Compiler;
- public-query compiler and final egress DLP;
- intent-aware direct-chat and current-request language fidelity from WorkSpace 0.15.

V3 does not introduce a second general-purpose orchestrator. The state machine only
chooses when an already-authorized capability may run and where execution resumes.

## Restart and compiler-drift safety

A paused workflow can be recovered after a process/browser restart by loading its
Task ID. Before reusing model authority after restart, V3 deterministically rebuilds
the expected TaskContract and compares its canonical SHA-256 with the immutable
bound TaskContract SHA-256. Any compiler/configuration drift fails closed instead
of silently adopting new authority.

A workflow interrupted while an agent node itself is actively executing is not
automatically replayed. This avoids duplicate side effects. V3.0 guarantees durable
resume at human approval checkpoints, not transparent replay of partially completed
agent calls.

## Persistence and disclosure

The workflow contract and state are stored locally under the WorkSpace artifact
root using atomic replacement. On platforms that support POSIX modes, V3 attempts
to restrict these files to mode `0600`.

HTTP state responses are metadata-only: task ID, state, revision, current node,
completed node IDs, current checkpoint metadata, latest validator summary, terminal
reason and redacted error. Server filesystem paths, artifact paths, raw prompts, raw
tool output and raw approver identity are not returned.

## Explicit non-goals for V3.0

The following remain design-only:

- schedule/event triggers;
- arbitrary condition expressions;
- branch joins or parallel graph execution;
- manual-step execution;
- medium/high/critical risk execution;
- non-terminal failed/rejected branches;
- new tool/capability creation;
- shell commands derived from workflow text;
- arbitrary network access;
- approval by unauthenticated or non-admin identities;
- unlimited workflow lifetime.

These capabilities require separate contracts and tests rather than silent
expansion of V3 authority.
