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
- graph: one input root, acyclic, no branch joins;
- executable actions: `input`, `research`, `validate`, `human_approval`,
  `presentation`, `daily_report`, `output`;
- decision branches: exact `passed` / `failed` only;
- approval branches: exact `approved` / `rejected` only;
- all other natural-language conditions remain design-only;
- every executable branch terminates at an output node.

## Authority model

The authority chain is:

`Diagram -> V3 Admission -> TaskContract -> Initial ADMIN AUTHORIZE -> State Machine -> Validator/Approval Branch -> Verified Output`

A diagram is intent only. Node labels and model-generated text are data and cannot
become commands, capabilities, conditions, network authority, filesystem authority,
or credentials.

The V3 TaskContract keeps the same low-risk analysis capability/model boundary as
V2. The only runtime-budget difference is a bounded 24-hour wall-time window so a
human checkpoint can survive a realistic approval wait. Step, tool-call, retry and
model-escalation limits are unchanged. There is no unlimited pause.

## Persistent checkpoint

When an approval node is reached, V3:

1. persists the exact current node and completed-node set;
2. records the current TaskStatus;
3. derives a checkpoint fingerprint from task ID, workflow SHA-256,
   TaskContract SHA-256, approval node ID, state revision and completed-node hash;
4. changes the task to `WAITING_HUMAN`;
5. returns `paused` without executing downstream nodes.

A checkpoint can resume only when an administrator supplies the exact current
fingerprint and explicitly confirms `APPROVE` or `REJECT`. A consumed checkpoint
cannot be replayed. The approver is stored as a SHA-256 reference, not a raw user
identifier.

`APPROVE` restores the exact pre-pause TaskStatus and resumes from the selected
`approved` branch. `REJECT` selects only the `rejected` branch and never grants the
approved branch authority.

## Deterministic branching

V3 does not interpret free-form conditions with an LLM.

A `decision` node may branch only on the latest authoritative WorkSpace validator
result:

- `passed` -> the child whose condition is exactly `passed`;
- `failed` -> the child whose condition is exactly `failed`.

An `approval` node may branch only on the explicit human decision:

- `APPROVE` -> `approved`;
- `REJECT` -> `rejected`.

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
- public-query compiler and final egress DLP.

V3 does not introduce a second general-purpose orchestrator. The state machine only
chooses when an already-authorized capability may run and where execution resumes.

## Persistence and disclosure

The workflow contract and state are stored locally under the WorkSpace artifact
root. HTTP state responses are metadata-only: task ID, state, revision, current
node, completed node IDs, current checkpoint metadata, last validator result,
terminal reason and redacted error. Server filesystem paths, artifact paths, raw
prompts, raw tool output and raw approver identity are not returned.

A paused workflow can be recovered after a process/browser restart by loading its
Task ID. A workflow interrupted while an agent node itself is actively executing is
not automatically replayed; this is intentionally fail-closed to avoid duplicate
side effects.

## Explicit non-goals for V3.0

The following remain design-only:

- schedule/event triggers;
- arbitrary condition expressions;
- branch joins or parallel graph execution;
- manual-step execution;
- medium/high/critical risk execution;
- new tool/capability creation;
- shell commands derived from workflow text;
- arbitrary network access;
- approval by unauthenticated or non-admin identities;
- unlimited workflow lifetime.

These capabilities require separate contracts and tests rather than silent
expansion of V3 authority.
