# WorkSpace Workflow Dispatch V2

## Purpose

Workflow Studio V1 converts an untrusted natural-language process description into a validated workflow contract plus Mermaid/SVG diagrams. V2 adds a deliberately narrow execution admission boundary without turning arbitrary diagrams into runtime authority.

The security rule is:

```text
Diagram is intent.
Dispatch Admission is authority.
WorkflowRunner is execution.
Validator Ledger is completion evidence.
```

A workflow that can be drawn is not necessarily executable.

## V2 execution path

```text
Natural-language description
        |
        v
Workflow Studio V1
        |
        v
Validated workflow contract + diagram
        |
        v
Dispatch Admission Controller
        |
        +-- BLOCKED_BY_ADMISSION --> design remains usable
        |
        v
Create Task + bind authoritative TaskContract
        |
        v
Canonical workflow fingerprint
+ TaskContract fingerprint
+ execution profile
        |
        v
Approval fingerprint
        |
        v
Administrator explicitly types AUTHORIZE
        |
        v
Existing WorkflowRunner
        |
        v
Execution budget + model authority + validators
        |
        v
Verified result / failed result
```

V2 does not add another orchestration framework, model, daemon, database, scheduler, diagram package, or external API.

## Executable slice in V2

V2 admits only workflows that exactly match capabilities already implemented by the existing WorkSpace runtime:

- trigger: `manual` only;
- risk: `low` only;
- data class: must exactly match the active WorkSpace confidentiality zone;
- graph: one connected linear chain, no branching or joins;
- conditions: none;
- business approval nodes: none;
- manual/unknown steps: none;
- output format: `pptx`;
- administrator approval: required before execution.

Supported action profiles are:

```text
input -> research -> presentation -> daily_report -> output
```

and:

```text
input -> research -> validate -> presentation -> daily_report -> output
```

The explicit `validate` node represents the deterministic runtime validation boundary; it does not create a new executable tool.

## Design-only features in V2

The following remain valid Workflow Studio design concepts but are blocked from execution admission:

- schedule triggers;
- event triggers;
- medium/high/critical risk;
- decision nodes and conditional branches;
- branch joins or parallel execution;
- `manual_step`;
- mid-workflow `human_approval`;
- arbitrary tool/action names;
- workflow data classes that do not match the active runtime zone;
- secret workflows (Workflow Studio V1 has no `secret` data-class representation);
- arbitrary shell/network/filesystem/credential authority.

This is intentional. V2 must not pretend the runtime supports pause/resume, scheduling, arbitrary DAG execution, or business-approval semantics that do not yet exist.

## Approval binding

Preparation creates a normal WorkSpace task and deterministically compiles the exact low-risk `analysis` TaskContract used by the current `RuntimeValidatorBridge`. The contract is bound before authorization.

WorkSpace then creates an approval fingerprint over compact immutable identifiers:

- dispatch schema version;
- task ID;
- canonical workflow SHA-256;
- bound TaskContract SHA-256;
- execution profile ID.

Execution requires all of the following:

1. administrator role;
2. prepared dispatch state;
3. exact approval fingerprint;
4. explicit `AUTHORIZE` confirmation;
5. one-time state transition from `prepared` to `executing`.

After the transition, the same preparation cannot be replayed. A successful or failed run is terminal for that dispatch record.

The approver is stored in dispatch audit metadata only as a SHA-256 reference, not as a raw username/email.

## Runtime reuse

V2 calls the existing `WorkflowRunner.run_task()` rather than implementing a second executor. Therefore existing controls remain authoritative:

- immutable TaskContract binding;
- persistent execution budgets;
- bounded model authority;
- inference scope;
- research evidence validation;
- presentation schema validation;
- validator ledger;
- verified completion gate;
- metadata-only security audit behavior.

The Dispatch layer cannot grant capabilities not present in the TaskContract or runtime configuration.

## Persistence

The dispatch preparation record is stored under the local WorkSpace artifact root as compact metadata. It contains fingerprints, action identifiers, bounded presentation options, risk/sensitivity, status, and the hashed approver reference.

The dispatch record does not store the full workflow graph, node labels, natural-language description, credentials, prompts, tool output, or model response.

## Future versions

A later version may add capabilities only after their runtime semantics exist and are independently tested. Likely stages are:

1. resumable human approval checkpoints;
2. deterministic branching/condition evaluator;
3. bounded parallel DAG execution;
4. scheduler/event broker as a separate authority boundary;
5. additional capability-specific executors.

No future workflow feature should infer execution authority from diagram syntax or model output.
