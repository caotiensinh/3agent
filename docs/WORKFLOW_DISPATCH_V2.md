# WorkSpace Workflow Dispatch V2

## Security statement

```text
Diagram is intent.
Dispatch Admission is authority.
WorkflowRunner is execution.
Validator Ledger is completion evidence.
```

Workflow Studio can describe and draw a process without granting any execution capability. Dispatch V2 is a separate deterministic admission layer and reuses the existing WorkSpace runtime rather than introducing another orchestrator.

## Execution path

```text
Natural-language workflow
  -> Workflow Studio contract + SVG/Mermaid
  -> deterministic Dispatch Admission
  -> create task
  -> compile and bind authoritative TaskContract
  -> workflow SHA + contract SHA + task ID + execution profile
  -> approval fingerprint
  -> administrator types AUTHORIZE
  -> existing WorkflowRunner
  -> execution budget / model authority / validator ledger
  -> verified or failed result
```

The prompt compiler and public-query DLP introduced before this version remain intact and authoritative. Dispatch V2 is layered above the prompt-aware gateway; it does not bypass or replace egress DLP.

## Executable slice

V2 admits only the capability slice already implemented by the production WorkflowRunner:

- manual trigger only;
- low risk only;
- workflow data class must equal the active WorkSpace confidentiality zone;
- exactly one connected linear chain;
- no conditional edges;
- no decision, manual, or business-approval nodes;
- administrator approval before execution;
- PPTX presentation output;
- no arbitrary shell/network/filesystem/credential capability.

Allowed action profiles:

```text
input -> research -> presentation -> daily_report -> output
```

or:

```text
input -> research -> validate -> presentation -> daily_report -> output
```

The `validate` design node represents the deterministic validation boundary already present in the runtime. It does not create a new tool.

## Design-only features

These remain valid diagram concepts but are blocked by V2 execution admission:

- schedule or event triggers;
- medium/high/critical risk;
- branching, joins, or conditional paths;
- `manual_step`;
- decision nodes;
- mid-workflow `human_approval`;
- arbitrary action names;
- data-class/runtime-zone mismatch;
- secret workflow design (Workflow Studio V1 has no secret data-class representation).

A blocked workflow remains available as a diagram. Admission failure must never silently simplify the process into a different executable workflow.

## Approval binding and replay prevention

Preparation deterministically binds:

- dispatch schema version;
- task ID;
- canonical workflow SHA-256;
- authoritative TaskContract SHA-256;
- fixed execution profile.

The resulting approval fingerprint must match exactly. Execution also requires administrator role and the literal confirmation `AUTHORIZE`.

Before the runtime is called, state changes atomically from `prepared` to `executing`. Completed, failed, or already-executing preparations cannot be replayed. A new attempt requires a fresh preparation and fingerprint.

The approver is persisted only as a SHA-256 reference. Dispatch records do not contain the complete graph, node labels, natural-language description, credentials, prompts, model responses, tool output, or internal runtime paths.

## Existing controls reused

Dispatch calls `WorkflowRunner.run_task()` and therefore preserves the existing controls:

- immutable TaskContract binding;
- persistent execution budgets;
- bounded model authority;
- inference scope;
- research evidence validation;
- presentation schema validation;
- validator ledger;
- verified-completion gate;
- prompt compiler boundary;
- public-query compiler and final egress DLP.

## Resource posture

V2 adds no runtime dependency, model, external API, database, scheduler, daemon, CDN, diagram library, or orchestration framework. Admission, fingerprinting, graph checking, authorization state, and replay prevention are deterministic Python.

## Future capability order

Additional workflow capabilities should be added only after their runtime semantics exist and are independently tested. Suggested order:

1. resumable human-approval checkpoints;
2. deterministic branch/condition evaluator;
3. bounded parallel DAG execution;
4. scheduler/event broker as a separate authority boundary;
5. additional capability-specific executors.

No future version should infer execution authority from diagram syntax or model output.
