# WorkSpace Workflow Studio / Dispatch v1

## Objective

Let an internal user describe a business process in natural language and receive a bounded workflow contract plus two visual representations:

- Mermaid `flowchart` source for copy/edit/export;
- a dependency-free SVG preview generated locally.

V1 is deliberately **design-only**. Compiling or drawing a workflow never grants authority to execute it.

## Design influences

Current agent products increasingly separate natural-language delegation from execution details:

- a user describes the desired outcome;
- the system classifies/plans the work;
- tools or execution environments are selected under policy;
- approval/verification remains explicit at important boundaries.

WorkSpace adopts that mechanism, not any vendor UI, prompt, or implementation.

## Enterprise-lean architecture

```text
Natural-language description
          |
          v
1 local structured LLM call
          |
          v
Workflow Contract
          |
          v
Deterministic validator
  - bounded nodes/edges
  - closed kind/action enums
  - dependency existence
  - DAG/cycle check
  - risk/approval warnings
          |
          +----> Mermaid source
          |
          +----> standard-library SVG
          |
          v
Design preview only
execution_authorized = false
```

No new model server, web framework, JS diagram library, Graphviz package, database, daemon, cloud API, or CDN is added.

## Closed action vocabulary

The model cannot invent executable tool names. V1 accepts only:

```text
input
research
presentation
daily_report
validate
human_approval
manual_step
output
```

A business action outside this vocabulary must be represented as `manual_step`. It can appear in the diagram, but it receives no shell/tool/network/credential authority.

## Security boundary

The user's workflow description is untrusted data. Text inside it cannot:

- grant filesystem, shell, network, secret, or credential access;
- enable scheduling/event execution;
- widen model authority;
- create arbitrary tool calls;
- bypass WorkSpace task contracts, capability authority, or runtime validators.

The structured compiler uses an allowlisted schema and the result is revalidated deterministically.

## Resource budget

V1 uses exactly one workflow-compile LLM call.

The compile call:

- uses the already-configured local WorkSpace model;
- disables explicit thinking;
- has a bounded output budget;
- performs no external research;
- does not launch subagents or critic loops.

Graph validation and rendering use deterministic Python.

## API

### `POST /api/workflows/compile`

Authenticated LAN users only.

Input:

```json
{
  "description": "Every Monday collect project metrics, validate them, request manager approval, then publish the approved report.",
  "language": "en"
}
```

Output includes:

```text
schema_version
contract
diagram.mermaid
diagram.svg
execution_authorized=false
execution_mode=design_only
```

## UI

Workflow Studio is an additive panel in the existing WorkSpace LAN interface.

It provides:

- natural-language workflow description;
- Compile workflow;
- risk/data-class chips;
- rendered SVG diagram;
- ordered step list;
- Mermaid source;
- normalized contract JSON;
- warnings/safety review.

## Future Dispatch execution gate

Execution is intentionally deferred to a separate enterprise gate.

A future executable workflow must bind the validated design to:

1. an exact workflow fingerprint;
2. a TaskContract;
3. allowed actions/capabilities;
4. data-class and trust-zone rules;
5. execution budgets;
6. required approval nodes;
7. validator ledger evidence;
8. explicit user/operator execution authorization.

Only then may a design be compiled to the existing `WorkflowRunner`/agent runtime.

This separation prevents a natural-language workflow feature from silently becoming an arbitrary automation or remote-code-execution surface.
