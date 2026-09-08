# Adaptive Micro-Tool Registry v0.2

## Purpose

WorkSpace must choose the minimum set of diagnostic capabilities that can materially reduce uncertainty. The registry is metadata-first: the harness can inspect lightweight tool metadata without loading implementation bodies into model context.

The execution doctrine remains:

`question -> hypothesis -> metadata registry -> cheapest relevant tools -> evidence -> stop or justified escalation`

A registry decision is not execution authority. Exact execution remains bound by `TaskContract` and `TaskCapabilityAuthority`.

## V0.2 foundation

`three_agent.micro_tool_registry` adds deterministic contracts for:

- `ToolMetadata`: platform, category, keywords, C0..C5 cost, risk, admin requirement, network-access class, sensitivity, effect, and implementation availability.
- `MicroToolRegistry`: fail-closed validation, deterministic indexing, compact metadata views, and exact tool lookup.
- `ToolSelectionRequest` / `ToolSelectionResult`: QUICK, TARGETED, or FULL selection with deterministic rejection reason codes.
- `ToolPreset`: composition-only full/deep presets. Presets contain tool ids and never duplicate tool implementation logic.
- `EscalationContext` / `EscalationDecision`: explicit stop/escalation decisions.

The existing Office IT v0.1 specs can be adapted into this registry through `MicroToolRegistry.from_specs(...)`; no second capability authority is introduced.

## Cost model

- C0: under 100 ms
- C1: under 1 s
- C2: 1–5 s
- C3: 5–30 s
- C4: 30 s–5 min
- C5: very expensive

Default mode ceilings:

- QUICK: C0..C2
- TARGETED: C0..C3
- FULL: C0..C5, but only after explicit or evidence-driven authorization

Within relevant candidates the selector sorts by lower cost first, then stronger keyword match, then stable tool id. Input registry order therefore cannot change the result.

## Fail-closed metadata

Metadata is rejected when the schema, id, platform/category, cost class, risk class, effect, network-access class, keyword list, or structural invariants are invalid. Duplicate tool ids and presets that reference unknown tools are rejected.

Unknown C/R classes are not interpreted optimistically.

## Security boundaries

The selector never executes tools and never creates authority.

Diagnostic selection accepts only read, network-read, or compute effects. Write, execute, control, and delete effects are not selected by the diagnostic selector even if they match keywords.

External/allowlisted egress is disabled by default. A matching external-network capability is rejected unless the selection request explicitly enables external networking and the existing task authority also permits the required network scope.

Internal-network tools are prefiltered against the task authority network scope, but this is only an early rejection optimization. Execution must still perform exact resource/effect authorization through `TaskCapabilityAuthority`.

Admin-required tools can be rejected early when administrative authority is known to be unavailable. Sensitive output metadata is preserved for evidence-handling policy; it is never treated as a capability grant.

## QUICK and TARGETED behavior

Normal diagnostic requests use QUICK. The selector never expands a preset implicitly.

TARGETED may admit C3 tools after the current hypothesis justifies them. C4/C5 remain outside the initial TARGETED boundary.

A C5 tool can exist in the registry and still be invisible to the initial QUICK selection.

## FULL/deep preset contract

FULL is a composition boundary, not a monolithic collector.

A `ToolPreset` lists atomic tool ids in deterministic order. `expand_preset(...)` rejects explicit-only presets unless FULL authorization is supplied. It also fails closed when a preset contains an unavailable, unauthorized, or non-diagnostic capability.

FULL mode itself is rejected unless the request records either explicit human authorization or evidence-driven escalation.

## Stop conditions

`decide_escalation(...)` makes the harness stop when any of these conditions is true:

1. evidence is sufficient;
2. another tool cannot materially reduce uncertainty;
3. required authority is unavailable;
4. next-tool cost exceeds justified diagnostic value, in which case human decision is required.

Only a justified next-tool decision or explicit FULL authorization keeps the investigation open.

## Non-goals

V0.2 does not implement an autonomous recursive agent loop, remediation, credential use, scanning, public-network discovery, service restart, log clearing, registry/firewall mutation, software installation, driver update, process termination, quarantine, permission changes, or network reconfiguration.

It also does not require all future Windows/Linux/camera tools to exist before the deterministic registry contract is stable.

## Test contract

Regression coverage proves:

- cheapest relevant selection;
- irrelevant rejection;
- no C5 during initial QUICK;
- normal requests do not activate FULL presets;
- explicit FULL permits preset expansion;
- task authority prefilters unauthorized tools;
- malformed metadata fails closed;
- unknown cost/risk classes fail closed;
- diagnostic selection cannot grant remediation;
- deterministic order is independent of registry input order;
- external egress is off by default;
- internal network scope is enforced;
- explicit stop logic is deterministic;
- the Office IT v0.1 metadata can be consumed through the generic registry adapter.
