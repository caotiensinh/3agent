# Capability Descriptor v0.1

Status: immutable metadata projection over the canonical Micro-Tool Registry.

## Goal

Introduce the first runtime-wide `CapabilityDescriptor` contract without creating a second registry or a new authority source.

The canonical reviewed micro-tool source remains `src/three_agent/micro_tool_registry.py::MicroToolRegistry` and `ToolMetadata`. v0.1 adds a provider-neutral immutable projection in `src/three_agent/capability_descriptor.py`.

## Current scope

The schema recognizes the planned capability kinds:

- `tool`
- `program`
- `gateway`
- `agent`
- `provider`
- `adapter`

However, v0.1 has exactly one canonical production projection: reviewed `ToolMetadata` -> `CapabilityDescriptor(kind="tool")`.

The other kinds are schema vocabulary only in v0.1. They are not registered, executable, or considered complete runtime integrations.

## Descriptor fields

Each projected tool descriptor contains:

- canonical capability id;
- kind and namespace;
- platform;
- effect and risk class;
- network-access class;
- admin requirement;
- sensitive-output marker;
- bounded result-size declaration;
- evidence-required declaration;
- required environment variable names only;
- provenance source and source schema version;
- exact source-metadata SHA-256 fingerprint;
- exact descriptor SHA-256 fingerprint.

## Fingerprint semantics

`source_fingerprint` is the SHA-256 of canonical JSON for the exact validated source `ToolMetadata` record.

`fingerprint` is the SHA-256 of canonical JSON for all descriptor identity fields except the fingerprint itself.

Both use sorted-key, compact UTF-8 JSON. A source metadata change therefore changes both the source fingerprint and the resulting descriptor fingerprint.

The fingerprint is metadata identity. It is not evidence, approval, authority, a credential, or a signature of trust.

## Environment-variable policy

A descriptor may declare required environment variable names such as `WORKSPACE_TOKEN` or `API_ENDPOINT`.

It cannot carry environment assignments or values. Values such as `TOKEN=secret` fail descriptor validation. Secret material remains outside model-visible descriptor data.

The current `ToolMetadata` source does not itself declare environment requirements; v0.1 therefore projects an empty tuple unless a reviewed adapter explicitly supplies names.

## Result/evidence declaration

The v0.1 tool projection declares:

- a default result-size limit equal to the current bounded tool-result stdout projection limit;
- an upper bound equal to the platform `MAX_RESULT_FIELD_BYTES` hard limit;
- `evidence_required=True` by default for accepted diagnostic outcomes.

These fields are declarative in v0.1. They do not yet enforce invocation, normalize `ExecutionObservation`, or persist canonical Evidence. Enforcement belongs to the later authority-bound capability adapter.

## Security invariants

1. `CapabilityDescriptor` is frozen and deterministic.
2. `MicroToolRegistry` remains the canonical reviewed source; `project_micro_tool_registry(...)` creates a view, not another registry.
3. A descriptor cannot grant or widen `TaskCapabilityAuthority`.
4. A descriptor cannot carry approval state or credential values.
5. Descriptor membership cannot invoke a tool.
6. Source metadata is revalidated before projection.
7. Invalid environment declarations and result limits fail closed.
8. Descriptor tampering is detectable because validation recomputes the exact fingerprint.
9. External/plugin/MCP metadata is not admitted by this v0.1 projection.
10. Unknown capability kinds are rejected.

## Checklist interpretation

This slice should only advance broad requirements to partial where appropriate:

- `T-01`: remains partial; a canonical immutable tool projection now exists, but runtime-wide multi-source convergence does not.
- `T-02`: partial at most; the schema vocabulary exists, but only `tool` has a canonical projection.
- `T-05`: partial; names-only environment declaration is enforced, while broader provider/adapter integration remains open.
- `T-06`: partial; tool descriptors declare result/evidence requirements, but invocation enforcement remains open.
- `T-08`: partial; stable fingerprint/provenance exists for the micro-tool projection, not every capability source.
- `T-13`: not claimed; registry-wide fingerprint is a separate follow-up.

## Next dependency

The next narrow slice should add reviewed namespaces and an immutable effective registry fingerprint over descriptor identities, still without granting invocation authority. After that, the universal capability adapter can intersect the resolved descriptor with canonical `TaskCapabilityAuthority` immediately before invocation.
