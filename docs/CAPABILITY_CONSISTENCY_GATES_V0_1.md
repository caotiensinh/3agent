# Capability Consistency Gates v0.1

## Purpose

This document defines the canonical ownership and extension path for diagnostic capabilities across WorkSpace runtime selection, task authority, invocation evidence, bounded observations, and evidence lineage.

The consistency layer is deliberately **not** a second permission engine and is **not** a second registry. It imports and checks the existing canonical sources and fails closed when they drift.

## Canonical ownership

| Layer | Canonical source | Role | Authority status |
| --- | --- | --- | --- |
| Task capability vocabulary | `src/three_agent/task_contract.py` → `TOOLS` | Defines tool IDs that may appear in a `TaskContract` | Authoritative vocabulary |
| Task authorization | `src/three_agent/capability_authority.py` → `TaskCapabilityAuthority` and `_EFFECTS` | Decides whether a task may invoke a capability for an exact effect/resource | **Authoritative decision boundary** |
| Implemented diagnostic runtime | `src/three_agent/diagnostics/runtime_registry.py` → `runtime_tool_metadata()` | Lists implemented diagnostic tools and their reviewed metadata | Runtime inventory only; does not grant authority |
| Abstract capability bindings | `src/three_agent/diagnostics/runtime_registry.py` → `default_runtime_capability_bindings()` | Maps route capability tags to implemented concrete tool IDs | Selection mapping only; does not grant authority |
| Invocation decision receipt | `src/three_agent/invocation_decision_receipt.py` | Records immutable audit metadata for an authority decision | Advisory/evidence-only |
| Diagnostic observation | `src/three_agent/security_monitoring/diagnostic_observation.py` | Carries bounded tool output with task/request provenance | Advisory/evidence-only |
| Diagnostic evidence lineage | `src/three_agent/security_monitoring/diagnostic_lineage.py` | Records deterministic parent/child provenance from task to evidence | Provenance-only; does not establish trust or authority |

## Monotonic linkage

The reviewed path is:

```text
runtime registry metadata
        ↓ concrete tool id must exist in
TaskContract TOOLS
        ↓ exact effect must match
TaskCapabilityAuthority
        ↓ decision metadata only
InvocationDecisionReceipt
        ↓ same task/request + capability/tool identity
DiagnosticObservation
        ↓ deterministic parent/child hashes
DiagnosticEvidenceLineage
```

Every layer may preserve or reduce authority. No downstream metadata object may create new authority.

## Reviewed runtime snapshot identity

There is no separate mutable `CapabilitySnapshot` registry in this phase. When a stable snapshot identity is needed for receipts or tests, it is derived deterministically from the canonical, sorted output of `runtime_tool_metadata()`.

A snapshot fingerprint is therefore evidence about **which reviewed runtime metadata set was observed**. It is not itself permission to invoke a tool.

Likewise, a descriptor fingerprint is derived from the canonical `ToolMetadata.to_dict()` representation for one runtime tool. Descriptor and snapshot fingerprints are audit identities only.

## Fail-closed consistency gates

`tests/test_capability_cross_layer_consistency.py` enforces the following invariants:

1. Every implemented runtime diagnostic tool ID must exist in `task_contract.TOOLS`.
2. Every implemented runtime tool must have an authority effect mapping in `capability_authority._EFFECTS`.
3. Runtime metadata `effect` must equal the canonical authority effect for the same tool ID.
4. Every concrete target in `default_runtime_capability_bindings()` must exist in `runtime_tool_metadata()`.
5. Unknown/stale tool IDs must fail before entering task authority.
6. A representative capability must reconcile the same task/request, tool, capability, authority, descriptor, and snapshot identities across authority → receipt → observation → lineage.
7. Mutation of descriptor or snapshot identity must change the invocation receipt fingerprint.
8. Deliberate registry-ID or effect drift fixtures must fail the consistency suite.

These checks are additive guardrails around existing canonical sources. They do not duplicate the capability list in production code.

## Authority versus evidence

### Authoritative

`TaskCapabilityAuthority` is the execution authorization boundary. A runtime registry entry, capability binding, descriptor fingerprint, snapshot fingerprint, receipt, observation, or lineage record must never be treated as authorization by itself.

### Advisory / evidence-only

`InvocationDecisionReceipt` is immutable audit evidence describing a decision that already occurred. Its `authority` remains `advisory` and `automatic_action_allowed` remains `False`.

`DiagnosticObservation` is bounded evidence from a diagnostic tool. It preserves provenance, truncation, redaction, status, and error semantics but cannot grant action authority.

`DiagnosticEvidenceLineage` proves deterministic provenance linkage. `provenance_status="complete"` explicitly remains distinct from `trust_status="unverified"`. Complete provenance does not mean trusted content and does not grant authority.

## Extension procedure

When adding a new diagnostic capability, extend the existing canonical sources in this order:

1. **Implement reviewed tool metadata** in the appropriate diagnostics tool module and include it through `runtime_tool_metadata()`.
2. **Add the concrete tool ID to `task_contract.TOOLS`** through the appropriate canonical tool group only when it is intentionally eligible for task authority.
3. **Add the exact effect mapping to `capability_authority._EFFECTS`**. Import-time vocabulary consistency must continue to fail closed on missing/stale mappings.
4. **Add an abstract route binding only when needed** through `default_runtime_capability_bindings()`. The binding must target an implemented runtime tool ID.
5. **Add focused authority/security tests** for default-deny behavior, resource kind, network scope, effect substitution, and data-boundary rules as applicable.
6. **Run the cross-layer consistency suite** so registry ID/effect/binding drift cannot silently enter the runtime.
7. **Use existing L17/L18/L19 contracts** for receipt, bounded observation, and lineage. Do not create a parallel receipt store, observation authority layer, or lineage permission engine.

## What must not be added

Do not add:

- a second hardcoded capability registry;
- a parallel permission/authority engine;
- a mutable snapshot registry whose contents can diverge from `runtime_tool_metadata()`;
- execution permission inferred from a receipt, observation, or lineage fingerprint;
- raw credential/resource payload duplication into audit lineage;
- trust inferred only from complete provenance.

If a new layer needs capability identity, it should import or derive from the canonical source and add a consistency test rather than copy the vocabulary.

## Phase completion rule

This integration phase is complete only when:

- deliberate drift fixtures fail as expected;
- the full deterministic test suite passes;
- exact-head CI is green;
- the merge is verified against live `main`.
