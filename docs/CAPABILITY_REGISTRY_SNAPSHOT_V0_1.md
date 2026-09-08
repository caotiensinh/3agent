# Capability Registry Snapshot v0.1

Status: immutable, non-authorizing projection over the canonical reviewed capability source.

## Goal

Add reviewed namespace binding and a stable registry-level fingerprint without creating a second mutable registry and without granting execution authority.

The canonical capability source remains `MicroToolRegistry` plus `ToolMetadata`. `CapabilityDescriptor` remains the immutable per-capability projection. This slice adds an immutable snapshot receipt over those descriptors.

## Canonical chain

`MicroToolRegistry -> CapabilityDescriptor -> CapabilityRegistrySnapshot`

The final object is a content-addressed view. It is not a registration surface, plugin manager, approval store, secret store, execution adapter, or authority source.

## Reviewed namespace policy

v0.1 has exactly one runtime-reviewed namespace:

- `builtin.tool`
  - kind: `tool`
  - provenance: `micro_tool_registry`
  - external: `false`

The reviewed namespace set is a **closed source allowlist** (`REVIEWED_NAMESPACE_POLICIES`). A runtime caller cannot make a namespace reviewed merely by constructing a structurally valid `ReviewedCapabilityNamespace`. Adding another reviewed namespace requires a reviewed source change that updates the canonical allowlist.

The schema can describe other capability kinds, but they are not automatically reviewed for runtime exposure.

A descriptor is accepted into the snapshot only when:

1. its namespace policy exactly matches a source-reviewed allowlist entry;
2. descriptor namespace is present in that reviewed policy set;
3. descriptor kind equals the namespace's reviewed kind;
4. descriptor provenance equals the namespace's reviewed provenance;
5. its own descriptor fingerprint is valid;
6. its capability ID is globally unique in the effective snapshot.

External namespaces are explicitly rejected in v0.1. External/plugin/MCP admission remains a later quarantine/review slice.

## Fingerprints

Each `ReviewedCapabilityNamespace` has a SHA-256 fingerprint over its exact canonical review-policy fields.

`CapabilityRegistrySnapshot.fingerprint` is a SHA-256 hash over canonical JSON containing:

- snapshot schema version;
- canonical ordered reviewed namespace policies, including their fingerprints;
- canonical ordered descriptor identities: namespace, ID, kind, descriptor fingerprint.

Therefore the registry fingerprint changes when any admitted descriptor identity changes or when an accepted namespace review policy changes.

The fingerprint is metadata identity only. It is not Evidence, approval, trust, authority, a signature, or a credential.

## Security invariants

1. No second mutable capability registry is introduced.
2. Namespace membership does not grant `TaskCapabilityAuthority`.
3. Snapshot membership does not invoke a capability.
4. Runtime callers cannot self-mint reviewed namespaces.
5. Duplicate capability IDs fail closed.
6. Unknown/unreviewed namespaces fail closed.
7. Kind/provenance mismatch fails closed.
8. External namespaces fail closed in v0.1.
9. Descriptor fingerprint tampering fails before admission.
10. Snapshot fingerprint tampering fails validation.
11. Input ordering cannot change the canonical snapshot identity.
12. No credential values, approval state, filesystem grants, or network grants are introduced.

## Checklist interpretation

This slice can advance the following broad items, but only to the level actually proven:

- `T-08`: stronger partial coverage because descriptor identities now participate in a registry-level content-addressed view.
- `T-11`: stronger partial coverage because the effective snapshot rejects duplicate capability IDs and unreviewed namespace/provenance mismatches.
- `T-12`: partial only; a reviewed namespace contract exists, but adapter/plugin/provider namespaces are not runtime-admitted yet.
- `T-13`: complete for the current effective reviewed descriptor snapshot: immutable registry fingerprint is implemented and validated.

This slice does not claim:

- generic invocation enforcement;
- runtime authority intersection at the final adapter call;
- external/plugin/MCP quarantine/admission;
- Observation/Evidence normalization;
- capability availability probes;
- Windows/Linux/network/camera toolset migration.

## Next dependency

The next narrow slice should introduce a universal capability invocation adapter that resolves the exact descriptor/snapshot identity, intersects it with canonical `TaskCapabilityAuthority` immediately before invocation, uses fixed reviewed adapter code rather than model-selected shell commands, and emits a bounded invocation decision receipt before later Observation/Evidence normalization.
