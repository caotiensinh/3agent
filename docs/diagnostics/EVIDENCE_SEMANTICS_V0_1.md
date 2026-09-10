# Diagnostic Evidence Semantics v0.1

## Purpose

WorkSpace diagnostics separates **evidence primitives** from **diagnostic capabilities**.

An evidence primitive reports one bounded observation. A capability tag represents evidence sufficient for a route-planning requirement. The existence of a similarly named tool must never be treated as proof that the broader capability is satisfied.

## Wave 1 policy

The five wave-1 collectors are local-only evidence primitives. Their semantic descriptors deliberately publish an empty `satisfied_capability_tags` set until a separate review proves that a collector or evidence bundle is sufficient for a concrete route requirement.

This prevents accidental promotion such as:

- local account state → directory/authentication health
- backup service/timer state → successful/fresh/restorable backup
- sync-client process state → cloud synchronization success
- mail-client process state → mailbox or Exchange service health
- softphone process state → SIP registration or call-path health

## Descriptor invariants

Every wave-1 descriptor must:

- identify exactly one tool ID and evidence kind
- remain `local_only=true`
- remain `execution_enabled=false`
- keep `selection_authority=none`
- list claims that the evidence cannot support
- grant no route capability tags by default

## Promotion rule

A future capability mapping must be introduced separately with route-specific evidence justification and regression tests. Evidence reuse is encouraged, but semantic widening is not automatic.
