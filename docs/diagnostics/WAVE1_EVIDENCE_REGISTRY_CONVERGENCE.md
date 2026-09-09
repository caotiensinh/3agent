# Wave 1 Evidence Registry Convergence

## Scope

Wave 1 adds five bounded local evidence collectors to the canonical diagnostic runtime metadata registry:

- `cloud_files.client_state.snapshot`
- `mail_exchange.client_state.snapshot`
- `voip.client_state.snapshot`
- `identity.account_state.snapshot`
- `backup.local_state.snapshot`

This convergence step is deliberately metadata-only. It makes the implemented evidence primitives discoverable by the runtime registry without claiming that they satisfy broader diagnostic capabilities.

## Fail-closed rule

No new abstract route capability binding is added in this step.

In particular, this convergence does not bind:

- `identity.account_state`
- `backup.status`
- `mail.client`
- `mail.account`
- `cloud.sync`
- `cloud.permissions`
- `voip.registration`

The current collectors do not provide sufficient evidence for those broad semantics across their full catalog domains.

## Evidence is not authority

Runtime metadata registration does not grant TaskCapabilityAuthority, network authority, write authority, remediation authority, or execution selection authority.

Canonical invocation admission is handled by a separate convergence step after exact resource/effect policies are reviewed.

## Safety invariants

- local-only collectors remain `network_access=none`
- all wave-1 collectors remain read-only
- no collector is used as a substitute for remote service health
- no route is promoted solely because a similarly named local collector exists
- missing semantic coverage remains unresolved rather than approximated
