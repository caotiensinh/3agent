# Diagnostic Capability Burn-down Policy v0.1

## Goal

Turn the remaining Office IT diagnostic capability backlog into a deterministic,
evidence-driven implementation queue without using raw occurrence count as a proxy
for value and without granting any execution authority.

The policy answers a narrow planning question:

> If one missing capability were implemented safely and bound correctly, how many
> currently blocked complaint routes could become fully promotable immediately?

It does **not** answer whether that capability is safe, authorized, technically
feasible, vendor-neutral, or worth implementing. Those remain explicit engineering
and authority reviews.

## Why raw count is insufficient

A missing capability can appear in many routes but still close none of them because
those routes have other unresolved capabilities.

Example at the 29-tool / 85-route baseline:

- `service.health` is unresolved on 55 routes;
- it has zero one-step route closures;
- therefore it must not outrank a capability that appears on only 20 routes but is
  the final missing capability for all 20.

This prevents a "largest number first" implementation strategy from pulling the
project toward broad external-service integrations before local bounded evidence is
complete.

## Canonical metric

For every unresolved capability, the planner reports:

- `unresolved_route_count`: number of routes where the capability is unresolved;
- `one_step_unlock_routes`: number of routes where it is the **only** unresolved
  capability and there are no rejected bindings;
- `minimum_unresolved_capabilities`: smallest unresolved-capability count on an
  affected route;
- `affected_domain_ids`;
- `one_step_domain_ids`.

One-step credit is deliberately fail-closed. A route gets no one-step credit when:

- more than one capability remains unresolved; or
- any binding on the route is rejected.

Rejected bindings are a binding/policy RCA problem, not an implementation backlog
problem.

## Deterministic ordering

Items sort by:

1. higher `one_step_unlock_routes`;
2. lower `minimum_unresolved_capabilities`;
3. higher `unresolved_route_count`;
4. capability tag alphabetically.

The order is planning metadata only.

## Authority boundary

The planner:

- does not execute tools;
- does not choose concrete commands;
- does not grant `TaskCapabilityAuthority`;
- does not widen network scope;
- does not enable public Internet access;
- does not create remediation authority;
- does not claim a safe implementation exists;
- does not mutate the runtime registry;
- does not auto-promote routes.

`selection_authority` is fixed to `none` and `execution_enabled` is fixed to `false`.

## Current one-step closure set

At the post-PR-430 baseline, four capabilities can each close one complete 20-route
domain if implemented and bound correctly:

| Capability | Domain | One-step routes | Engineering boundary |
| --- | --- | ---: | --- |
| `backup.status` | `server_backup` | 20 | Vendor/status semantics need careful scoping |
| `identity.account_state` | `identity_auth` | 20 | High authority ambiguity: local vs directory identity must not be conflated |
| `meeting.client` | `meeting_collaboration` | 20 | Strong candidate for bounded local process/version evidence |
| `vpn.status` | `vpn_remote` | 20 | Strong candidate if Windows/Linux/vendor states are represented honestly |

The planner intentionally gives all four the same route-closure score. Engineering
review then applies safety and semantic feasibility.

## Recommended implementation sequence after route-value planning

The current engineering review should prefer:

1. `meeting.client`
   - local read-only evidence;
   - no external egress required;
   - no remediation required;
   - process/version/running-state evidence can be bounded;
   - low risk of pretending to know remote service health.

2. `vpn.status`
   - local read-only evidence is feasible;
   - requires explicit Windows/Linux adapter semantics;
   - unknown vendor state must remain `UNKNOWN`, not be inferred as disconnected.

Defer until contracts are narrowed:

- `backup.status`: a generic "backup status" tool can easily overclaim across Windows
  Backup, Veeam, vendor agents, snapshots, cloud backup, and application-native backup.
- `identity.account_state`: local account state and domain/directory account state are
  different authority and evidence problems. A local-only implementation must not
  make the whole capability look complete.

## No-blind-rerun doctrine

The same evidence discipline applies to CI:

1. a slow runner is not a reason to rerun;
2. an old SHA is not a reason to rerun by itself;
3. main movement is impact-classified before any reconcile;
4. unrelated main changes reuse existing evidence;
5. overlapping or behaviorally relevant dependency changes justify one convergence
   validation on the new exact head;
6. a failure must be RCA'd at the failing gate before any retry;
7. retries without a code/config/environment change are not accepted as progress.

This turns the remaining project work into bounded causally justified batches rather
than repeated full workflows or arbitrary capability implementation.
