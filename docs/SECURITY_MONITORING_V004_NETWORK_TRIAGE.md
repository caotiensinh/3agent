# WorkSpace Security Monitoring v0.0.4 — Network Incident Triage

## Purpose

v0.0.4 connects the deterministic incident-correlation output from v0.0.3 to a bounded local analyst stage. The new stage interprets already-correlated evidence; it does not collect new evidence and does not gain control-plane authority.

The input contract is:

`workspace-security-monitoring/incident-graph-v1`

The output contract is:

`workspace-security-monitoring/network-incident-triage-v1`

## Processing model

The analyst accepts only `IncidentGraph` objects produced under the supported correlation schema. Every graph is validated before classification:

- graph ID and edge IDs must have the deterministic correlation format;
- authority must remain `advisory`;
- severity and upstream priority must be supported values;
- stages must be unique and in canonical order;
- rules must be known exact-correlation rules and must agree with the stages present;
- event/evidence/source references must be compact references rather than URLs or free-form text;
- entity references may only be approved inventory asset references or typed SHA-256 entity references;
- timestamps must be timezone-aware and ordered;
- conflicting replays of the same graph ID fail closed.

No fuzzy time-only linkage is added in this stage. A triage decision is based only on exact rules already proven by the correlation engine.

## Deterministic triage classes

The current classes are intentionally small and auditable:

| Exact correlation evidence | Triage kind | Confidence | Default investigation priority |
| --- | --- | --- | --- |
| DNS → FLOW | `dns-flow` | medium | normal |
| FLOW → AUTH | `flow-auth` | medium | elevated |
| AUTH → PROCESS | `auth-process` | medium | elevated |
| DNS → FLOW → AUTH | `dns-flow-auth` | high | elevated |
| FLOW → AUTH → PROCESS | `flow-auth-process` | high | high |
| DNS → FLOW → AUTH → PROCESS | `dns-flow-auth-process` | high | high |
| IDS exact-entity corroboration only | `ids-corroborated` | medium | elevated |

If IDS corroborates a graph that already has another exact rule, confidence becomes high. High upstream priority or high/critical source severity makes investigation priority high.

**Source severity is never manufactured by triage.** The output copies the graph severity exactly. Investigation priority and confidence are analyst metadata, not a replacement for source evidence.

## Privacy boundary

The triage output preserves graph/event/evidence anchors so an operator can trace the decision back to stored evidence. It does not reveal the raw values used to create sensitive entity links.

Sensitive IP, DNS, user, process and service identities must be represented as:

`entity:<kind>:sha256:<64 hex>`

Approved inventory assets may remain explicit as:

`asset:<asset_id>`

Any raw or malformed entity identity is rejected.

## Resource bounds

Default analyst-side bounds are independent of upstream collection bounds:

- maximum graphs: 128;
- maximum event references: 4,096;
- maximum entity references: 16,384;
- maximum evidence references: 4,096.

Configuration has hard ceilings and invalid values fail closed. Exact replay is deduplicated before aggregate bounds are evaluated, preventing replay inflation while still rejecting conflicting evidence under the same graph ID.

## Authority boundary

`network_triage_plan()` declares the stage as `local_deterministic` and `advisory`.

Enabled capability is limited to validation, exact-chain classification, evidence-anchor preservation and bounded advisory output.

The following remain disabled:

- active discovery;
- packet capture;
- command execution;
- network mutation;
- credential retrieval;
- remediation;
- external model calls;
- outbound network access.

This module therefore cannot scan a subnet, run shell commands, capture traffic, change network policy, quarantine a host, retrieve credentials or call an Internet/LLM service.

## Operator interpretation

A high-priority triage record means: **review this correlated evidence first**. It does not mean an attack has been conclusively proven, and it never authorizes an automated response.

The operator can use `triage_id`, `graph_id`, `graph_fingerprint`, `event_ids` and `evidence_refs` to reproduce and audit the local decision.

## v0.0.4 acceptance target

The checkpoint is complete only when focused tests cover deterministic classification, replay handling, graph integrity, privacy, bounds and authority isolation, and the repository regression suite plus exact-head CI remain green.
