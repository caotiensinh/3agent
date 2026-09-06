# WorkSpace Security Operator Posture v0.1

## Purpose

`operator-posture-v1` is the final read-only operator projection for the current WorkSpace security monitoring milestone. It combines bounded risk, latest asset observation health, deterministic exact-entity correlation, flow evidence analysis, and incident timeline information without exposing the detailed identifiers or evidence objects used internally to calculate those aggregates.

The feature is an observation surface only. It is not an execution, remediation, forensic browsing, packet-capture, shell, or remote-administration surface.

## Canonical path

```text
Local Console
  -> SecurityMonitoringService.operator_posture()
    -> safe_operator_posture_summary(config)
      -> SecurityMonitoringUIReadModel (SOC + asset reads)
      -> SQLite mode=ro + PRAGMA query_only=ON (correlation sample)
      -> canonical deterministic correlation / flow / timeline engines
      -> privacy reducer
```

The browser cannot supply a config path, database path, cutoff time, target, asset selector, event selector, evidence selector, page size, correlation window, command, credential, collector selector, packet-capture request, or remediation action.

## Bounded read contract

- at most 100 recent evidence-bound correlation-capable events;
- at most 4,096 typed entity references;
- correlation edge budget: 2,048;
- exact correlation window: 900 seconds;
- SOC risk data comes from the existing deterministic SOC read model;
- asset health is a count over the latest observation state of enabled assets;
- no database is created or initialized when durable monitoring storage is absent;
- incomplete/missing SQLite storage is treated as a read-side data gap, not permission to mutate storage.

## Public projection

The HTTP endpoint is:

```text
GET /api/v1/security/monitoring/operator-posture
```

It may return only fixed-enum or numeric aggregate structures:

- risk counts for today / rolling 7d / rolling 30d;
- fixed severity counts;
- enabled-asset latest-observation buckets: `healthy`, `degraded`, `unreachable`, `unknown`;
- exact deterministic correlation graph/event counts;
- fixed correlation severity, priority, and stage counts;
- bounded flow event counts and fixed stage/severity aggregates;
- bounded incident timeline counts and relative recency buckets;
- explicit authority flags.

The endpoint does **not** return:

- event IDs;
- graph IDs;
- entity references;
- evidence references;
- finding IDs;
- rule IDs;
- asset IDs;
- source IDs;
- categories or arbitrary stored labels;
- IP addresses, DNS names, ports, usernames, process paths, or credentials;
- raw observation/event/evidence values;
- exact incident timestamps.

Timeline time is reduced to fixed relative buckets:

- `last_15m`;
- `15m_to_1h`;
- `1h_to_24h`;
- `older`;
- `future` (clock-skew indicator only).

## Correlation semantics

The projection reuses the canonical `DeterministicIncidentCorrelator`; it does not implement a second correlation engine. Existing exact rules remain authoritative:

- DNS -> FLOW requires exact initiator and resolved destination linkage;
- FLOW -> AUTH requires exact source, destination, and service linkage;
- AUTH -> PROCESS requires exact approved asset and user linkage;
- IDS corroboration requires exact shared typed entity evidence.

Correlation remains local, deterministic, evidence-bound, bounded, and advisory. Multi-stage linkage may increase investigation priority under the canonical correlator but cannot manufacture critical severity without critical source evidence.

## Flow and timeline semantics

Flow analysis reuses `analyze_flow_evidence()` and accepts only canonical admitted flow evidence. Incident timeline construction reuses `build_incident_timeline()` and requires deterministic correlation. Detailed objects from those engines contain IDs/references internally, but those objects are never serialized by the Local Console endpoint. The privacy reducer emits counts and fixed enums only.

## Security authority

The response explicitly reports:

```text
aggregate_only=true
database_read_only=true
exact_timestamps_exposed=false
event_ids_exposed=false
graph_ids_exposed=false
entity_refs_exposed=false
evidence_refs_exposed=false
rule_ids_exposed=false
asset_ids_exposed=false
network_addresses_exposed=false
raw_values_exposed=false
browser_filters_exposed=false
database_write=false
network_execution=false
collector_execution=false
packet_capture_execution=false
remediation_execution=false
```

The existing Local Console protections remain unchanged: loopback-only bind, Host-header validation, restrictive CSP, `Cache-Control: no-store`, frame denial, anti-CSRF protection for POST, and explicit human confirmation for the separate read-only monitoring execution action.

## Acceptance criteria

The increment is acceptable only when:

1. privacy regression proves internal event/graph/entity/evidence/asset values and exact timestamps do not occur in the serialized projection;
2. browser query-string selectors do not change server-side bounds or select internal objects;
3. missing monitoring DB does not create a file or initialize a schema;
4. canonical module and internet-egress gates remain green;
5. full harness, EV-01 through EV-10, installer, Windows, and portable Ubuntu deployment workflows pass on the exact PR head.
