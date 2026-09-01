# Network Security Intelligence v0.0.3 — deterministic multi-source entity correlation

## Status

v0.0.3 extends the merged Security Monitoring stack and Network Security Intelligence v0.0.2 with a local, deterministic correlation layer for structured security evidence.

**Correlation remains advisory.** A graph does not authorize remediation, packet capture, active scanning, firewall/account/process mutation, shell execution, package installation, deployment, model actions, or learning/promotion.

## Why entity correlation is required

The existing `CanonicalEvent` intentionally stores compact event metadata: source, timestamp, category, severity, message hash, parser version and evidence reference. That is sufficient for evidence indexing and category/time correlation, but it is not sufficient to reliably connect a DNS lookup to a later flow, an authentication event, or a process start.

v0.0.3 therefore does **not** weaken `CanonicalEvent` or add raw identity fields to it. Instead it adds a separate bounded `EventEntityContext` bound to the exact `event_id`.

## Privacy-preserving entity context

Supported entity kinds are:

- IP address;
- DNS name;
- authentication user;
- process image;
- approved asset;
- service/port.

Sensitive/discovered values are converted immediately to typed deterministic references:

```text
entity:<kind>:sha256:<64 hex chars>
```

The raw value is not retained in the entity context. This includes internal or external IP addresses, DNS names, usernames, process paths and service values.

The only explicit identity permitted is an **already approved inventory asset ID**:

```text
asset:<approved-asset-id>
```

Entity role and kind are bound by a fixed allowlist (`source_ip`, `destination_ip`, `dns_query`, `dns_answer`, `asset`, `auth_user`, `process_image`, `service`). A mismatched kind/role pair fails closed.

## Parser enrichment

Existing callers of `parse_json_sensor_event()` remain unchanged. v0.0.3 adds separate enrichment entry points.

### Suricata EVE

Only an explicit entity-field allowlist may affect correlation metadata:

- `src_ip`;
- `dest_ip`;
- `dest_port`;
- `proto`;
- selected `dns` query/answer fields.

Other EVE fields remain raw evidence and are not silently turned into identities.

### Zeek JSON

Only selected structured fields are used:

- `id.orig_h`;
- `id.resp_h`;
- `id.resp_p`;
- `proto`;
- `query`;
- IP-valued `answers`.

Values such as arbitrary `uid` or unrelated application metadata do not enter entity context.

### WorkSpace audit

`workspace_audit` uses a strict local JSON schema for:

- `auth_success`;
- `auth_failure`;
- `process_start`.

Authentication services are explicitly supported and canonicalized (`ssh`, `smb`, `rdp`, `winrm`, `winrm_tls`). Unknown keys fail closed. This deliberately prevents password, token, cookie, session, command-line or other unexpected material from entering correlation metadata.

Free-form text is not interpreted by a model to create identities or graph edges.

## Storage

`EventEntityContextStore` extends the **existing MonitoringStore SQLite database**. It does not introduce another database, vector store or service.

The additive table is keyed by exact event ID and exact typed entity reference. Existing monitoring databases can be initialized in place without rewriting `canonical_events` or `findings`.

An exact replay is idempotent. A different entity context for an already-bound event ID is rejected rather than silently replacing history.

## Structured ingest

`StructuredEntityIngestor` accepts only approved structured source types:

- `suricata_eve`;
- `zeek_json`;
- `workspace_audit`.

Input is byte-bounded. Invalid enriched records are quarantined. A correlation-capable accepted record must contain at least one validated entity reference.

Existing trusted source mapping remains authoritative; v0.0.3 does not discover or trust new senders.

## Deterministic graph rules

Time proximity is a necessary bound, never sufficient evidence.

### DNS -> FLOW

Requires both:

1. an exact initiating identity match (approved asset or source-IP entity); and
2. a DNS answer entity exactly matching the flow destination-IP entity.

### FLOW -> AUTH

Requires all of:

1. exact source-IP entity match;
2. exact destination-IP entity match;
3. exact canonical service entity match.

### AUTH -> PROCESS

Requires both:

1. exact approved asset entity match; and
2. exact authentication-user entity match.

### IDS corroboration

A Suricata alert or supported Zeek IDS-like event may corroborate another stage only when an exact asset/source/destination entity is shared inside the bounded time window.

## Multi-stage graph

Connected exact-relationship edges form an `IncidentGraph`. The graph contains metadata only:

- deterministic graph ID;
- event/evidence references;
- opaque entity refs and approved asset IDs;
- source types;
- stage types;
- first/last timestamps;
- deterministic severity and investigation priority;
- rule IDs and edge IDs;
- `authority=advisory`.

A graph with at least three linked stage types receives `priority=high`. This can raise a lower source severity to `high` for investigation priority, but it **cannot manufacture `critical`**. Critical severity requires critical source evidence.

## Bounds and replay safety

The correlator enforces explicit bounds for:

- events per run;
- entity references per run;
- graph edges per run;
- correlation time window.

Exact duplicate events are deduplicated. A duplicate `event_id` with conflicting event/context identity fails closed.

## Authority boundary

The correlation engine has no dependency or method for:

- Internet or LAN access;
- socket/probe execution;
- subprocess or shell execution;
- PCAP approval or execution;
- credentials/secrets;
- model/LLM calls;
- firewall/account/process mutation;
- host quarantine;
- deployment/Git mutation;
- automatic learning, fine-tuning or skill promotion.

The existing PCAP human-approval ceremony remains separate and unchanged.

## Acceptance contract

v0.0.3 is accepted only when:

1. existing `CanonicalEvent` and parser callers remain backward compatible;
2. raw IP/DNS/user/process values never appear in entity-context or graph serialization;
3. DNS->FLOW requires exact answer/destination plus initiating identity linkage;
4. FLOW->AUTH requires exact endpoints and service;
5. AUTH->PROCESS requires exact asset and user;
6. same-window unrelated events do not correlate;
7. duplicate replay does not inflate a graph;
8. conflicting duplicate context fails closed;
9. graph/input bounds fail closed;
10. multi-stage graphs remain advisory;
11. the existing PCAP approval boundary remains unchanged;
12. v0.0.2 truth separation and advisory-only deep-flow behavior remain unchanged;
13. exact-head harness, installer, portable-deploy and Windows-deploy gates pass before merge.
