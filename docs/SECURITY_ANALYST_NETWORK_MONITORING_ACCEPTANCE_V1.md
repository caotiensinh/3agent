# WorkSpace Security Analyst & Network Monitoring — Implementation Acceptance Gates v1

This file is a pre-code gate. No implementation is production-ready merely because it can collect data or produce a report.

## NS-0 Contract Gate

PASS requires:

- asset inventory schema;
- observation/event/finding schemas;
- explicit data classification;
- command capability vocabulary;
- network scope policy;
- secret-handle contract;
- SQLite schema;
- synthetic fixtures;
- no real network mutation capability.

## NS-1 Lean Collector Gate

PASS requires:

- known-inventory-only polling by default;
- bounded concurrency;
- bounded timeout;
- maximum one retry by default;
- ICMP/TCP probe results are structured;
- SNMP read path is read-only;
- SNMPv3 preferred;
- no SNMP SET;
- no arbitrary shell or SSH;
- counter wrap/reset handling;
- hourly receipt contains evidence coverage;
- collector failure does not become a false "healthy" result.

## NS-2 Log Gate

PASS requires:

- raw log content treated as untrusted data;
- timestamps/source identity normalized;
- template extraction;
- secrets and credential-like fields redacted/masked;
- raw message body excluded from LLM context by default;
- source-freshness monitoring;
- bounded local retention;
- no Internet log egress.

## NS-3 Detection Gate

PASS requires:

- deterministic rules evaluated before AI;
- baseline warm-up state;
- versioned statistical baseline;
- maintenance-window handling;
- findings preserve evidence references;
- no model-only critical alert verdict;
- false-positive/suppression state auditable.

## NS-4 Report / NAS Gate

PASS requires:

- deterministic report available without AI;
- report contains 24h, rolling 7d and rolling 30d sections;
- report distinguishes FACT / CORRELATION / HYPOTHESIS / RISK / ACTION / DATA GAP;
- every material statement has evidence/finding references;
- 17:30 schedule uses deterministic runtime authority;
- report bundle is validated before archive;
- SHA-256 manifest generated;
- NAS write uses local temp/spool and finalization semantics;
- NAS unavailable => PENDING_NAS, never silent loss;
- weekly/monthly canonical report archives are revision-safe.

## NS-5 AI Analyst Gate

PASS requires:

- local model only for confidential telemetry;
- compact finding pack rather than raw log dump;
- token/context hard budget;
- bounded retry;
- model cannot suppress deterministic high/critical findings;
- model cannot change network, capture policy, schedule or credentials;
- factual-reference validator checks generated narrative;
- deterministic fallback report remains available.

## NS-6 Sensor Gate

Zeek/Suricata integration is optional.

PASS requires:

- SPAN/TAP or other approved passive source;
- source health/packet-drop visibility;
- Zeek/Suricata data normalized before AI;
- Suricata payload logging disabled by default;
- PCAP disabled by default;
- sensor resource budget measured separately from WorkSpace inference.

## Incident PCAP Gate

PASS requires explicit operator authorization bound to:

- interface/segment;
- reason/evidence case;
- maximum duration;
- maximum bytes;
- retention TTL;
- destination storage;
- approval identity/fingerprint.

Capture stops when the first bound is reached. The model cannot extend capture.

## Enterprise invariants

The following target is always zero:

```text
unauthorized successful network mutation
unapproved full PCAP
raw credential logging
confidential Internet telemetry egress
model-generated arbitrary shell execution
unbounded retry
silent evidence/report loss
```

## Resource acceptance

Every phase records:

- CPU seconds;
- peak RAM;
- disk bytes written;
- polling network bytes where measurable;
- events processed;
- findings produced;
- AI calls;
- input/output tokens;
- GPU seconds where available;
- evidence coverage.

An optimization is accepted only when verified quality/security remain equivalent or improve.
