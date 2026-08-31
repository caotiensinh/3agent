# WorkSpace Security Analyst & Network Monitoring — Phased Implementation Plan v1

## NS-0 — Contracts first

Deliver:

- asset inventory schema;
- observation/event/finding schemas;
- typed collector capability vocabulary;
- network-scope policy;
- secret-handle interface;
- SQLite schema and migrations;
- synthetic fixtures for router/switch/syslog/Suricata/Zeek-like events;
- policy and parser tests.

No real LAN access.

## NS-1 — Lean read-only collector

Deliver:

- known-target ICMP/TCP probes;
- read-only SNMP adapter;
- interface counter delta/rate calculation;
- local host network metrics;
- bounded concurrency/timeouts/retries;
- hourly collection receipt;
- coverage/data-gap semantics;
- systemd hourly timer.

No AI required.

## NS-2 — Log pipeline

Deliver:

- rsyslog/local spool adapter;
- canonical event normalization;
- template mining/compression;
- event partitioning to gzip JSONL;
- source freshness;
- deterministic rule engine;
- retention worker.

## NS-3 — Baseline and findings

Deliver:

- median/MAD/EWMA rolling statistics;
- baseline warm-up/versioning;
- maintenance/change suppression context;
- finding lifecycle;
- cross-source correlation;
- immediate high/critical internal alert interface.

## NS-4 — Reporting and NAS

Deliver:

- deterministic 24h/7d/30d report;
- 17:30 systemd timer;
- weekly/monthly canonical archive;
- local spool;
- atomic NAS writer;
- SHA-256 manifests;
- archive receipts and retry.

## NS-5 — Local AI analyst

Deliver:

- compact analyst context pack;
- one normal daily LLM inference;
- correlation/executive narrative;
- FACT/CORRELATION/HYPOTHESIS/RISK/ACTION/DATA GAP labelling;
- evidence-reference validator;
- deterministic fallback.

## NS-6 — Optional passive network sensor

Deliver adapters for existing:

- Zeek JSON logs;
- Suricata EVE JSON;
- NetFlow/sFlow/IPFIX if available.

Do not make sensor installation mandatory for lean mode.

## NS-7 — Advanced anomaly benchmark

Benchmark classical/ML options against the deterministic/statistical baseline.

Admission requires measurable improvement in useful anomaly detection without unacceptable false positives/resource cost.

## Explicit later work

Not part of first implementation:

- autonomous remediation;
- continuous full PCAP;
- vulnerability scanning framework;
- cloud AI;
- SIEM cluster deployment;
- Internet threat-intelligence ingestion;
- automatic network configuration backup containing secrets.
