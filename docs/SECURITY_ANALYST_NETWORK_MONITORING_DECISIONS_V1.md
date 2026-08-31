# WorkSpace Security Analyst & Network Monitoring — Architecture Decisions v1

## ADR-NS-001 — Evidence engineering before AI

**Decision:** raw telemetry is collected, structured, reduced and detected before LLM analysis.

**Why:** lower token/GPU cost, better auditability, lower prompt-injection surface, deterministic verification.

## ADR-NS-002 — SQLite + compressed files before observability cluster

**Decision:** v1 uses SQLite metadata plus partitioned gzip JSONL evidence.

**Rejected initially:** mandatory OpenSearch, Elasticsearch, Kafka, Loki, Prometheus or Redis stack.

**Why:** avoid infrastructure cost until workload proves it necessary.

## ADR-NS-003 — Known-inventory hourly polling

**Decision:** hourly collector polls approved inventory. Active discovery is separate and disabled by default.

**Why:** less traffic, lower privilege, fewer false positives, clearer evidence coverage.

## ADR-NS-004 — SNMP/interface counters before packet capture for bandwidth

**Decision:** use interface counters to calculate bandwidth/utilization whenever available.

**Why:** significantly cheaper and less privacy-sensitive than packet capture.

## ADR-NS-005 — Full PCAP off by default

**Decision:** normal monitoring uses metadata/flow/IDS evidence. PCAP is incident-only.

**Why:** storage, privacy, confidentiality and high-speed capture cost.

## ADR-NS-006 — systemd timers for v1 schedule

**Decision:** hourly and 17:30 jobs use deterministic systemd timers on Linux.

**Why:** no extra Python daemon, reliable boot/missed-run behavior, journal evidence, low resource use.

## ADR-NS-007 — One normal AI call for daily report

**Decision:** uneventful hourly monitoring uses zero AI calls. Daily report targets one compact local inference.

**Why:** AI is most valuable for correlation/explanation, not repetitive polling.

## ADR-NS-008 — Desired inventory separate from observed state

**Decision:** live discovery never overwrites approved inventory.

**Why:** network source-of-truth must be operator controlled.

## ADR-NS-009 — Deep learning is not v1 baseline

**Decision:** rules, rolling robust statistics and template-frequency anomalies are implemented first.

**Why:** cheaper, explainable, train-free and easier to validate. ML/deep models require benchmark evidence.

## ADR-NS-010 — NAS is a mounted storage target

**Decision:** WorkSpace writes to a pre-mounted NAS path; SMB/NFS authentication remains outside model/runtime feature logic.

**Why:** avoid storing NAS credentials in app config and keep filesystem concerns deterministic.

## ADR-NS-011 — Security alert evidence is not autonomous remediation authority

**Decision:** finding/incident analysis can alert/recommend but not mutate network state.

**Why:** monitoring and change authority are separate enterprise capabilities.
