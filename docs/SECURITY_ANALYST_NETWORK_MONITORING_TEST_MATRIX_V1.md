# WorkSpace Security Analyst & Network Monitoring — Test Matrix v1

## Unit / contract tests

- inventory validation;
- collector capability allowlist;
- undeclared target rejection;
- timeout/retry bound;
- SNMP read-only policy;
- counter wrap/reset;
- rate calculation;
- event timestamp normalization;
- template stability;
- secret-like field masking;
- rule evaluation;
- baseline warm-up;
- finding scoring;
- report evidence references;
- NAS path traversal rejection;
- manifest verification.

## Concurrency tests

- maximum collector workers enforced;
- two collectors cannot exceed aggregate network/step budget;
- overlapping hourly run is rejected or skipped with receipt;
- SQLite transaction integrity under concurrent observations.

## Failure tests

- device unreachable;
- partial SNMP response;
- stale syslog;
- malformed syslog/event;
- DB locked/failure;
- disk low/full;
- NAS unavailable;
- LLM unavailable;
- LLM invalid evidence references;
- sensor event source stops.

## Security tests

- log prompt injection remains inert;
- arbitrary command text rejected;
- undeclared subnet rejected;
- SNMP SET unavailable;
- SSH write/config commands unavailable;
- secret values never emitted to log/report;
- full PCAP requires explicit incident authorization;
- NAS root escape rejected;
- external telemetry egress denied.

## Synthetic scenario tests

1. healthy stable LAN;
2. single device offline;
3. uplink congestion;
4. CRC/error growth;
5. interface flap;
6. new unknown MAC;
7. IP/MAC conflict;
8. high-severity Suricata alert;
9. repeated auth failure template;
10. multiple correlated symptoms behind one uplink issue;
11. monitoring sensor failure;
12. maintenance-window expected change;
13. NAS offline at 17:30;
14. AI report generation failure;
15. incomplete evidence coverage.

## Acceptance rule

A scenario is not PASS because the AI narrative sounds correct.

PASS requires deterministic expected findings, evidence references, state transitions and resource/security limits.
