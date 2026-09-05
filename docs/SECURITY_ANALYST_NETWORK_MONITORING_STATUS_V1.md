# WorkSpace Security Analyst & Network Monitoring — Integration Status v1

Status: **RUNTIME INTEGRATION CANDIDATE / FRESH RELEASE GATES REQUIRED**

The verified research/design baseline is already present on `main` through commit `3c7800da6f0e3a42d4a34cf4215b05decae04303`.

This integration candidate adds the Security Analyst & Network Monitoring runtime derived from PR #105 while preserving the newer WorkSpace runtime that already exists on `main`. In particular, it does not roll back current-request language/context behavior, credential hardening, adaptive-learning changes, current Workflow V4 behavior, or the current frontend UX.

Product integration in this candidate:

- authenticated **Security Analyst** specialized UI;
- query-only monitoring views for overview, network observations, findings, events/logs, approved assets, reports, and admin status;
- approved-inventory-only monitoring contracts;
- optional SNMPv3 read dependency as an explicit package extra;
- deterministic hourly monitoring and reporting components;
- local evidence/read model with read-only SQLite access from chat;
- bounded incident-PCAP approval metadata in web/admin;
- packet capture execution remains a separate POSIX dedicated runner with its own literal confirmation and systemd capability boundary;
- enterprise verification harness and receipt generation.

Security authority remains fail-closed:

- no model-generated LAN command execution;
- no autonomous remediation;
- no router, switch, firewall, VLAN, route, QoS, endpoint, credential, or policy mutation;
- no arbitrary LAN target discovery;
- no continuous/full packet capture;
- web/chat has no packet-capture execution path;
- raw credentials are excluded from monitoring contracts, UI output, logs, reports, CI and evidence receipts.

`NS1-18` real-LAN acceptance remains intentionally **NOT PERFORMED**. Synthetic/unit/CI results must not be represented as production-LAN evidence.

Promotion sequence for this candidate:

1. create one exact integration commit on a dedicated branch;
2. run fresh harness Python 3.11/3.12, installer, portable Ubuntu, Windows, and enterprise verification on that exact SHA;
3. fix deterministic integration defects only in a new session/commit if required;
4. obtain fresh TEST_RELEASE and SEC_GATE evidence on the final exact candidate;
5. re-read live `main` and merge only the exact fully verified candidate.
