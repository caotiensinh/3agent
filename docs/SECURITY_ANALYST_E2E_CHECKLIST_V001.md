# Security Analyst End-to-End Closure Checklist v0.0.1

Status baseline: 2026-09-02
Target: make WorkSpace Security Analyst usable end-to-end from configuration to live read-only monitoring and chat-assisted analysis.

## Scoring rules

- Total weight is exactly **100%**.
- A task contributes its weight only after its listed acceptance criteria pass on the exact candidate SHA.
- Partial implementation may be reported as engineering progress, but does not count as acceptance PASS.
- Production network access remains approved-inventory-only, read-only and non-disruptive.
- No raw passwords, SNMP communities/auth keys, arbitrary shell commands, subnet expansion or autonomous remediation are allowed.

| ID | Task | Weight | Baseline | Acceptance criteria |
|---|---|---:|---|---|
| SA-01 | Safety contracts and authority boundary | 10% | PASS | `approved_inventory_only`, `read_only=true`, non-disruptive profile, typed secret refs, bounded budgets, no arbitrary target expansion; security tests PASS. |
| SA-02 | Security Configuration Center | 12% | INTEGRATION PENDING | Admin can view/edit General, Policy, Approved Assets and metadata-only Audit; backend validates with production `load_runtime_config`; atomic save; strong real-network confirmation. |
| SA-03 | Installer/runtime bootstrap | 8% | MISSING ON MAIN | `install_chat_gateway.sh` provisions a fail-closed monitoring config path, data directory and secret-ref directory without overwriting custom paths; service loads the config after restart. |
| SA-04 | Approved asset onboarding | 10% | UI PENDING | Admin can add/edit/disable exact assets, collectors, TCP ports, data class and credential refs; raw secrets rejected; router/switch can be represented without subnet scanning. |
| SA-05 | Collector execution and monitoring service lifecycle | 12% | BACKEND EXISTS / E2E OPEN | A bounded collector runner consumes the approved config, persists observations, survives restart, exposes health/last-run/error state and never mutates network devices. |
| SA-06 | Real-LAN read-only collection acceptance | 10% | REACHABILITY ONLY | Explicitly authorized assets `192.168.11.1` and `192.168.11.116` produce real persisted observations through approved collectors; no credentials/PCAP unless separately approved. |
| SA-07 | Observation/event/finding data pipeline | 8% | PARTIAL | Raw approved observations normalize into bounded events/findings with evidence refs; storage/schema migrations and retention behavior pass tests. |
| SA-08 | Security dashboard operational UX | 8% | PARTIAL | Overview, Network, Findings, Events, Assets, Reports and Administration show meaningful configured/empty/error states; no misleading `not_configured` after valid bootstrap; freshness and last collection visible. |
| SA-09 | Chat ↔ Security Analyst integration | 10% | FAILING | WorkSpace chat knows Security Analyst exists, accurately reports its current local state/capabilities, can answer security-status questions from bounded local read models, and never claims the feature is absent when installed. |
| SA-10 | AI analyst/correlation surfacing | 5% | BACKEND PARTIAL | Existing AI analyst/correlation outputs are exposed through bounded read APIs/UI/chat with evidence references and advisory-only authority. |
| SA-11 | Alerts and reports operationalization | 3% | PARTIAL | Alert/report state is visible, deterministic, local-first and bounded; report configuration is only writable once a canonical deployment-owned path exists. |
| SA-12 | Exact-head E2E and self-hosted release gate | 4% | PARTIAL | Targeted tests, full unit suite, EV-01…EV-10, installer CI and self-hosted runner PASS on the same exact SHA; authorized real-LAN acceptance is separately evidenced. |

**Total weight: 100%**

## Baseline acceptance score

Accepted at baseline: **10/100 = 10%** (`SA-01` only).

This intentionally scores usable end-to-end behavior rather than lines of code. Several backend components already exist, but they do not receive acceptance weight until the user-facing chain is connected and verified.

## Execution order

1. SA-02 Configuration Center
2. SA-03 Installer/runtime bootstrap
3. SA-09 Chat ↔ Security Analyst integration
4. SA-04 Approved asset onboarding
5. SA-05 Collector lifecycle
6. SA-06 Real-LAN collection acceptance
7. SA-07 Data pipeline closure
8. SA-08 Dashboard operational UX
9. SA-10 AI analyst/correlation surfacing
10. SA-11 Alerts/reports
11. SA-12 final exact-head E2E gate

## Current authorized real-LAN scope

The current explicit production-LAN acceptance scope is limited to:

- Router: `192.168.11.1`
- Cisco switch: `192.168.11.116`

Existing evidence only proves bounded reachability. It does **not** authorize arbitrary scanning, configuration changes, SNMP write, SSH mutation or packet capture.
