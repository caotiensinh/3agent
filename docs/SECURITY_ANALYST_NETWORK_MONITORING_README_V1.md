# WorkSpace Security Analyst & Network Monitoring — Document Index v1

This research package is intentionally **documentation-only**. It exists so architecture can be reviewed before WorkSpace gains real LAN monitoring authority.

## Product position

`Security Analyst & Network Monitoring` is the first specialized WorkSpace product surface. When implemented, it is **pinned in the primary left sidebar** rather than hidden behind chat, Workflow Studio, or an admin-only page.

The current WorkSpace shell is not rewritten into a new frontend framework. The design keeps the existing Python-served HTML/CSS/JavaScript approach and introduces a lightweight persistent navigation rail with progressive migration/regression gates.

## Read in this order

1. `SECURITY_ANALYST_NETWORK_MONITORING_RESEARCH_V1.md`
   - complete research synthesis and target architecture;
2. `SECURITY_ANALYST_NETWORK_MONITORING_RESEARCH_SOURCES_V1.md`
   - upstream source/provenance register;
3. `SECURITY_ANALYST_NETWORK_MONITORING_DECISIONS_V1.md`
   - concise architecture decisions;
4. `SECURITY_ANALYST_NETWORK_MONITORING_SECURITY_MODEL_V1.md`
   - trust, capability, secrets, packet-capture and failure boundaries;
5. `SECURITY_ANALYST_NETWORK_MONITORING_SKILLS_V1.md`
   - clean-room skills and knowledge packs;
6. `SECURITY_ANALYST_NETWORK_MONITORING_WORKFLOW_V1.md`
   - complete product workflow blueprint: passive intake, hourly, detection/correlation, data gaps, 17:30, weekly/monthly, NAS and incident paths;
7. `SECURITY_ANALYST_NETWORK_MONITORING_OPERATING_WORKFLOWS_V1.md`
   - actor/swimlane contracts, input/output, locks, idempotency, retries, restart behavior and implementation mapping;
8. `SECURITY_ANALYST_NETWORK_MONITORING_UI_SIDEBAR_V1.md`
   - pinned sidebar, specialized screens, navigation, refresh/resource policy and UI authorization boundaries;
9. `SECURITY_ANALYST_NETWORK_MONITORING_REPORT_SPEC_V1.md`
   - daily/7d/30d report and NAS output contract;
10. `SECURITY_ANALYST_NETWORK_MONITORING_STORAGE_V1.md`
    - SQLite/evidence/NAS storage and retention design;
11. `SECURITY_ANALYST_NETWORK_MONITORING_RESOURCE_BUDGET_V1.md`
    - CPU/RAM/storage/network/AI budgets and weak-hardware-first targets;
12. `SECURITY_ANALYST_NETWORK_MONITORING_TEST_MATRIX_V1.md`
    - deterministic, security, failure, NAS and resource test coverage;
13. `SECURITY_ANALYST_NETWORK_MONITORING_ACCEPTANCE_V1.md`
    - phase-by-phase implementation gates;
14. `SECURITY_ANALYST_NETWORK_MONITORING_PHASES_V1.md`
    - staged delivery plan;
15. `SECURITY_ANALYST_NETWORK_MONITORING_IMPLEMENTATION_ORDER_V1.md`
    - exact coding order after design approval.

Supporting review/status/glossary documents are listed in the package manifest.

## Workflow summary

```text
continuous passive logs (where available)
        +
hourly known-target read-only polling
        ↓
normalize
        ↓
rules/templates/statistics
        ↓
findings + correlation
        ↓
optional immediate high/critical triage
        ↓
17:30 cutoff
        ↓
today + rolling 7d + rolling 30d
        ↓
1 normal local AI synthesis call
        ↓
evidence validation
        ↓
report bundle + SHA256
        ↓
atomic NAS archive
```

## Code-start gate

Do not start with Zeek/Suricata/OpenSearch/AI.

The first code phase is deliberately:

```text
NS-0 contracts/synthetic fixtures
+
NS-1 known-inventory read-only collectors
```

The first real-network collector must be unable to mutate network state by construction.
