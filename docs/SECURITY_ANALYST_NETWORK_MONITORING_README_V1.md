# WorkSpace Security Analyst & Network Monitoring — Document Index v1

This research package is intentionally **documentation-only**. It exists so architecture can be reviewed before WorkSpace gains real LAN monitoring authority.

Read in this order:

1. `SECURITY_ANALYST_NETWORK_MONITORING_RESEARCH_V1.md`
   - complete research synthesis and target architecture;
2. `SECURITY_ANALYST_NETWORK_MONITORING_SOURCES_V1.md`
   - upstream source/provenance register;
3. `SECURITY_ANALYST_NETWORK_MONITORING_DECISIONS_V1.md`
   - concise architecture decisions;
4. `SECURITY_ANALYST_NETWORK_MONITORING_SECURITY_MODEL_V1.md`
   - trust, capability, secrets, packet-capture and failure boundaries;
5. `SECURITY_ANALYST_NETWORK_MONITORING_SKILLS_V1.md`
   - clean-room skills and knowledge packs;
6. `SECURITY_ANALYST_NETWORK_MONITORING_WORKFLOW_V1.md`
   - continuous/hourly/17:30/weekly/monthly workflow blueprint;
7. `SECURITY_ANALYST_NETWORK_MONITORING_REPORT_SPEC_V1.md`
   - daily/7d/30d report and NAS output contract;
8. `SECURITY_ANALYST_NETWORK_MONITORING_STORAGE_V1.md`
   - SQLite/evidence/NAS storage and retention design;
9. `SECURITY_ANALYST_NETWORK_MONITORING_ACCEPTANCE_V1.md`
   - phase-by-phase implementation gates.

## Code-start gate

Do not start with Zeek/Suricata/OpenSearch/AI.

The first code phase is deliberately:

```text
NS-0 contracts/synthetic fixtures
+
NS-1 known-inventory read-only collectors
```

The first real-network collector must be unable to mutate network state by construction.
