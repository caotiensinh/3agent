# WorkSpace Security Analyst & Network Monitoring — Review Summary v1

This branch is documentation-only.

Research conclusion:

- use read-only SNMP/ICMP + existing log transport as lean baseline;
- treat Zeek/Suricata as optional passive sensor adapters;
- avoid full PCAP by default;
- use SQLite metadata + compressed evidence files before adding a log/time-series cluster;
- use deterministic rules/statistics/templates before AI;
- target zero AI calls in healthy hourly cycles and one compact local AI call for the daily report;
- generate 24h/7d/30d report at 17:30 and archive atomically to a pre-mounted NAS path;
- keep monitoring separate from network mutation/remediation authority.

Requested review outcome before coding:

**APPROVE DESIGN** or specific changes to the research package.
