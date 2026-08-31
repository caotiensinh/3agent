# WorkSpace Security Analyst & Network Monitoring — Source Register v1

This file records the primary upstream sources reviewed for the design in `SECURITY_ANALYST_NETWORK_MONITORING_RESEARCH_V1.md`.

The WorkSpace project uses these sources for **concept/procedure extraction only** unless a later dependency/rule admission review explicitly approves reuse.

## Network security monitoring / SIEM

- Wazuh — https://github.com/wazuh/wazuh — https://documentation.wazuh.com/current/quickstart.html
- Security Onion — https://docs.securityonion.net/en/2.4/introduction.html — https://docs.securityonion.net/en/2.4/network.html
- Malcolm — https://github.com/cisagov/Malcolm — https://github.com/cisagov/Malcolm/blob/main/docs/README.md
- Zeek — https://github.com/zeek/zeek — https://docs.zeek.org/en/master/reference/logs/conn.html
- Suricata — https://docs.suricata.io/en/latest/output/eve/eve-json-output.html — https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- Arkime — https://github.com/arkime/arkime
- ntopng — https://github.com/ntop/ntopng — https://www.ntop.org/products/traffic-analysis/ntopng/
- OpenSearch Security Analytics — https://github.com/opensearch-project/security-analytics — https://docs.opensearch.org/latest/security-analytics/

## Polling / inventory / endpoint observation

- Prometheus blackbox_exporter — https://github.com/prometheus/blackbox_exporter
- Prometheus snmp_exporter — https://github.com/prometheus/snmp_exporter
- Prometheus node_exporter documentation — https://prometheus.io/docs/guides/node-exporter/
- LibreNMS — https://docs.librenms.org/Support/Features/
- osquery — https://github.com/osquery/osquery
- NetBox — https://github.com/netbox-community/netbox — https://github.com/netbox-community/netbox/blob/main/docs/introduction.md

## Log transport / observability storage

- rsyslog — https://github.com/rsyslog/rsyslog
- Fluent Bit performance project — https://github.com/fluent/fluent-bit-perf
- Vector — https://vector.dev/docs/introduction/ — https://github.com/vectordotdev/vector
- Grafana Loki — https://github.com/grafana/loki — https://grafana.com/docs/loki/latest/get-started/labels/
- VictoriaMetrics — https://github.com/VictoriaMetrics/VictoriaMetrics — https://docs.victoriametrics.com/victoriametrics/

## Log parsing / AI / anomaly analysis

- Drain3 — https://github.com/logpai/Drain3
- Salesforce LogAI — https://github.com/salesforce/logai
- LogPAI Loglizer — https://github.com/logpai/loglizer
- LogPAI deep-loglizer — https://github.com/logpai/deep-loglizer

## Detection engineering

- Sigma rule repository — https://github.com/SigmaHQ/sigma
- Sigma specification — https://github.com/SigmaHQ/sigma-specification

Important license note: SigmaHQ community rules are released under the Sigma Detection Rule License rather than being treated as unrestricted project text. WorkSpace must review exact rule provenance/license before importing any rule. The initial feature should prefer project-owned rules and clean-room adaptations of general detection concepts.

## Enterprise guidance

- NIST SP 800-92 — Guide to Computer Security Log Management — https://csrc.nist.gov/pubs/sp/800/92/final
- CIS Controls v8.1 — https://www.cisecurity.org/controls/v8-1
- CIS Controls list — https://www.cisecurity.org/controls/cis-controls-list

## Admission rule

No upstream project in this register is automatically approved as a WorkSpace runtime dependency.

A dependency must independently satisfy:

```text
MeasuredBenefit > Complexity + ResourceCost + SecurityRisk + OperationalBurden
```

and must pass provenance, license, supply-chain, privilege, network, credential and data-boundary review before admission.
