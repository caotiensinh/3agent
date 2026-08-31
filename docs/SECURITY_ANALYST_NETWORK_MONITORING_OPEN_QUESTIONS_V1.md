# WorkSpace Security Analyst & Network Monitoring — Pre-Code Decision Checklist v1

The design supplies safe defaults so coding can begin without blocking on every deployment detail, but the following values must eventually be operator-configurable.

## Required before real LAN rollout

- approved management subnet(s);
- approved asset inventory;
- which devices support SNMPv3;
- which legacy devices require SNMPv2c or read-only CLI;
- approved syslog sources;
- whether a SPAN/TAP sensor exists;
- NAS mounted path;
- local retention capacity;
- report recipients/access roles;
- maintenance windows;
- asset criticality tiers.

## Safe defaults if unset during synthetic development

```text
real network access             disabled
active discovery                disabled
SNMP write                      impossible
SSH arbitrary commands          impossible
PCAP                            disabled
Internet egress                 disabled
hourly collector concurrency    4
collector retry                 1
report time                     17:30 Asia/Tokyo
AI hourly call                  none
AI daily calls                  one + bounded validation retry
NAS                             synthetic temporary path
```

## Future decision, not needed for NS-0/NS-1

- Zeek versus Suricata sensor placement;
- NetFlow/sFlow source availability;
- long-term Loki/VictoriaMetrics scale-out;
- advanced ML anomaly detector;
- incident PCAP workflow;
- threat-intelligence update channel;
- autonomous remediation.
