# WorkSpace Security Analyst & Network Monitoring — Implementation Order v1

The first coding sequence after design approval is intentionally narrow:

```text
NS-0A schemas/contracts
-> NS-0B synthetic fixtures
-> NS-0C policy/command broker tests
-> NS-1A local/loopback probes
-> NS-1B SNMP read-only collector
-> NS-1C hourly receipt + coverage
-> NS-1D systemd timer/install contract
```

Only after this path passes enterprise/security/resource gates:

```text
NS-2 logs
-> NS-3 findings/baseline
-> NS-4 17:30 report/NAS
-> NS-5 local AI analyst
-> NS-6 Zeek/Suricata optional sensor
```

Do not begin with UI dashboards or deep-learning anomaly models. First make evidence collection and failure semantics correct.
