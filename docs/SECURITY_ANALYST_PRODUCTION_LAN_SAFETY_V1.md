# WorkSpace Security Analyst — Production LAN Safety Contract v1

## Purpose

The monitored LAN is a live production environment. Monitoring must never become a source of outage, congestion, configuration drift or packet injection.

This contract is authoritative for `Security Analyst & Network Monitoring ver.0.0.1`.

## Default operating mode

```text
production_safety_profile = non_disruptive_v1
bandwidth_measurement     = counter_only
packet_analysis           = passive_only
active_liveness           = disabled
state_change              = impossible in capability vocabulary
```

Normal hourly monitoring uses existing state and telemetry, not generated load.

## Permitted routine evidence

- SNMPv3 read-only interface/system counters from exact approved assets;
- local OS read-only counters such as `/proc/net/dev`;
- passive syslog/event ingestion;
- existing Zeek/Suricata metadata;
- existing NetFlow/sFlow/IPFIX data where already provided;
- packet/session analysis from an operator-provisioned SPAN/TAP/sensor feed;
- bandwidth, utilization, errors and discards derived from counters and timestamps.

## Bandwidth rule

WorkSpace does not run a throughput benchmark against production infrastructure.

```text
counter_delta = current_counter - previous_counter
bps           = counter_delta * 8 / elapsed_seconds
utilization   = bps / interface_speed_bps * 100
```

Counter reset, reboot, wrap ambiguity, missing samples, invalid intervals or changed interface speed produce `DISCONTINUITY` / `DATA_GAP`. WorkSpace never fabricates a rate.

The following are prohibited as bandwidth measurements:

- iperf / iperf3;
- speedtest;
- generated bulk TCP/UDP transfers;
- stress/load tests;
- synthetic packet floods.

## Packet-analysis rule

Routine packet analysis is passive/off-path only. Preferred sources are SPAN/TAP-connected sensors and Zeek/Suricata/flow metadata.

Routine monitoring cannot inject, replay, mutate or redirect traffic.

Full PCAP capture remains a separately approved incident exception with exact interface/filter/duration/max-bytes/TTL/purpose. AI suspicion alone cannot authorize it.

## Low-impact liveness exception

ICMP echo and TCP connect are disabled by default. They may be enabled only by explicit operator policy for an exact approved asset/port when a passive health signal is unavailable.

When enabled:

- fixed typed operation only;
- exact inventory target only;
- no port ranges;
- no service discovery;
- hard per-asset work cap;
- worker concurrency <= 4;
- timeout <= 5 seconds;
- retry <= 1;
- never used for throughput measurement.

## Permanently forbidden operations

`ver.0.0.1` has no authority for:

- nmap/masscan or service/port-range scanning;
- packet injection/replay/fuzzing;
- SYN/UDP/broadcast flooding;
- ARP poisoning/spoofing or MAC flooding;
- switch/router/AP/firewall/VLAN/ACL/routing/QoS changes;
- interface up/down/flap;
- reboot/reload/reset/power operations;
- firmware or software update;
- credential/user/key changes;
- host blocking/quarantine or autonomous remediation;
- model-generated shell/network commands.

Unknown capability names are rejected by schema/policy before execution.

## Authority layering

```text
Operator-approved inventory
        ↓
non_disruptive_v1 policy
        ↓
typed collection planner
        ↓
capability policy check
        ↓
reviewed collector
        ↓
normalized evidence
```

LLM output is not present in this authority chain.

## Installation safety

A monitoring install is not permission to contact the LAN.

Real collection requires all deployment gates to be deliberately enabled, and the systemd service runs under the dedicated `workspace-monitor` identity. Network sandbox/firewall allowlisting remains an operator deployment responsibility.

## Test rule

CI and development tests use documentation-range addresses, fakes and synthetic fixtures. They must not contact the user's real LAN.

Tests must prove:

1. default policy disables active liveness;
2. default planner emits no ICMP/TCP work;
3. disruptive capability names are outside the closed vocabulary;
4. bandwidth calculations use counters only;
5. any explicit liveness exception remains bounded and exact-target-only.
