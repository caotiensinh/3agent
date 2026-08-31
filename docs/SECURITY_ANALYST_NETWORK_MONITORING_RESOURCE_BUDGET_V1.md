# WorkSpace Security Analyst & Network Monitoring — Resource Budget v1

## Principle

Monitoring must not become a larger operational problem than the network it observes.

## Hourly cycle targets

Initial targets for the lean profile:

```text
AI calls in healthy hourly cycle         0
collector retry                          <= 1
collector concurrency                    <= 4 by default
hourly cycle overlap                     forbidden
raw full packet capture                  0
external Internet telemetry egress       0
```

Exact CPU/RAM/network thresholds must be benchmarked on the deployment hardware before promotion.

## Daily report AI target

```text
normal model calls per report            1
bounded retry after validation failure   <= 1
raw log lines in prompt                   0 by default
PCAP in prompt                            0
```

## Resource accounting

Record per cycle/report:

- wall time;
- process CPU time;
- peak RSS if measurable;
- SQLite bytes written;
- evidence bytes raw/compressed;
- NAS bytes copied;
- probe count;
- SNMP request count;
- collector failures/retries;
- AI calls/tokens;
- GPU seconds when telemetry exists.

## Adaptive collection

Do not increase poll frequency globally because one asset is unstable.

Possible later policy:

- stable asset: hourly baseline;
- active finding: temporarily higher sampling for exact asset/interface with bounded TTL;
- after TTL: automatically return to baseline.

Such escalation must be deterministic and budgeted.

## Scale-out criteria

Add another storage/service component only when measured workload crosses a defined threshold and the candidate proves a lower total cost.

Examples:

- VictoriaMetrics if time-series queries/writes become a SQLite bottleneck;
- Loki if log volume/search makes compressed-file retrieval insufficient;
- separate Zeek/Suricata sensor when deep packet analysis would compete with WorkSpace inference.

Hardware scaling is the final response, not the first design choice.
