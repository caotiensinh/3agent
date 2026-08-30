# WorkSpace Security Analyst & Network Monitoring — Report Specification v1

## Schedule

Every day at **17:30 Asia/Tokyo** create one report bundle with:

- Daily window: current reporting day;
- Rolling weekly window: previous 7 days including current day;
- Rolling monthly window: previous 30 days including current day.

Additionally:

- Sunday 17:30 creates a canonical weekly archive;
- last calendar day 17:30 creates a canonical monthly archive.

## Report header

- report ID;
- generated timestamp;
- reporting windows;
- WorkSpace version;
- monitoring policy version;
- inventory version/hash;
- data coverage percentage;
- data gaps;
- archive status.

## Section A — Executive summary

Maximum concise management view:

- overall network status;
- important incidents/findings;
- availability degradation;
- security risk requiring human action;
- whether evidence coverage is sufficient.

## Section B — Asset availability

- monitored assets expected;
- assets successfully observed;
- unavailable assets;
- intermittent assets;
- uptime changes;
- device/sensor data freshness.

## Section C — Network performance

- uplink/interface utilization peaks;
- daily/7d/30d comparisons;
- packet loss and latency;
- interface errors/discards;
- interface flaps;
- unusual asymmetric traffic;
- top talkers if flow telemetry exists.

## Section D — Network topology / inventory drift

- new MAC/device observations;
- disappeared devices;
- IP/MAC changes;
- FDB movement;
- LLDP neighbor changes;
- VLAN/STP changes where monitored;
- differences versus approved inventory.

Discovered state is not automatically promoted to inventory.

## Section E — Logs and security detections

- log source freshness;
- normalized event count;
- counts by severity/category;
- new templates;
- rare/error template increases;
- IDS alerts;
- reviewed rule findings;
- repeated authentication failures;
- sensor health/drop counters.

## Section F — Correlated findings

For every material item:

```text
Finding ID
Severity
Confidence
First/last seen
Assets
Evidence sources
Observed facts
Correlation
Hypothesis, if any
Recommended investigation
Status
```

## Section G — Rolling 7-day trend

Compare today against seven-day context:

- availability;
- traffic/utilization;
- errors;
- finding count/severity;
- new devices/topology changes;
- security rule frequency;
- evidence coverage.

## Section H — Rolling 30-day trend

Focus on slower changes:

- repeated weak links;
- capacity growth;
- recurring devices/interfaces;
- security finding recurrence;
- baseline drift;
- monitoring blind spots;
- storage/archive reliability.

## Section I — Data gaps and monitoring health

Mandatory section.

Examples:

- device unreachable;
- SNMP denied/timeout;
- syslog source stale;
- Zeek/Suricata sensor offline;
- packet-drop visibility unavailable;
- local disk low;
- NAS unavailable;
- AI analysis unavailable.

The report must not interpret a data gap as "no issue".

## Section J — Recommended human actions

Recommendations are non-executing.

Examples:

- inspect switch port X;
- verify cable/device power;
- review device Y authentication failures;
- compare approved change record;
- authorize deeper incident capture if justified.

No configuration command is run from the report.

## Evidence classification

Every narrative item is tagged as one of:

- FACT;
- CORRELATION;
- HYPOTHESIS;
- RISK;
- ACTION;
- DATA GAP.

## Formats

V1 canonical bundle:

- `report.md` — human-readable;
- `report.json` — structured machine-readable report;
- `metrics-summary.csv` — compact summary for analysis/spreadsheet use;
- `findings.jsonl.gz` — referenced finding set;
- `manifest.sha256` — integrity manifest.

PDF is not required for the first implementation; it can be generated later from the verified report without changing analysis semantics.

## NAS paths

```text
<NAS_ROOT>/daily/YYYY/MM/DD/
<NAS_ROOT>/weekly/YYYY/Www/
<NAS_ROOT>/monthly/YYYY/MM/
```

The NAS root must be configured as a pre-mounted filesystem path. WorkSpace does not receive SMB/NFS credentials.

## AI use

One local AI call is the normal daily target.

Input is limited to a compact evidence pack: aggregates, findings, timelines, trend comparisons and data gaps.

AI output is validated against finding/evidence IDs before finalization.

If validation fails after the bounded retry policy, publish the deterministic report and flag AI narrative as unavailable.
