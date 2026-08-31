# WorkSpace Security Analyst & Network Monitoring — Operating Workflows v1

## Status

Design-only operational specification. It converts the architecture into implementation-ready workflow contracts without granting any runtime authority.

This document answers four questions for every workflow:

1. **Who** performs each stage?
2. **What input/output** crosses the stage boundary?
3. **What deterministic gate** must pass?
4. **What happens on failure/restart/retry?**

---

# 1. Actors

```text
Scheduler
  time-based trigger only; no device authority

Monitoring Policy Engine
  resolves approved assets, collector profiles, limits and data classes

Collector Broker
  grants only predeclared read-only collector actions to known targets

Collectors
  ICMP/TCP, SNMPv3, local-state and fixed read-only adapters

Normalizer
  converts source-specific records into canonical observation/event schemas

Detection Engine
  exact rules, thresholds, baselines, robust statistics and template checks

Correlation Engine
  groups related findings/evidence using deterministic keys/windows

Evidence Store
  SQLite metadata + bounded compressed evidence partitions

Local AI Analyst
  optional compact analysis only; no collection/remediation authority

Report Builder
  deterministic skeleton, evidence validation and artifact generation

NAS Archive Writer
  writes only validated report bundles to a pre-mounted approved path

Security Analyst / Admin
  reviews findings and authorizes exceptional actions such as packet capture

Specialized UI
  read/inspect/report/control surface; opening it grants no collector authority
```

---

# 2. Hourly workflow — swimlane

```mermaid
sequenceDiagram
    autonumber
    participant S as Scheduler
    participant P as Policy Engine
    participant B as Collector Broker
    participant C as Collector Pool
    participant N as Normalizer
    participant D as Detection Engine
    participant R as Correlation
    participant E as Evidence Store

    S->>P: hourly_cycle(profile_id, scheduled_at)
    P->>P: acquire idempotency/single-run lock
    P->>P: resolve approved inventory snapshot
    P->>B: collector plan + exact targets + budgets
    B->>B: validate read-only capability and scope
    B->>C: bounded collector work items
    par approved target A
      C->>C: ICMP/TCP/SNMP/read-only probe
    and approved target B
      C->>C: ICMP/TCP/SNMP/read-only probe
    end
    C->>N: bounded raw collector results
    N->>N: canonicalize + quality labels
    N->>D: normalized observations
    D->>D: deltas/rates + rules + baseline/statistical checks
    D->>R: finding candidates
    R->>R: correlate/update finding state
    R->>E: findings + hourly aggregates
    N->>E: evidence references/partitions
    E-->>P: commit receipt
    P-->>S: COMPLETED/PARTIAL/FAILED
```

## 2.1 Inputs

```text
monitoring_profile_id
scheduled_at
policy_version
approved_inventory_version/hash
collector_registry_version
previous validated hourly sample refs
```

## 2.2 Outputs

```text
hourly_run_id
run status
coverage percentage
asset observations
interface aggregates
network-health aggregates
finding updates
data-gap updates
source freshness
collector error summary
evidence partition refs
hourly receipt SHA/hash metadata
```

## 2.3 Idempotency key

Recommended:

```text
hourly:<profile_id>:<YYYY-MM-DDTHH Asia/Tokyo>
```

Only one terminal receipt may own the canonical hourly slot. A restart/catch-up creates a new attempt under the same slot key and explicit attempt number; it must not manufacture a historical sample timestamp.

## 2.4 Hard gates

Before collector execution:

```text
feature enabled
profile valid
single-run lock acquired
asset exists in approved inventory
collector action is allowlisted
collector is read-only
exact management target allowed
credential handle reference valid if required
resource budget available
```

After collection:

```text
schema valid
source attribution valid
counter discontinuity classified
observation timestamp in accepted window
raw/evidence size within bound
```

Before completion:

```text
metadata transaction committed
coverage calculated
all failures classified
hourly receipt durable
```

---

# 3. Passive log/event intake — swimlane

```mermaid
sequenceDiagram
    participant SRC as Device/Sensor
    participant SP as Bounded Spool
    participant P as Parser
    participant N as Normalizer
    participant D as Detection/Templates
    participant C as Correlation
    participant E as Evidence Store

    SRC->>SP: syslog / Zeek / Suricata event
    SP->>SP: enforce source/size/rotation bounds
    SP->>P: record
    P->>P: parse using versioned parser
    alt valid record
      P->>N: parsed object
      N->>D: canonical event
      D->>C: zero or more finding candidates
      C->>E: finding/event metadata + evidence ref
    else malformed record
      P->>E: quarantine ref + parser error class
    end
```

## Invariants

- parser errors are observable;
- source identity comes from trusted listener/source mapping;
- raw web/file/log instructions remain data, not authority;
- no passive event can grant a tool capability;
- continuous ingestion has bounded spool/rotation/backpressure behavior.

---

# 4. High/Critical finding — immediate path

```mermaid
sequenceDiagram
    participant D as Detection/Correlation
    participant E as Evidence Store
    participant A as Local AI Analyst
    participant V as Evidence Validator
    participant UI as Security Analyst UI

    D->>E: persist finding + severity + evidence refs
    alt high/critical
      D->>UI: immediate internal alert metadata
      opt AI triage enabled and budget available
        D->>A: compact finding/correlation pack
        A->>V: analysis with evidence IDs
        V->>V: validate references/classification
        alt valid
          V->>E: attach AI analysis
        else invalid/unavailable
          V->>E: AI analysis unavailable/invalid status
        end
      end
    end
```

The immediate alert must not depend on AI availability.

---

# 5. 17:30 daily report — swimlane

```mermaid
sequenceDiagram
    autonumber
    participant S as Scheduler
    participant E as Evidence Store
    participant G as Coverage Gate
    participant B as Report Builder
    participant A as Local AI Analyst
    participant V as Evidence Validator
    participant N as NAS Archive Writer
    participant UI as Security Analyst UI

    S->>E: freeze cutoff 17:30 Asia/Tokyo
    E->>G: today + rolling7d + rolling30d aggregates/findings
    G->>G: coverage/freshness/data-gap evaluation
    G->>B: validated aggregate snapshot
    B->>B: deterministic report skeleton
    B->>B: compact analyst evidence pack
    alt AI available + policy allows
      B->>A: compact pack
      A->>V: narrative + evidence refs
      V->>V: validate refs/labels/no unsupported facts
      alt valid
        V->>B: accepted analyst narrative
      else one bounded retry allowed
        V->>A: validator failure summary only
        A->>V: corrected narrative
      end
    else AI unavailable
      B->>B: deterministic narrative/status
    end
    B->>B: render report.md/report.json/csv/findings set
    B->>B: create manifest.sha256
    B->>N: validated local bundle
    alt NAS available
      N->>N: write temp + verify hash + atomic rename
      N->>E: ARCHIVED receipt
    else NAS unavailable
      N->>E: PENDING_NAS receipt + local spool ref
    end
    E->>UI: report status/index refresh
```

## Daily report input contract

```text
cutoff timestamp
inventory snapshot/version
monitoring policy version
parser/rule versions
coverage summary
hourly aggregate refs
finding refs/open/closed deltas
trend aggregates
sensor health/data gaps
NAS health
```

No unbounded raw log corpus enters the normal daily LLM context.

## Daily report completion gate

A daily report is `COMPLETED` only when:

```text
report cutoff frozen
coverage/data gaps explicitly calculated
deterministic skeleton rendered
all narrative evidence references validated
artifact hashes generated
local report bundle durable
archive state explicitly ARCHIVED or PENDING_NAS
```

`PENDING_NAS` is a valid report generation state but not an archived state.

---

# 6. Weekly canonical archive workflow

Trigger: Sunday 17:30 Asia/Tokyo.

```mermaid
flowchart TD
    A[Freeze weekly cutoff] --> B[Load validated daily/hourly rollups]
    B --> C[Coverage gate]
    C --> D[Weekly trend/finding synthesis]
    D --> E[Render canonical weekly bundle]
    E --> F[Manifest SHA256]
    F --> G[Atomic NAS archive]
```

Idempotency key:

```text
weekly:<profile_id>:<ISO-year>-W<week>
```

Do not re-read all raw logs when validated aggregates/findings suffice.

---

# 7. Monthly canonical archive workflow

Trigger: last local calendar day at 17:30.

```mermaid
flowchart TD
    A[Freeze month cutoff] --> B[Load validated daily/hourly rollups]
    B --> C[Coverage gate]
    C --> D[Month trend/finding synthesis]
    D --> E[Render canonical monthly bundle]
    E --> F[Manifest SHA256]
    F --> G[Atomic NAS archive]
```

Idempotency key:

```text
monthly:<profile_id>:<YYYY-MM>
```

---

# 8. Pending NAS retry workflow

Hourly monitoring may retry validated bundles in `PENDING_NAS` state.

```mermaid
flowchart TD
    H[Hourly post-commit stage] --> Q[Query bounded pending queue]
    Q --> L{NAS mounted/healthy?}
    L -->|No| STOP[Leave PENDING_NAS]
    L -->|Yes| W[Take oldest bounded batch]
    W --> C[Copy/write to temp]
    C --> V[Verify manifest/hash]
    V -->|Pass| A[Atomic rename + ARCHIVED receipt]
    V -->|Fail| F[Archive failure receipt]
```

Rules:

- bounded number/bytes per hourly retry;
- no report regeneration during archive retry;
- no overwrite of different final hash;
- archived report is immutable.

---

# 9. Unknown-device workflow

```mermaid
sequenceDiagram
    participant O as Observation Engine
    participant I as Approved Inventory
    participant D as Detection
    participant E as Evidence Store
    participant UI as Analyst UI

    O->>I: compare observed identity/location
    alt exact approved match
      I-->>O: known
    else unknown/unmatched
      O->>D: NEW_UNKNOWN_DEVICE candidate
      D->>E: finding + observation evidence
      E->>UI: show untrusted observed device
    end
```

No automatic inventory enrollment exists in this workflow.

---

# 10. Manual investigation workflow

```mermaid
sequenceDiagram
    participant U as Analyst
    participant UI as Specialized UI
    participant E as Evidence Store
    participant P as Policy Engine
    participant C as Collector Broker

    U->>UI: open finding
    UI->>E: fetch finding/timeline/evidence refs
    E-->>UI: bounded detail
    opt refresh read-only evidence
      U->>UI: request approved refresh
      UI->>P: exact collector request
      P->>C: authorized bounded read-only work item
      C->>E: new observation/evidence
      E-->>UI: updated finding/timeline
    end
```

There is no free-form command box in the analyst view.

---

# 11. Incident PCAP workflow — exceptional authority

```mermaid
sequenceDiagram
    participant U as Admin/Analyst
    participant UI as Specialized UI
    participant P as Policy Engine
    participant C as Capture Broker
    participant E as Incident Store

    U->>UI: request packet capture for finding/case
    UI->>P: interface + filter + duration + max bytes + TTL + purpose
    P->>P: validate role, scope and hard limits
    P-->>UI: approval fingerprint
    U->>UI: explicit approval
    UI->>C: execute exact approved capture contract
    C->>E: bounded PCAP + hash + receipt
```

Capture authority is not part of normal hourly monitoring.

---

# 12. UI refresh workflow

```mermaid
sequenceDiagram
    participant B as Browser
    participant API as WorkSpace API
    participant E as Aggregate Store

    B->>B: Security Analyst page becomes visible
    loop every 30 seconds while visible
      B->>API: compact status/aggregate request
      API->>E: precomputed aggregate lookup
      E-->>API: compact state
      API-->>B: metadata-only dashboard response
    end
    B->>B: page hidden
    B->>B: stop normal polling
```

The browser never triggers the hourly collector merely by opening/refreshing the page.

---

# 13. Scheduler ownership and catch-up policy

V1 should use operating-system timers rather than add a scheduler framework/service.

Logical timers:

```text
workspace-network-hourly.timer
workspace-network-report-daily.timer
```

Weekly/monthly canonical generation may be evaluated from the 17:30 daily report runner after the cutoff calendar condition, avoiding two additional long-lived services.

Timer responsibilities are limited to invoking deterministic CLI/entrypoints. They do not contain credentials or network commands.

Catch-up rules:

```text
hourly missed cycles -> max one catch-up sample after startup
17:30 report missed  -> one catch-up using original intended cutoff when evidence permits, otherwise explicit delayed-report cutoff/status
weekly/monthly       -> derive from validated period state with idempotency key
```

---

# 14. Concurrency contract

Concurrency is useful only for independent approved targets.

```text
collector workers default: small bounded value (e.g. 4)
per-device concurrent collector actions: 1 by default
per-management-endpoint rate limit: configured
AI calls during normal hourly collection: 0
AI calls in normal daily reporting: 1
```

A later benchmark may change worker count. Higher concurrency is not automatically an optimization.

---

# 15. Workflow observability

Every run exposes compact metadata:

```text
run_id
workflow_type
scheduled_at
started_at
finished_at
status
attempt
policy_version
inventory_hash
asset_count_expected
asset_count_observed
coverage_pct
collector_success_count
collector_failure_count
finding_delta_by_severity
data_gap_count
AI_calls
report_id if applicable
archive_status
failure_classes
```

Do not put raw credentials, raw packet payload, full logs, or full AI prompts into workflow audit metadata.

---

# 16. Implementation mapping

The future implementation should map the above workflows to small components rather than one giant security-agent loop:

```text
network_monitoring/schemas.py
network_monitoring/inventory.py
network_monitoring/policy.py
network_monitoring/collector_broker.py
network_monitoring/collectors/
network_monitoring/normalize.py
network_monitoring/detection.py
network_monitoring/correlation.py
network_monitoring/store.py
network_monitoring/reporting.py
network_monitoring/nas_archive.py
network_monitoring/cli.py
```

AI-specific skills remain procedural modules loaded only for triage/reporting; collectors and authorization remain deterministic runtime code.

---

# 17. Code-start workflow

```mermaid
flowchart LR
    NS0[NS-0 schemas + fixtures] --> NS1[NS-1 read-only collectors]
    NS1 --> NS2[NS-2 storage + normalization]
    NS2 --> NS3[NS-3 rules + findings]
    NS3 --> NS4[NS-4 17:30 reports + NAS]
    NS4 --> NS5[NS-5 local AI analyst]
    NS5 --> NS6[NS-6 optional Zeek/Suricata]
    NS6 --> NS7[NS-7 optional incident PCAP]
```

No later phase may be used to justify weakening an earlier security boundary.
