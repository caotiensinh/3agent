# WorkSpace OSS Network, Security, Monitoring and Diagnostic Design Blueprint

Status: architecture research baseline  
Repository baseline: `c03b7b9eab76d38a1d50c1b1c6126f0e5adbc844`  
Research date: 2026-09-01  
Scope: architecture and engineering patterns only; no upstream source code is copied into WorkSpace.

## 1. Purpose

This document extracts reusable engineering philosophy, control logic, state handling, data-flow patterns, failure semantics, security boundaries, and test ideas from ten MIT-licensed open-source projects and maps those lessons onto the existing WorkSpace security-monitoring subsystem.

The goal is **not** to turn WorkSpace into a collection of embedded scanners. The goal is to improve the existing local-first, evidence-bounded, deterministic monitoring and security-analysis architecture using patterns that have already survived real-world use.

The ten studied projects are:

1. Uptime Kuma — availability monitoring and state transitions.
2. mitmproxy — typed flow/event lifecycle and extension hooks.
3. Nuclei — compiled detection-as-code and matcher/extractor separation.
4. Beszel — lightweight hub/agent monitoring and transport abstraction.
5. GoAccess — incremental log ingestion, normalization, aggregation and persistence.
6. CrowdSec — staged parsing, behavioral scenarios, temporal buckets and separation of detection from remediation.
7. Subfinder — passive-source fan-out, source isolation, rate-aware collection and deduplication.
8. bandwhich — network-flow to process attribution and OS-specific adapters.
9. httpx — bounded probing, fallback strategy, result enrichment and rate/concurrency control.
10. WatchYourLAN — LAN presence discovery, host identity/history and state-change notification.

## 2. License and clean-room boundary

The licenses were verified from the repositories at research time. Each project is MIT licensed:

| Project | Repository | License path checked | Design use in WorkSpace |
|---|---|---|---|
| Uptime Kuma | https://github.com/louislam/uptime-kuma | `LICENSE` | conceptual patterns only |
| mitmproxy | https://github.com/mitmproxy/mitmproxy | `LICENSE` | conceptual patterns only |
| Nuclei | https://github.com/projectdiscovery/nuclei | `LICENSE.md` | conceptual patterns only |
| Beszel | https://github.com/henrygd/beszel | `LICENSE` | conceptual patterns only |
| GoAccess | https://github.com/allinurl/goaccess | `COPYING` | conceptual patterns only |
| CrowdSec | https://github.com/crowdsecurity/crowdsec | `LICENSE` | conceptual patterns only |
| Subfinder | https://github.com/projectdiscovery/subfinder | `LICENSE.md` | conceptual patterns only |
| bandwhich | https://github.com/imsnif/bandwhich | `LICENSE.md` | conceptual patterns only |
| httpx | https://github.com/projectdiscovery/httpx | `LICENSE.md` | conceptual patterns only |
| WatchYourLAN | https://github.com/aceberg/WatchYourLAN | `LICENSE` | conceptual patterns only |

### Clean-room rule

WorkSpace must preserve a strict design boundary:

- Read upstream code/documentation to understand behavior and engineering principles.
- Record the principle, invariant, state machine, interface shape or algorithmic idea in independent words.
- Design a WorkSpace-native contract that fits existing policy and evidence models.
- Write implementation from the WorkSpace specification, not by translating upstream functions line-by-line.
- Never import upstream template corpora, detection content, default credentials, cloud integrations, or source files as an undeclared dependency.
- If a future implementation directly incorporates upstream code, treat that as a separate dependency/license decision and preserve the required MIT notices.

This document assumes **clean-room conceptual reimplementation**.

## 3. Existing WorkSpace baseline

WorkSpace is already substantially aligned with the strongest patterns found in the ten projects. The correct strategy is therefore additive refinement, not replacement.

### 3.1 Existing core security-monitoring path

At the baseline commit, the security-monitoring package contains dedicated modules for contracts, policy, collection planning, collectors, dispatch, hourly execution, storage, log ingestion, deterministic parsing, behavior analysis, entity context, correlation, findings, incident capture, reporting and UI read models.

The important existing contracts include:

- `AssetInventoryRecord`
- `ObservationRecord`
- `CanonicalEvent`
- `FindingRecord`
- `HourlyRunReceipt`

The current conceptual flow is already close to:

```text
Approved inventory
      |
      v
Policy authorization
      |
      v
Collection plan
      |
      v
Bounded collectors
      |
      v
ObservationRecord
      |
      v
Normalization / parser
      |
      v
CanonicalEvent
      |
      +------------------+
      |                  |
      v                  v
Deterministic rules   Behavior analysis
      |                  |
      +--------+---------+
               v
        Entity context
               |
               v
      Deterministic correlation
               |
               v
         Finding / Incident
               |
               v
       Advisory AI analyst
```

### 3.2 Existing authority invariants that must not regress

`security_monitoring/policy.py` already establishes strong boundaries:

- network scope is `approved_inventory_only`;
- monitoring is read-only;
- production safety profile is non-disruptive;
- active ICMP/TCP liveness is disabled by default;
- bandwidth measurement is counter-only;
- packet analysis is passive-only;
- worker count, timeout and retry count are bounded;
- capability, target host, target port and credential reference are validated against the approved asset record;
- raw credentials are not part of the monitoring contract.

These are **hard architectural invariants**. No pattern imported from Nuclei, httpx, WatchYourLAN, mitmproxy or any future security tool may bypass them.

### 3.3 Existing bounded execution

`security_monitoring/hourly.py` already provides several mature patterns:

- one durable hourly slot;
- lock acquisition to prevent duplicate concurrent collection;
- finalized-slot replay returns the durable receipt instead of recollecting;
- bounded thread pool;
- bounded retries;
- policy failure closes the collector path;
- partial coverage is represented explicitly;
- missing assets become data-gap failure codes;
- inventory and policy fingerprints are recorded.

This is a better enterprise foundation than blindly copying high-concurrency defaults from scanning tools.

### 3.4 Existing log pipeline

`security_monitoring/log_pipeline.py` already includes:

- bounded local spool with backpressure;
- hard record and byte limits;
- atomic evidence partition writes;
- compressed local JSONL evidence;
- SHA-256 receipt material;
- deterministic template normalization;
- deterministic event-rule engine;
- source freshness checks;
- bounded retention deletion.

The GoAccess and CrowdSec lessons should extend this pipeline instead of creating another ingestion subsystem.

### 3.5 Existing deterministic incident correlation

`security_monitoring/correlation_graph.py` already links exact typed evidence across:

```text
DNS -> FLOW -> AUTH -> PROCESS
               + IDS corroboration
```

It requires exact shared entity references, enforces time/event/entity/edge bounds, produces deterministic graph identifiers, and keeps incident authority as `advisory`.

This is a critical WorkSpace advantage: upstream patterns should feed **better normalized evidence into this graph**, not create a competing graph engine.

### 3.6 Existing incident capture boundary

`security_monitoring/incident_capture.py` already treats PCAP as an exceptional capability with:

- default disabled state;
- explicit approved interfaces;
- explicit request schema;
- approved asset targets;
- duration/byte/target/port/snaplen bounds;
- separate approval and execution;
- approval expiry;
- filter and inventory fingerprints;
- capture receipt and retention TTL.

Therefore, mitmproxy/bandwhich packet or flow concepts must not be interpreted as permission to introduce unrestricted packet capture.

---

# 4. Deep analysis of the ten projects

## 4.1 Uptime Kuma

### Engineering philosophy

Uptime Kuma succeeds because it treats monitoring as a **continuous state machine**, not a stream of independent pings. A probe result matters primarily because of its relationship to previous state, retry history and notification policy.

The reusable principle is:

> Observe cheaply, persist the result, classify state, suppress noise, notify on meaningful transitions.

### Core logic

Its public monitor/heartbeat model exposes a useful separation:

- monitor configuration describes what is expected;
- heartbeat describes one observation;
- status expresses interpreted current state;
- retry counters prevent one transient failure from becoming an incident;
- an `important`/transition concept distinguishes ordinary samples from state changes;
- notification routing is downstream of state evaluation.

The key states include UP, DOWN, PENDING and MAINTENANCE. The exact labels are less important than the principle that **unknown/maintenance/transitional state is not equivalent to failure**.

### Failure handling philosophy

Good availability monitoring does not immediately promote a single timeout to an outage. It needs:

1. a bounded attempt;
2. retry budget;
3. consecutive-failure evidence;
4. transition evaluation;
5. optional resend/escalation logic.

### What WorkSpace should adopt

Adopt the state-machine philosophy for asset/service health:

```text
UNKNOWN
  |
  +--> HEALTHY
  +--> DEGRADED
  +--> UNREACHABLE
  +--> MAINTENANCE
  +--> DATA_GAP
```

State changes should be derived from existing observations and must include the evidence IDs that caused the transition.

Add hysteresis rather than creating findings on every failed sample. For example:

```text
healthy -> suspect       after 1 bounded failure
suspect -> unreachable   after policy-defined consecutive evidence
unreachable -> recovering after first good sample
recovering -> healthy    after N good samples
```

The exact thresholds belong in WorkSpace policy, not in model output.

### What not to import

- Do not copy a web-monitor-centric schema into all telemetry.
- Do not allow notification state to become the source of truth.
- Do not treat every liveness failure as a security finding.
- Do not broaden active probing just because a monitor type exists upstream.

### WorkSpace mapping

Primary local targets:

- `contracts.py`: additive health-state contract if required.
- `hourly.py`: state evaluation after observations are durable.
- `findings.py`: emit findings only on meaningful transitions/evidence thresholds.
- `ui_read_model.py`: present state separately from individual measurements.

---

## 4.2 mitmproxy

### Engineering philosophy

mitmproxy's most reusable idea is **a typed lifecycle object travelling through explicit hooks**. The `Flow` abstraction gives multiple protocol/lifecycle stages one stable object that extensions can observe or transform.

The conceptual pattern is:

```text
raw transport activity
       |
       v
 typed flow object
       |
       +--> lifecycle event A
       +--> lifecycle event B
       +--> lifecycle event C
       |
       v
 durable/result representation
```

### Extension model

Addons subscribe to well-known lifecycle hooks. This is superior to arbitrary callbacks because the runtime owns ordering and the extension receives a constrained object at a known stage.

For WorkSpace this suggests **typed, stage-specific adapters**, not dynamically executing arbitrary plugins.

### Strong idea: preserve one identity through the lifecycle

A connection/request should keep a stable correlation identity across parsing/enrichment. This reduces accidental duplication and makes evidence lineage easier.

### Security lesson

mitmproxy is powerful precisely because it can modify traffic and terminate TLS. That power is inappropriate as a default WorkSpace monitoring capability.

WorkSpace should adopt:

- flow identity;
- lifecycle events;
- protocol adapter separation;
- structured metadata extraction.

WorkSpace should reject by default:

- transparent interception;
- TLS man-in-the-middle;
- request/response mutation;
- arbitrary traffic rewriting;
- unrestricted packet/network authority.

### WorkSpace mapping

A WorkSpace-native `FlowObservation` concept, if introduced, should be **metadata/evidence only** and should ultimately normalize into existing `CanonicalEvent` plus entity references.

Likely local integration points:

- `passive_sensors.py`
- `passive_ingest.py`
- `entity_context.py`
- `correlation_graph.py`

The flow object must never be a new execution authority.

---

## 4.3 Nuclei

### Engineering philosophy

Nuclei demonstrates a powerful separation between **declarative detection intent** and **execution machinery**.

A template is loaded, validated and compiled before execution. Matchers and extractors are reusable operators rather than embedded ad-hoc conditions inside every protocol implementation.

Conceptually:

```text
Rule source
   |
   v
Parse + validate
   |
   v
Compile
   |
   +--> protocol plan
   +--> matcher plan
   +--> extractor plan
   |
   v
Authorized execution
   |
   v
Typed results
```

### Optimization philosophy

Nuclei clusters identical requests so repeated rules do not cause repeated network work. This is the correct meaning of optimization for WorkSpace:

> eliminate duplicate collection before increasing concurrency.

This directly matches WorkSpace's constraint-first/PicoLM-inspired philosophy.

### Detection content lesson

Detection logic should have:

- stable rule ID;
- metadata/version;
- explicit inputs;
- typed predicates;
- optional extraction;
- severity as metadata, not proof;
- deterministic validation;
- test fixtures.

### Major safety adaptation

Nuclei is a vulnerability scanner and can intentionally generate active requests. WorkSpace must separate two things that Nuclei often combines:

1. **rule compilation and matching** — broadly reusable;
2. **active probe execution** — restricted by WorkSpace capability policy.

A rule must never grant itself permission to run a probe. Authorization must be external and deterministic.

Correct WorkSpace flow:

```text
Rule compile
    |
    v
Required capabilities
    |
    v
Policy engine / approved inventory
    |
    +--> denied -> deterministic receipt
    |
    +--> allowed -> bounded work item
                    |
                    v
                 result
                    |
                    v
             matcher/extractor
```

### What WorkSpace should adopt

- rule-as-data;
- compile before execute;
- deterministic matcher/extractor library;
- request/work-item clustering;
- template validation harness;
- explicit rule version/fingerprint;
- fixture-driven regression tests.

### What WorkSpace should reject

- rule-defined authority;
- unrestricted target lists;
- large default concurrency;
- automatic external template download in confidential runtime;
- cloud reporting;
- destructive or state-changing checks without a separately designed exceptional capability.

### WorkSpace mapping

The current `EventRule` is intentionally simple. A future WorkSpace rule compiler can extend it without replacing `CanonicalEvent`, `FindingRecord` or `MonitoringPolicyEngine`.

Potential local modules:

- existing `log_pipeline.py` rule engine;
- new deterministic `rules/` package if complexity justifies it;
- existing `plan.py` for compiled authorized work;
- existing `findings.py` for durable outcomes.

---

## 4.4 Beszel

### Engineering philosophy

Beszel is valuable because it keeps the edge agent lightweight and places aggregation/management in a hub. It also abstracts hub-agent communication behind a transport interface, allowing WebSocket and SSH implementations without forcing the business logic to depend on one transport.

Conceptually:

```text
Host collectors
     |
     v
Local lightweight agent
     |
     v
Transport interface
  /        \
SSH      WebSocket
  \        /
     v
Central hub
     |
     v
History / alerts / UI
```

### Reusable principles

1. **Collection belongs close to the resource.**
2. **Transport is replaceable.**
3. **Metrics contract should be transport-neutral.**
4. **Identity/authentication is separate from metrics.**
5. **A sleeping/offline agent is not equivalent to a negative metric.**

### WorkSpace relevance

For 100–10,000 endpoints, central polling of every local detail eventually becomes inefficient and operationally fragile. An optional WorkSpace edge collector can reduce central authority and bandwidth by producing compact, typed evidence locally.

However, WorkSpace confidential architecture adds a stronger constraint than Beszel: a hub/agent design must not become an uncontrolled egress path.

### Required WorkSpace adaptation

A WorkSpace edge agent must be:

- local/LAN only by policy;
- mutually authenticated;
- asset-bound;
- capability-limited;
- unable to execute arbitrary shell commands;
- unable to accept arbitrary collection configuration from an untrusted central peer;
- able to spool bounded evidence while disconnected;
- able to prove config/policy fingerprint with each batch.

### Transport lesson

Define transport as a narrow interface around typed requests/results, not raw command execution.

Bad interface:

```text
run(command: str) -> bytes
```

Preferred interface:

```text
request(action: ApprovedAction, contract: TypedRequest) -> TypedResponse
```

### WorkSpace mapping

Future scale-out path can reuse:

- existing collector/result contracts;
- existing capability decisions;
- existing evidence fingerprints;
- bounded spool pattern;
- separate transport adapter.

Do not build this until current single-node contracts and replay harness are stable.

---

## 4.5 GoAccess

### Engineering philosophy

GoAccess is a useful model for a high-throughput monitoring pipeline because it minimizes abstraction overhead around the hot path:

```text
read -> parse -> normalize -> aggregate -> persist/report
```

It uses in-memory structures for speed while supporting persistence and incremental processing.

### Strongest reusable lesson: resumable ingestion

GoAccess records progress information such as file identity/inode, previously parsed position/snippet and timestamp. It can distinguish normal append from rotation/truncation and avoid reparsing all historical input.

This is highly relevant to WorkSpace's large Cisco/Windows/Linux/network logs.

### WorkSpace-native checkpoint concept

A source checkpoint should bind at least:

- source ID;
- source type;
- immutable source identity where available;
- file identity/inode/device or equivalent cursor;
- byte/line cursor;
- last accepted event timestamp;
- parser version;
- small content fingerprint around the boundary;
- checkpoint generation/fingerprint.

Resume logic should fail safely:

```text
checkpoint compatible -> continue
rotation detected      -> start new generation
truncation detected    -> start new generation + discontinuity evidence
parser version changed -> explicit reparse policy, never silent reuse
checkpoint corrupt     -> data-gap/discontinuity receipt
```

### What to adopt

- incremental ingestion;
- minimal hot-path transformations;
- deterministic parser configuration;
- bounded in-memory aggregation;
- persistence as a resumability mechanism, not only long-term storage.

### What not to import

- web-access-log-specific schema;
- aggregation that discards evidence lineage required by security investigations;
- unbounded memory growth for high-cardinality keys.

### WorkSpace mapping

Extend `BoundedLogSpool`/ingest with a durable source-checkpoint contract. Keep raw evidence and normalized event hashes so an aggregate can always be traced back to evidence.

---

## 4.6 CrowdSec

### Engineering philosophy

CrowdSec's best architectural lesson is the staged separation of:

```text
Acquisition
   -> raw normalization
   -> application parsing
   -> enrichment
   -> temporal scenario evaluation
   -> alert
   -> decision
   -> external remediation
```

This pipeline makes it possible to reason about failure and false positives at each stage.

### Parsing stages

The parser stages normalize heterogeneous sources before application-specific extraction and enrichment. WorkSpace already has the right primitives for this and should preserve the same separation.

### Behavioral detection

CrowdSec scenarios use temporal buckets. A typical scenario includes:

- event eligibility filter;
- group key, often source identity;
- optional distinct key to avoid duplicate inflation;
- capacity;
- leak rate/time behavior;
- overflow predicate;
- post-overflow checks/allowlists.

The key idea is important:

> Security meaning often comes from **rate and sequence**, not a single event.

### WorkSpace-native adaptation

Implement deterministic behavior windows as evidence aggregation, not automatic blocking.

Example conceptual contract:

```text
BehaviorRule
- rule_id
- eligible categories
- grouping roles
- distinct roles/fields
- window_seconds
- threshold
- cooldown/hysteresis
- minimum evidence count
- severity ceiling
```

Output:

```text
BehaviorFinding
- exact event refs
- exact entity refs
- time window
- count/distinct count
- rule fingerprint
- advisory authority
```

### Most important separation to preserve

CrowdSec explicitly separates detection from remediation components. WorkSpace should take this separation even further:

```text
Detection -> Finding -> Analyst recommendation
```

No firewall action, account disable, quarantine or process kill should be reachable from the detection rule itself.

### What to adopt

- staged parser architecture;
- scenario/rate/sequence detection;
- distinct counting;
- post-detection allowlist/exception stage;
- metrics for parsed/unparsed/whitelisted/poured/detected events;
- separation of detection and enforcement.

### What to reject by default

- automatic bouncer/remediation behavior;
- cloud/community signal sharing from confidential data;
- implicit installation/download of external detection content.

### WorkSpace mapping

Primary local targets:

- `parsers.py` / `enriched_parsers.py`;
- `behavior_intelligence.py` / `behavior_risk.py`;
- `behavior_store.py`;
- `findings.py`;
- `correlation_graph.py`.

---

## 4.7 Subfinder

### Engineering philosophy

Subfinder is intentionally narrow: passive discovery from multiple independent sources. Its strongest lesson is not subdomain enumeration; it is **fan-out collection with source-specific constraints followed by normalization and deduplication**.

Conceptually:

```text
Input
  |
  +--> Source A --+
  +--> Source B --+
  +--> Source C --+--> normalize -> dedupe -> validate -> result
```

### Rate-limit lesson

More concurrency is not automatically better. Passive sources impose different limits and increasing worker count can decrease result quality by triggering throttling.

For WorkSpace this generalizes to:

> Concurrency is a policy budget per source/capability, not a global performance knob.

### Source adapter contract

Each source should declare:

- source ID/version;
- trust/data class;
- acquisition mode;
- required authority/capability;
- rate budget;
- timeout budget;
- retry/backoff class;
- output schema;
- freshness expectation.

### WorkSpace use

The same model applies to LAN asset discovery sources:

- approved ARP observations;
- DHCP lease exports;
- DNS cache/logs;
- switch MAC tables via SNMPv3 read;
- LLDP tables via approved read-only interfaces;
- existing inventory;
- local OS neighbor tables.

These should not individually create assets as trusted truth. They should produce **discovery evidence** that is reconciled against the approved inventory.

### Crucial distinction

```text
Observed candidate != approved asset
```

A newly discovered MAC/IP must remain `candidate/unapproved` until operator policy admits it. Discovery must never broaden monitoring authority automatically.

---

## 4.8 bandwhich

### Engineering philosophy

bandwhich converts anonymous traffic into operational context by correlating packet/connection information with local process ownership using OS-specific mechanisms.

Conceptually:

```text
packet/flow
   |
   v
local socket tuple
   |
   v
OS attribution adapter
   |
   v
process / PID / user context
```

This is extremely valuable for incident diagnosis because `10.0.0.4 -> 8.8.8.8:443` is much less useful than a typed relationship such as:

```text
asset -> process -> user -> flow -> destination
```

### Architecture lesson

OS-specific implementation belongs behind an adapter. Linux `/proc`, macOS tooling and Windows APIs are different mechanisms for the same logical contract.

### Security lesson

Process attribution can require elevated privileges and can expose sensitive cross-user traffic. Therefore WorkSpace must treat attribution as a separate capability and minimize retained identity data.

Recommended handling:

- store typed/hash references where raw identity is unnecessary;
- never grant packet capture because process attribution is requested;
- separate socket-table attribution from full packet capture;
- make OS adapter failure explicit (`unsupported`, `permission_denied`, `stale_mapping`).

### WorkSpace mapping

The current correlation graph already supports PROCESS and entity-context stages. bandwhich's strongest contribution is therefore an **evidence producer**, not a new analytics engine.

Potential future adapters should normalize into existing entity references and correlation rules.

---

## 4.9 httpx

### Engineering philosophy

httpx treats probing as a configurable, composable pipeline with explicit timeout, retry, thread and rate-limit controls. It also uses sensible protocol fallback: HTTPS first, then HTTP when appropriate.

### Reusable logic

A diagnostic probe should have:

- a typed target;
- protocol/scheme plan;
- connection timeout;
- response read limit;
- retry budget;
- host error budget;
- rate budget;
- bounded concurrency;
- fallback policy;
- structured metadata result.

### Strong lesson: result reliability under concurrency

High worker count is only useful when there are guardrails around timeouts, rate limits and host errors. WorkSpace should **not** copy httpx defaults; its production policy is intentionally far more conservative. It should copy the explicit budgeting model.

### WorkSpace-safe probe model

Every probe must be compiled from approved inventory and pass `MonitoringPolicyEngine` before execution.

A WorkSpace probe rule cannot accept arbitrary URLs/hosts from AI output.

Correct hierarchy:

```text
Operator-approved asset
       |
       v
Approved capability + port
       |
       v
Compiled probe work item
       |
       v
Bounded executor
       |
       v
ObservationRecord
```

### Useful diagnostics to adapt later

Within explicit policy, safe metadata-oriented probes may include:

- TCP connect availability;
- TLS certificate metadata;
- HTTP status/latency/header metadata;
- RTSP/ONVIF service metadata where explicitly approved;
- protocol fallback only when both variants are pre-authorized.

### What not to import

- arbitrary input target expansion;
- broad port ranges;
- autonomous recursive probing;
- screenshot/crawling or secondary-host discovery by default;
- cloud output;
- high default concurrency.

---

## 4.10 WatchYourLAN

### Engineering philosophy

WatchYourLAN turns repeated ARP observations into an inventory-like history of host presence. The valuable pattern is the separation between **scan observation** and **host state/history**.

Conceptually:

```text
ARP observation
      |
      v
normalized MAC/IP identity
      |
      v
known host lookup
      |
      +--> new candidate
      +--> known online
      +--> state changed
      +--> absent/offline
      |
      v
history + notification
```

### Operational lesson

Presence history is more valuable than a one-time scan. A device appearing for the first time, moving IP, disappearing for a long interval, or oscillating online/offline are different diagnostic/security signals.

### Security lesson

WatchYourLAN requires LAN-level scanning/host networking. WorkSpace cannot simply inherit that authority. Any active ARP scanner must be separately authorized and bounded.

Prefer evidence sources in this order:

1. existing passive/management data already available;
2. approved switch/DHCP/neighbor-table reads;
3. explicit, bounded active LAN discovery only when policy enables it.

### WorkSpace identity model

Do not identify a device solely by mutable IP address. Prefer a confidence-weighted identity model from:

- approved asset ID;
- MAC reference where legitimately available;
- switch port/interface evidence;
- hostname/DHCP evidence;
- management address;
- historical continuity.

New observations must never auto-create an approved asset.

---

# 5. Cross-project distilled engineering principles

## Principle 1 — Separate observation from interpretation

Raw/typed evidence is not a finding.

```text
Observation -> Event -> Correlation/Behavior -> Finding -> Recommendation
```

This prevents model or rule layers from rewriting history.

## Principle 2 — Compile before execute

Any declarative rule/probe must be validated and compiled to a bounded execution plan before touching the network.

A compiled plan must contain only:

- approved asset IDs;
- approved capabilities;
- explicit ports/protocols;
- timeout/retry/rate/byte budgets;
- rule/policy/inventory fingerprints.

## Principle 3 — Authority is external to detection content

A rule may say what evidence it needs. It may not grant itself permission to collect that evidence.

## Principle 4 — Passive first

Prefer existing logs, counters, exports and local metadata before active probes.

## Principle 5 — State transitions are more meaningful than samples

Use hysteresis, consecutive evidence and recovery states. Avoid alert storms.

## Principle 6 — Time is part of the data model

Freshness, windows, retry spacing, behavior rates and incident correlation all require explicit time semantics.

## Principle 7 — Identity must be typed and evidence-backed

IP address alone is not an asset identity. Process/user/service/host relationships need typed references and exact evidence lineage.

## Principle 8 — Bound everything

Bound:

- workers;
- per-source requests;
- retries;
- timeout;
- response bytes;
- spool bytes;
- events per run;
- entities per graph;
- edges per graph;
- bucket cardinality;
- history retention;
- capture duration/bytes;
- candidate asset growth.

## Principle 9 — Backpressure is a valid result

When a spool, queue or budget is full, the system should return an explicit status rather than silently dropping or allocating without limit.

## Principle 10 — Partial truth is explicit

A run with 8/10 assets is not success and is not total failure. Coverage must remain part of the receipt.

## Principle 11 — Resume needs provenance

Incremental ingestion must bind checkpoints to source identity and parser version.

## Principle 12 — Detection and remediation are separate products

The security-analysis runtime produces evidence-backed advisory findings. Enforcement requires a separately authorized mechanism and should not be added implicitly.

## Principle 13 — Optimize duplicated work before concurrency

Cluster equivalent requests/work items, cache deterministic transformations with provenance, and deduplicate evidence before increasing worker count.

## Principle 14 — Protocol and OS specifics belong behind adapters

Core analytics should not know whether a metric arrived over SNMPv3, WebSocket, SSH transport, local `/proc`, Windows API or a log export.

## Principle 15 — AI explains; deterministic code proves

LLMs may summarize, prioritize and propose hypotheses. They must not invent evidence, change canonical state, or widen authority.

---

# 6. Target WorkSpace architecture

The recommended architecture extends the existing package rather than replacing it.

```text
                       OPERATOR APPROVED INVENTORY
                                  |
                                  v
                         POLICY / CAPABILITY GATE
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
             PASSIVE SOURCES              ACTIVE READ-ONLY
        logs/counters/local metadata       approved probes only
                    |                           |
                    +-------------+-------------+
                                  v
                         COMPILED WORK PLAN
                    dedupe / cluster / budgets
                                  |
                                  v
                         COLLECTION ADAPTERS
                                  |
                                  v
                          ObservationRecord
                                  |
                    +-------------+--------------+
                    |                            |
                    v                            v
            INCREMENTAL CHECKPOINT          EVIDENCE PARTITION
                    |                            |
                    +-------------+--------------+
                                  v
                            NORMALIZATION
                                  |
                                  v
                           CanonicalEvent
                                  |
                 +----------------+----------------+
                 |                |                |
                 v                v                v
          Stateless rules   Behavior windows  Health state
                 |                |                |
                 +----------------+----------------+
                                  v
                           ENTITY CONTEXT
                                  |
                                  v
                      DETERMINISTIC CORRELATION
                        DNS/FLOW/AUTH/PROCESS/IDS
                                  |
                                  v
                         FINDING / INCIDENT GRAPH
                                  |
                                  v
                         LOCAL AI ANALYST
                       explain / rank / propose
                                  |
                                  v
                     OPERATOR-FACING RECOMMENDATION

                NO automatic firewall / shell / quarantine
```

---

# 7. Proposed WorkSpace-native abstractions

These are design targets, not permission to create parallel subsystems.

## 7.1 SourceDescriptor

Purpose: describe collection-source constraints independently of collector implementation.

Recommended fields:

```text
source_id
source_type
acquisition_mode: passive | active_readonly
required_capability
expected_interval_seconds
rate_budget
retry_class
max_record_bytes
data_class
adapter_version
```

## 7.2 SourceCheckpoint

Purpose: resumable log/stream ingestion.

Recommended fields:

```text
checkpoint_id
source_id
source_generation
source_identity_fingerprint
cursor_kind
cursor_value
last_event_at
boundary_sha256
parser_version
created_at
schema_version
```

## 7.3 CompiledWorkItem extension

Current collection planning should eventually carry enough provenance to prove why each network operation is allowed:

```text
work_item_id
asset_id
capability
protocol
host_ref
port
rule_refs
policy_fingerprint
asset_fingerprint
plan_fingerprint
timeout_seconds
max_retries
rate_class
max_response_bytes
```

The concrete host can remain internal where privacy requires; receipts can use hashes.

## 7.4 HealthStateRecord

Purpose: Uptime-Kuma-inspired state transitions without tying health to a single probe.

Recommended fields:

```text
asset_id / service_ref
previous_state
new_state
transition_at
evidence_refs
consecutive_failure_count
consecutive_success_count
transition_rule_id
transition_rule_fingerprint
```

## 7.5 BehaviorRule / BehaviorWindowReceipt

Purpose: CrowdSec-inspired temporal detection, advisory only.

Recommended capabilities:

- filter by canonical category/source type;
- group by typed entity references;
- distinct counting;
- fixed/sliding bounded window;
- threshold;
- cooldown;
- exact event refs;
- overflow/firing receipt;
- rule fingerprint.

## 7.6 DiscoveryCandidate

Purpose: WatchYourLAN/Subfinder-inspired discovery without automatically expanding authority.

Recommended states:

```text
observed
reobserved
candidate
matched_to_approved_asset
conflict
expired
```

There must be no automatic transition from `candidate` to `approved`.

## 7.7 FlowAttribution

Purpose: bandwhich/mitmproxy-inspired typed flow/process context.

Recommended fields should favor references over raw personal identifiers:

```text
flow_ref
asset_ref
source_ip_ref
destination_ip_ref
service_ref
process_ref
auth_user_ref
observed_at
evidence_ref
attribution_confidence
adapter_version
```

---

# 8. Pattern decision matrix

| Upstream pattern | Decision | WorkSpace adaptation |
|---|---|---|
| Uptime Kuma heartbeat/state transition | ADOPT | deterministic health state + hysteresis |
| Uptime Kuma broad monitor types | ADAPT | only capabilities approved by WorkSpace policy |
| mitmproxy Flow lifecycle | ADOPT | metadata/evidence lifecycle only |
| mitmproxy TLS interception/mutation | REJECT default | exceptional future product only, not monitoring |
| Nuclei declarative rules | ADOPT | WorkSpace rule DSL/contract |
| Nuclei compile/validate before execute | ADOPT | mandatory |
| Nuclei request clustering | ADOPT | dedupe authorized work items |
| Nuclei arbitrary active scanning | REJECT default | inventory/capability bounded only |
| Beszel hub-agent split | ADAPT | optional enterprise scale-out after local contracts stable |
| Beszel transport abstraction | ADOPT | typed transport, no shell abstraction |
| GoAccess incremental resume | ADOPT | provenance-bound source checkpoints |
| GoAccess in-memory aggregation | ADAPT | hard cardinality/memory bounds + evidence lineage |
| CrowdSec staged parsing | ADOPT | align existing parser/enrichment path |
| CrowdSec leaky-bucket scenarios | ADOPT | deterministic advisory behavior windows |
| CrowdSec bouncer remediation | REJECT default | recommendation only |
| Subfinder source fan-out | ADOPT | LAN/data-source adapters |
| Subfinder passive-first | ADOPT | default acquisition philosophy |
| bandwhich process attribution | ADAPT | separate privileged capability; typed/hash refs |
| bandwhich unrestricted packet sniffing | REJECT default | existing PCAP approval boundary governs |
| httpx timeout/retry/rate budgets | ADOPT | stricter WorkSpace limits |
| httpx protocol fallback | ADAPT | only among pre-authorized protocol/ports |
| httpx arbitrary target expansion | REJECT | approved inventory only |
| WatchYourLAN presence history | ADOPT | candidate/history state |
| WatchYourLAN automatic LAN scan posture | REJECT default | passive/read-only sources first |

---

# 9. Failure semantics

WorkSpace should standardize failures across adapters instead of allowing every collector to invent text messages.

Recommended classes:

```text
POLICY_DENIED
TARGET_NOT_APPROVED
CAPABILITY_NOT_APPROVED
RATE_BUDGET_EXHAUSTED
QUEUE_BACKPRESSURE
SOURCE_STALE
SOURCE_ROTATED
SOURCE_TRUNCATED
CHECKPOINT_INVALID
CONNECT_TIMEOUT
READ_TIMEOUT
REMOTE_UNREACHABLE
REMOTE_PROTOCOL_ERROR
RESPONSE_BOUND_EXCEEDED
PARSER_UNSUPPORTED
PARSER_ERROR
ATTRIBUTION_UNAVAILABLE
ATTRIBUTION_PERMISSION_DENIED
PARTIAL_COVERAGE
DATA_GAP
STORAGE_FAILED
```

Rules:

- Exact exception strings are not canonical evidence.
- Stable reason codes are canonical.
- A failure should not be retried unless its retry class explicitly permits it.
- Policy denials are never retried.
- Parsing failures do not authorize alternate network collection.
- Missing evidence lowers confidence/coverage; it must not be silently inferred.

---

# 10. Concurrency, rate control and backpressure

The upstream projects demonstrate two opposing failure modes:

1. insufficient concurrency can make monitoring stale;
2. excessive concurrency can trigger rate limiting, exhaust sockets, overload SQLite/storage, or create self-inflicted network noise.

WorkSpace should remain conservative.

Recommended hierarchy:

```text
Global production bound
   |
   +--> capability bound
   |      |
   |      +--> source bound
   |
   +--> per-asset bound
```

The existing production `max_workers <= 4` is a good baseline for direct LAN monitoring. Any future scale increase should be measured with exact-head benchmarks rather than increased by assumption.

Before increasing workers:

1. remove duplicate work;
2. batch compatible reads;
3. cache deterministic transformations;
4. use local agents where scale requires it;
5. rate-limit per target/source;
6. measure queue wait and end-to-end freshness.

---

# 11. Detection confidence and severity discipline

A finding should separate:

- source severity;
- correlation strength;
- evidence coverage;
- confidence;
- investigation priority.

The current correlation graph already contains an important safety rule: multi-stage evidence can raise investigation priority without manufacturing a critical severity when no critical source evidence exists.

Keep that philosophy.

Recommended confidence dimensions:

```text
identity_exactness
source_count
stage_count
temporal_coherence
evidence_freshness
coverage
parser_confidence
attribution_confidence
```

An LLM may summarize these fields but must not override the deterministic calculation.

---

# 12. Observability of the monitoring system itself

A monitoring platform that cannot report its own blind spots is unsafe.

Required self-metrics should include:

- expected assets vs observed assets;
- source freshness;
- parse success/failure counts;
- unparsed-event counts;
- queue/spool utilization;
- evidence partition count/bytes;
- checkpoint lag;
- retry counts;
- timeout counts;
- policy-denied work count;
- candidate asset count;
- behavior-window cardinality;
- correlation event/entity/edge utilization versus bounds;
- analysis latency;
- AI invocation count and evidence coverage;
- storage failures.

The UI should distinguish:

```text
TARGET PROBLEM
from
MONITORING BLIND SPOT
```

For example, `switch unreachable` and `collector had no permission` must never render as the same condition.

---

# 13. Data minimization and privacy

Network/security telemetry can expose usernames, processes, destinations, DNS names and device identities. WorkSpace should maintain a typed-reference strategy:

- raw credentials never enter event contracts;
- raw identities are retained only when required for an operator-approved use case;
- correlations should prefer typed hash references;
- reports should include the minimum human-readable identity needed for action;
- evidence partitions remain local/confidential;
- public research zone must not receive internal telemetry;
- cloud upload/reporting features present in upstream tools are not adopted into confidential runtime.

---

# 14. Rule lifecycle and governance

Nuclei and CrowdSec show the value of content-driven detection, but enterprise WorkSpace needs stronger governance.

Recommended lifecycle:

```text
DRAFT
  -> STATIC_VALIDATED
  -> FIXTURE_TESTED
  -> SECURITY_REVIEWED
  -> APPROVED
  -> ACTIVE
  -> DEPRECATED
  -> REVOKED
```

Each active rule should have:

- immutable rule ID/version;
- author/source provenance;
- description;
- input contract;
- required capabilities;
- severity ceiling;
- test fixture IDs;
- expected positive/negative outcomes;
- policy compatibility;
- fingerprint;
- approval record.

A rule update is a new version/fingerprint and invalidates deterministic caches derived from the old version.

---

# 15. Harness philosophy derived from the research

The future implementation harness should not begin with live-network tests. It should begin with deterministic replay.

Recommended layers:

### Layer A — contract tests

Validate malformed inputs, bounds, unknown fields, identity conflicts and fingerprint stability.

### Layer B — parser fixtures

Raw fixture -> exact normalized `CanonicalEvent`.

### Layer C — rule fixtures

Canonical events -> exact matched rule IDs / no-match expectations.

### Layer D — behavior replay

Ordered event stream + deterministic clock -> exact behavior-window result.

### Layer E — health state replay

Observation sequence -> exact transition sequence.

### Layer F — correlation replay

DNS/FLOW/AUTH/PROCESS/IDS fixture -> exact graph IDs, edge rules and evidence refs.

### Layer G — policy-negative tests

Ensure arbitrary host, port, capability, raw secret, active liveness and capture requests fail closed.

### Layer H — boundedness tests

Prove limits for events, entities, edges, spool bytes, records, workers, retries, response bytes and buckets.

### Layer I — fault injection

Timeout, partial parse, checkpoint corruption, storage exception, agent disconnect and stale source should produce stable reason codes.

### Layer J — exact-head CI evidence

All acceptance evidence must bind to the exact Git commit under review.

This is only the architecture specification. The concrete checklist and harness implementation are intentionally deferred until after this document is committed, per the requested sequencing.

---

# 16. Suggested adoption order

The recommended order minimizes risk and maximizes reuse of existing code.

## Phase 1 — strengthen deterministic ingestion and replay

Adopt GoAccess/CrowdSec concepts:

- durable source checkpoints;
- parser-stage metrics;
- fixture/replay harness;
- discontinuity evidence.

Why first: better input quality improves every later detector.

## Phase 2 — health state machine

Adopt Uptime Kuma concepts:

- transition records;
- hysteresis;
- recovery state;
- noise suppression.

Why second: uses existing observations and does not require new network authority.

## Phase 3 — behavior windows

Adopt CrowdSec scenario logic:

- bounded temporal grouping;
- distinct counting;
- thresholds/cooldowns;
- advisory findings.

Why third: significantly improves security analysis using existing event streams.

## Phase 4 — declarative rule compiler and work clustering

Adopt Nuclei concepts:

- rule schema;
- validation/compile stage;
- capability declaration;
- deterministic matchers/extractors;
- duplicate work elimination.

Why fourth: powerful, but must sit on mature policy/harness foundations.

## Phase 5 — discovery candidates

Adopt Subfinder/WatchYourLAN concepts:

- multi-source candidate evidence;
- deduplication;
- host presence history;
- explicit operator admission.

Why fifth: adds visibility without letting discovery broaden authority.

## Phase 6 — process/flow attribution

Adopt bandwhich/mitmproxy concepts:

- typed flow lifecycle;
- socket/process adapters;
- process/user references;
- stronger correlation.

Why sixth: higher privilege/privacy cost; should be added only after governance is mature.

## Phase 7 — optional edge agent

Adopt Beszel concepts:

- lightweight collector agent;
- typed transport abstraction;
- bounded offline spool;
- central evidence ingestion.

Why last: distribution increases identity, deployment and trust complexity. It should scale a proven local architecture rather than compensate for an unstable one.

---

# 17. Architectural acceptance criteria

No implementation derived from this research is acceptable unless all of the following hold:

1. Confidential Core remains local-first and has no new Internet authority.
2. Discovery does not auto-approve assets.
3. Rules do not grant themselves network authority.
4. Active probes remain disabled unless explicitly authorized by policy and inventory.
5. PCAP remains behind the existing explicit approval boundary.
6. No raw credentials appear in contracts, logs, findings or CI artifacts.
7. Every finding references durable evidence.
8. Behavior detection is deterministic and bounded.
9. Health state uses hysteresis and does not equate one timeout with an outage by default.
10. Incremental ingestion has parser/source provenance.
11. Queue/spool saturation produces explicit backpressure/data-gap state.
12. Partial coverage is visible.
13. AI output is advisory and cannot alter canonical evidence.
14. No automatic firewall, account disable, process kill, shell execution or quarantine is introduced.
15. All new rules/adapters have positive, negative, malformed and boundary fixtures.
16. CI evidence is bound to the exact head commit.
17. Performance claims are measured, not assumed.
18. Upstream code is not copied unless a separate dependency/license review explicitly approves it.

---

# 18. Research sources

Primary sources used for this design extraction:

- Uptime Kuma repository and API/heartbeat model: https://github.com/louislam/uptime-kuma
- mitmproxy repository, flow/addon event lifecycle and proxy concepts: https://github.com/mitmproxy/mitmproxy
- Nuclei architecture document and repository: https://github.com/projectdiscovery/nuclei/blob/dev/DESIGN.md
- Beszel repository and transport abstraction: https://github.com/henrygd/beszel
- GoAccess repository/readme including incremental processing and storage: https://github.com/allinurl/goaccess
- CrowdSec log-processor/scenario architecture: https://docs.crowdsec.net/docs/log_processor/intro/ and https://docs.crowdsec.net/docs/concepts/
- Subfinder repository and passive-source architecture: https://github.com/projectdiscovery/subfinder
- bandwhich repository and process/connection attribution description: https://github.com/imsnif/bandwhich
- httpx repository and ProjectDiscovery usage documentation: https://github.com/projectdiscovery/httpx and https://docs.projectdiscovery.io/opensource/httpx/usage
- WatchYourLAN repository and API/config documentation: https://github.com/aceberg/WatchYourLAN

Local WorkSpace baseline reviewed for mapping:

- `README.md`
- `pyproject.toml`
- `src/three_agent/security_monitoring/contracts.py`
- `src/three_agent/security_monitoring/policy.py`
- `src/three_agent/security_monitoring/hourly.py`
- `src/three_agent/security_monitoring/log_pipeline.py`
- `src/three_agent/security_monitoring/correlation_graph.py`
- `src/three_agent/security_monitoring/incident_capture.py`
- package directory inventory under `src/three_agent/security_monitoring/`

---

# 19. Decision

WorkSpace should **not** integrate the ten projects as ten dependencies.

The preferred strategy is to extract and reimplement a small number of high-value primitives that reinforce the architecture WorkSpace already has:

1. provenance-safe incremental checkpoints;
2. explicit health state/hysteresis;
3. bounded temporal behavior rules;
4. compiled declarative detection/probe plans;
5. work-item clustering/deduplication;
6. multi-source discovery candidates without authority expansion;
7. typed flow/process attribution;
8. optional transport-neutral edge collection at scale;
9. deterministic replay/fault/boundary harnesses for all of the above.

This preserves WorkSpace's differentiator: **local confidential operation with mechanically constrained authority and evidence-backed AI analysis**, while incorporating mature operational ideas from established open-source monitoring and security systems.

The next step after this documentation commit is to inspect the exact current tests/harness and implementation surfaces, produce an implementation checklist mapped to exact files and acceptance tests, then create the first bounded vertical slice. That subsequent work must build on this committed architecture baseline rather than coding directly from upstream projects.
