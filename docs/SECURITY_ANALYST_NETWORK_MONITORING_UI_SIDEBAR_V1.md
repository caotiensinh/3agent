# WorkSpace Security Analyst & Network Monitoring — Pinned Sidebar / UI Specification v1

## Status

Design-only. This document defines the product navigation and screen contract before frontend/runtime implementation.

## 1. Product decision

`Security Analyst & Network Monitoring` is a **first-class specialized WorkSpace feature** and must be pinned permanently in the primary left sidebar when the feature is installed.

It must not be hidden behind:

- the chat plus-menu;
- Workflow Studio;
- an admin-only settings page;
- a floating action button;
- model-generated navigation.

The current WorkSpace UI is primarily topbar + chat and Workflow Studio currently opens from a floating button/overlay. The specialized security feature therefore introduces the first persistent left navigation rail while preserving the existing chat and Workflow Studio behavior during migration.

No React, Node.js, SPA framework, WebSocket service, or additional frontend dependency is required for v1. The implementation should remain HTML/CSS/JavaScript generated from the existing Python frontend layer.

---

# 2. Sidebar information architecture

Recommended desktop structure:

```text
┌─────────────────────────────┐
│ WorkSpace                   │
│                             │
│  Chat                       │
│  Workflow Studio            │
│                             │
│  SPECIALIZED                │
│  Security Analyst      ● 2  │  <- pinned
│                             │
│  ------------------------   │
│  Reports                    │  <- optional global shortcut later
│  Settings                   │
│                             │
│  ver.0.0.1                  │
└─────────────────────────────┘
```

`Security Analyst` is always visible in the specialized section.

The badge may expose only aggregate, non-sensitive state:

```text
● green  = monitoring fresh, no open high/critical finding
● amber  = warning or data gap
● red    = one or more open high/critical findings
● gray   = feature disabled/not configured/stale
number   = count of open high+critical findings only
```

The sidebar must never expose:

- IP addresses;
- MAC addresses;
- device names;
- usernames;
- event text;
- finding descriptions;
- credential state;
- packet payload information.

---

# 3. Migration from current UI

The current product already has Chat and Workflow Studio. Workflow Studio is currently exposed as a floating entry point.

Safe migration order:

## UI-0

Add the left rail and pin `Security Analyst` while preserving all existing controls.

```text
Chat behavior unchanged
Workflow Studio floating button retained temporarily
Security Analyst sidebar item added
```

## UI-1

After navigation regression tests pass, make sidebar `Workflow Studio` the primary entry point. The floating button may remain as compatibility affordance until acceptance testing proves no regression.

## UI-2

Only after acceptance evidence exists may duplicate floating navigation be removed.

This prevents a specialized feature from forcing a risky full frontend rewrite.

---

# 4. Security Analyst internal navigation

Opening the pinned item shows a specialized workspace with a compact secondary tab bar.

```text
Security Analyst
├── Overview
├── Network
├── Findings
├── Events & Logs
├── Assets
├── Reports
└── Administration   [admin only]
```

For v1, use client-side view switching or hash state rather than introducing a new frontend router framework.

Suggested hashes:

```text
#/security/overview
#/security/network
#/security/findings
#/security/events
#/security/assets
#/security/reports
#/security/admin
```

Backend APIs remain authenticated `/api/...` resources. A URL/hash must never grant authority by itself.

---

# 5. Overview screen

The Overview is the default landing page and must be usable without AI.

Recommended layout:

```text
┌──────────────────────────────────────────────────────────────┐
│ Security Analyst & Network Monitoring                       │
│ Monitoring: HEALTHY    Last hourly: 21:05    Next: 22:05   │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ Assets       │ Reachable    │ Open High    │ Data Coverage  │
│ 42           │ 40 / 42      │ 2            │ 96%            │
├──────────────┴──────────────┴──────────────┴────────────────┤
│ Network Health / Bandwidth Trends                           │
├──────────────────────────────────────────────────────────────┤
│ Important Findings                                          │
│ severity | asset ref | category | first seen | status       │
├──────────────────────────────────────────────────────────────┤
│ Sensor Health              │ Reporting / NAS                │
│ syslog fresh               │ 17:30 report: scheduled        │
│ SNMP coverage 93%          │ NAS: available                 │
│ optional IDS fresh         │ pending archives: 0            │
└──────────────────────────────────────────────────────────────┘
```

The dashboard uses precomputed aggregates. It must not full-scan event storage every refresh.

---

# 6. Network screen

Purpose: operational network state and trends.

Required views:

- asset reachability matrix;
- latency and bounded probe loss;
- interface operational state;
- bandwidth RX/TX trend;
- utilization percentage when interface speed is known;
- errors/discards;
- interface flaps;
- topology/FDB/LLDP changes where configured;
- collector freshness and missing measurements.

Default data granularity:

```text
last 24h -> hourly samples
7d       -> hourly or validated daily rollups
30d      -> validated rollups
```

The UI should avoid rendering raw per-packet data.

---

# 7. Findings screen

Purpose: security analyst work queue.

Default table fields:

```text
severity
finding_id
category
asset_ref
first_seen
last_seen
status
evidence_count
```

Filters:

```text
severity
status
category
asset group
time range
```

Finding detail must contain:

1. deterministic reason/rule;
2. timeline;
3. evidence references;
4. related findings/correlation;
5. affected assets;
6. current coverage/data gaps;
7. AI analysis if produced, clearly labeled as analysis;
8. recommended investigation steps;
9. report references.

Raw evidence is loaded on demand, not preloaded with every finding row.

---

# 8. Events & Logs screen

This is an investigation surface, **not a giant always-live log console**.

Default behavior:

- query by time/source/asset/type/template/finding reference;
- server-side pagination;
- hard row/page cap;
- summarized/template view first;
- raw record expansion only on demand;
- no auto-tail by default;
- no raw log text injected into an AI prompt just because the page is open.

Optional future tail mode must use a bounded refresh interval and visibility-aware polling before considering a streaming transport.

---

# 9. Assets screen

Display two clearly separate concepts:

```text
APPROVED INVENTORY
vs
OBSERVED STATE
```

Never merge them visually into one ambiguous trust list.

Approved inventory includes configuration such as:

- stable asset ID;
- role/type;
- approved management address;
- collector profile;
- expected interfaces/sensors;
- data classification;
- enabled/disabled state.

Observed state includes:

- current reachability;
- last seen;
- observed MAC/IP evidence;
- operational interface state;
- last successful collection;
- drift findings.

Unknown device evidence appears as an untrusted observation/finding, not a trusted asset.

---

# 10. Reports screen

Tabs:

```text
Daily
Weekly
Monthly
Archive Status
```

Each report item shows:

```text
report_id
period/cutoff
status
coverage
finding counts
AI analysis status
NAS archive status
SHA-256 manifest reference
```

Actions:

- open validated HTML/text report;
- download approved artifact where supported;
- inspect evidence manifest;
- retry `PENDING_NAS` only under allowed policy;
- never edit an archived report in place.

---

# 11. Administration screen

Admin only.

Configuration groups:

## Monitoring profile

- enabled;
- time zone;
- hourly minute;
- worker limit;
- timeout/retry limits;
- report time (default 17:30);
- retention profile.

## Approved assets

- import/create/disable asset;
- collector type;
- management endpoint;
- SNMPv3/credential reference handle;
- approved fixed command adapter ID where unavoidable.

Credentials themselves must not be rendered back to the browser.

## Sensors

- syslog listeners/source mappings;
- optional Zeek source;
- optional Suricata EVE source;
- freshness policy.

## NAS archive

- pre-mounted local path only;
- path validation;
- write test using bounded synthetic artifact;
- no SMB/NFS password field in WorkSpace.

## Packet capture policy

Disabled by default. If enabled:

- allowed interfaces;
- max duration;
- max bytes;
- retention TTL;
- explicit admin approval requirement.

---

# 12. Authorization surface

Initial product mapping should stay compatible with existing WorkSpace auth rather than inventing an untested enterprise IAM system during this feature.

Minimum policy:

```text
authenticated user
  -> read overview/network/findings/events/assets/reports

admin
  -> all read access
  -> edit monitoring configuration/inventory
  -> approve incident packet capture
  -> retry/administer archive operations
```

Future analyst/operator roles may be added only with explicit API tests and capability boundaries.

Frontend hiding is not authorization. Every mutation endpoint must enforce role/policy server-side.

---

# 13. Refresh and resource budget

The specialized UI must not create monitoring load by merely being open.

Default client policy:

```text
Overview visible          -> GET compact status every 30s
Overview hidden           -> stop periodic refresh
Network charts            -> fetch selected window on demand
Findings list             -> manual/30s refresh when visible
Finding detail            -> fetch on selection
Events/logs               -> paged query only
Reports                   -> fetch index on entry/manual refresh
Admin                      -> no polling
```

No new WebSocket, Redis pub/sub, Kafka, or browser telemetry service in v1.

---

# 14. Error/partial-state UX

The UI must represent monitoring uncertainty explicitly.

Examples:

```text
HEALTHY
WARNING
CRITICAL FINDINGS
PARTIAL DATA
DATA GAP
COLLECTOR STALE
REPORT PENDING
PENDING NAS
FEATURE DISABLED
```

Never show a generic green status when expected sources are stale.

---

# 15. Accessibility and enterprise usability

- keyboard reachable navigation;
- visible focus states;
- status never encoded by color alone;
- tables usable at 125–150% zoom;
- Japanese-first labels at deployment if configured, with current WorkSpace language behavior preserved;
- do not render confidential identifiers into page titles/browser notifications by default;
- responsive sidebar collapses to an explicit menu button on narrow screens.

---

# 16. UI acceptance gates

The pinned-sidebar feature is accepted only when tests prove:

1. `Security Analyst` is always reachable from the authenticated shell when enabled;
2. opening the feature does not start a collector or grant LAN authority;
3. sidebar badge contains only aggregate status/count;
4. non-admin users cannot mutate monitoring configuration via API;
5. admin configuration never returns stored secret values;
6. data-gap state is visible and cannot appear as green/healthy;
7. hidden browser tab stops normal polling;
8. events/log view is bounded/paginated;
9. Workflow Studio and Chat continue working after sidebar introduction;
10. mobile/collapsed navigation remains usable;
11. no new frontend framework/dependency is required;
12. frontend state cannot override deterministic monitoring/report status.
