# WorkSpace Micro-Tool Architecture & Implementation Contract

Status: **Canonical design baseline**  
Scope: **cross-platform tool registry, lazy routing, bounded execution, evidence contracts, and composable deep investigation**  
Product: **WorkSpace**

This document is the canonical implementation plan for WorkSpace micro-tools. New tool-runtime code MUST map to an implementation item in this document instead of being added ad hoc.

This document does not replace `AGENTS.md`, `config/workspace.execution-governance.json`, `docs/WORKSPACE_SECURITY_ARCHITECTURE.md`, or the security-domain guidance in `docs/SECURITY_ANALYST_HACKINGTOOL_DISTILLATION.md`. Repository execution governance and deterministic security policy remain authoritative.

---

## 1. Purpose

WorkSpace needs many small diagnostic and evidence-acquisition capabilities without forcing every request through a large, slow workflow.

The runtime therefore uses **atomic micro-tools + metadata-only discovery + lazy execution + evidence-driven escalation**.

The core invariant is:

> **Default = minimum sufficient evidence. Escalate only when evidence is insufficient. Full/deep collection runs only when explicitly requested or diagnostically justified.**

A user asking a narrow question should trigger only the smallest relevant tool set. A deep RCA/DFIR request may compose many of the same micro-tools into an investigation preset. There must be no duplicated “full workflow” implementation that bypasses the atomic tools.

---

## 2. Non-goals

The micro-tool layer is NOT intended to:

- create one monolithic `diagnose_everything` executor;
- give an LLM arbitrary shell, PowerShell, SSH, network, or administrator authority;
- replace skills, runbooks, or domain knowledge;
- treat model confidence as evidence;
- perform remediation during evidence acquisition by default;
- load hundreds of executor implementations into model context;
- duplicate existing security/capability policy in a second authority layer;
- silently escalate a quick request into full collection;
- enable disabled audit/event channels just to obtain more evidence;
- upload confidential evidence to Internet services by default.

---

## 3. Terminology and authority boundaries

### 3.1 TOOL

A **Tool** is an atomic, deterministic capability contract with bounded input, bounded output, explicit effects, and verifiable evidence.

Examples:

- `windows.event.system`
- `windows.event.provider`
- `windows.gpu.nvidia_smi`
- `linux.journal.kernel`
- `linux.auth.ssh`
- `network.tcp.connect`
- `camera.rtsp.probe`

A tool ID does not require one unique source file. Multiple tool IDs MAY share one canonical executor when their differences can be represented safely as fixed presets/parameters.

### 3.2 SKILL

A **Skill** explains how to solve a class of problem by selecting/interpreting tools. Skills do not grant runtime authority.

Example: `diagnose_gpu_black_screen`.

### 3.3 RUNBOOK

A **Runbook** is reviewed operational/vendor knowledge used to interpret evidence and propose safe next steps.

Examples: Microsoft BugCheck guidance, NVIDIA Xid guidance, Hikvision troubleshooting, Cisco interface-error guidance.

### 3.4 HARNESS / ROUTER

The **Harness/Router** interprets user intent, searches lightweight tool metadata, selects the cheapest relevant approved tools, evaluates returned evidence, and decides whether more evidence is needed.

The router does not gain authority by choosing a tool. Policy, `TaskContract`, registry approval, target scope, privilege constraints, and execution gates remain authoritative.

### 3.5 PRESET / DEEP WORKFLOW

A **Preset** is only a composition of micro-tool IDs plus bounded parameters and stopping rules.

A preset MUST NOT contain an independent copy of collection logic.

---

## 4. Primary runtime model

```text
User request
    |
    v
Intent classification
    |
    v
Metadata-only Tool Registry search
    |
    v
Select cheapest relevant approved tools
    |
    v
Policy / scope / privilege gate
    |
    v
Lazy-load only selected executors
    |
    v
Execute bounded micro-tools
    |
    v
Normalize EvidenceRecord(s)
    |
    v
Is evidence sufficient?
    |                 \
   yes                 no
    |                   \
    v                    v
Answer             select next tools
                         |
                         +----> repeat
```

The normal path must stop as soon as sufficient evidence exists.

---

## 5. Execution modes

WorkSpace recognizes three user-facing investigation depths. These are routing policies, not separate implementations.

### QUICK

Default for narrow questions. Usually selects the cheapest small set of directly relevant tools.

Example request:

> Is the NVIDIA GPU showing errors?

Candidate set:

- `windows.gpu.nvidia_smi`
- `windows.event.display`
- `windows.event.nvlddmkm`

### TARGETED

Used when the request asks for a cause or when QUICK evidence is insufficient.

Example request:

> The display goes black and the PC restarts. Find the likely cause.

Candidate expansion may include:

- `windows.event.kernel_power`
- `windows.event.bugcheck`
- `windows.event.whea`
- `windows.reliability.read`
- `windows.crashdump.inventory`

### DEEP / FULL

Used when the operator explicitly requests deep/full investigation or when a diagnostic policy permits escalation because targeted evidence remains insufficient.

DEEP/FULL is a preset composed from approved micro-tools. It is never an alternate privileged collector.

---

## 6. Tool naming convention

Canonical tool IDs use lowercase dotted names:

```text
<platform-or-domain>.<subsystem>.<operation-or-view>
```

Examples:

```text
windows.event.system
windows.event.security
windows.event.provider
windows.event.event_id
windows.event.channel_export
windows.gpu.nvidia_smi
windows.service.query
linux.journal.kernel
linux.journal.boot_previous
linux.auth.ssh
linux.storage.errors
network.icmp.echo
network.tcp.connect
network.dns.resolve
camera.onvif.discover
camera.rtsp.probe
switch.poe.inspect
```

Rules:

1. Tool IDs describe one bounded capability.
2. Avoid version numbers in IDs unless they represent a genuine externally supported protocol/API compatibility boundary.
3. Avoid names implying unrestricted execution such as `shell`, `run_anything`, or `admin_exec`.
4. A generic executor may implement multiple constrained tool IDs.
5. Tool IDs remain stable when internal implementation changes.

---

## 7. Registry metadata contract

The registry contains lightweight metadata. Listing/searching tools MUST NOT import executor modules.

Minimum `ToolSpec` fields:

```json
{
  "id": "windows.event.system",
  "version": "0.1.0",
  "title": "Read Windows System event channel",
  "platforms": ["windows"],
  "category": "event",
  "intents": ["system_error", "unexpected_restart", "driver_failure"],
  "keywords": ["event viewer", "system", "kernel", "driver", "restart"],
  "cost": "C1",
  "effect": "read_only",
  "privilege": "user_or_elevated_when_required",
  "network_requirement": "none",
  "sensitivity": "internal",
  "timeout_seconds": 10,
  "max_output_bytes": 10485760,
  "executor_ref": "three_agent.micro_tools.executors.windows_event:run",
  "preset": {
    "channel": "System"
  },
  "input_schema_ref": "...",
  "output_schema_ref": "..."
}
```

`executor_ref` is a locator only. Registry discovery must not import it until execution is approved.

Registry validation MUST reject malformed, duplicate, or policy-incompatible specs.

---

## 8. Cost model

Cost is used for routing and must be measurable over time. Initial classes:

| Class | Meaning | Typical examples |
|---|---|---|
| `C0` | negligible local lookup | service state, cached inventory |
| `C1` | small local command/query | `nvidia-smi`, narrow event query |
| `C2` | bounded local scan/query | recent channel slice, small inventory |
| `C3` | heavier collection/parse | broad logs, bounded packet/file analysis |
| `C4` | large/deep collection | all event channels, broad system evidence |
| `C5` | very expensive/sensitive analysis | large dump analysis, extensive corpus correlation |

Cost class is a routing hint, not permission. A cheap tool can still be forbidden by policy.

The router prefers the lowest-cost relevant approved set that can answer the request.

---

## 9. Effects and safety model

Tool effects are explicit and fail closed.

Initial effect classes:

- `read_only`: reads local state without changing operational configuration;
- `local_evidence_write`: reads state and writes only WorkSpace evidence artifacts/metadata;
- `active_network_readonly`: sends bounded diagnostic traffic without modifying the target;
- `remediation`: changes system/network/application state and is outside the default evidence-acquisition path.

A tool MUST declare all relevant effects. An executor may not perform effects stronger than its `ToolSpec`.

Evidence acquisition MAY create local evidence files, hashes, indexes, or archives. This does not authorize service control, registry modification, firewall changes, package installation, driver updates, process termination, event-log clearing, or network reconfiguration.

---

## 10. Privilege model

Every tool declares its minimum privilege expectation.

Examples:

- normal user;
- elevated/admin required;
- root required;
- capability-specific privilege.

The runtime MUST NOT silently elevate. If elevation is required and unavailable, return a structured blocked/partial evidence result describing what could not be read.

Privilege failure must never be disguised as “no events found”.

---

## 11. Input contract

Inputs are typed and bounded.

Examples:

- host/asset identifier;
- channel/provider/event ID;
- lookback duration;
- maximum record count;
- target IP/hostname already allowed by policy;
- port already allowed by policy;
- output/evidence destination controlled by WorkSpace.

Arbitrary shell fragments are not valid general-purpose tool inputs.

Each tool must define:

1. required fields;
2. optional fields and defaults;
3. bounds;
4. validation rules;
5. target-scope rules;
6. redaction/sensitivity behavior.

---

## 12. Evidence output contract

Executors return normalized evidence metadata plus optional artifacts.

Minimum `EvidenceRecord` concept:

```json
{
  "evidence_id": "EVD-...",
  "tool_id": "windows.event.system",
  "tool_version": "0.1.0",
  "status": "ok",
  "started_at": "...",
  "completed_at": "...",
  "host": "...",
  "platform": "windows",
  "acquisition_effect": "read_only",
  "summary": {},
  "artifacts": [
    {
      "path": "...",
      "size_bytes": 0,
      "sha256": "...",
      "sensitivity": "internal"
    }
  ],
  "warnings": [],
  "limitations": [],
  "provenance": {}
}
```

Requirements:

- timestamps must be unambiguous;
- original host/time-zone context is retained when relevant;
- artifacts receive SHA-256 when bytes are preserved;
- partial acquisition explicitly records limitations;
- “no findings” is distinguishable from “could not read”;
- raw/native evidence should be preserved when feasible, with normalized views generated separately;
- model-generated conclusions are never stored as if they were raw evidence.

---

## 13. Evidence sufficiency and escalation

The router follows an evidence loop:

```text
select -> execute -> evaluate sufficiency -> stop OR expand
```

Escalation must be justified by one of:

- required evidence is missing;
- evidence conflicts;
- a hypothesis needs discrimination;
- a tool returned an explicit limitation;
- the user explicitly requested deeper scope.

The router MUST NOT escalate solely because more tools exist.

Higher-cost or more sensitive tools require proportionally stronger justification and all normal policy gates.

---

## 14. Lazy loading requirements

Tool discovery and tool execution are separate phases.

### Discovery phase

Allowed to load:

- ToolSpec metadata;
- indexes/tags/intents;
- approval/revocation state;
- cost/effect/sensitivity metadata.

Must not automatically load:

- PowerShell bodies;
- shell executors;
- heavy Python modules;
- packet parsers;
- dump analyzers;
- model-specific code.

### Execution phase

Only after selection and policy approval may the runtime resolve/import the executor referenced by the chosen ToolSpec.

Acceptance requirement: a registry list/search test must prove executor modules are not imported merely by discovery.

---

## 15. Shared executor rule

**Micro-tool does not mean one source file per tool.**

To comply with the repository Single Canonical Module Rule, related tool IDs SHOULD share a canonical generic executor when practical.

Example:

```text
windows.event.system
windows.event.application
windows.event.security
windows.event.provider
windows.event.event_id
```

may share one canonical Windows Event executor with validated fixed presets/typed parameters.

Do not create files such as:

```text
windows_event_v2.py
windows_event_new.py
windows_event_final.py
```

Git history is version history.

---

## 16. Windows Event Viewer tool family

Event Viewer is a UI over Windows event channels. The tool family must support both targeted queries and full native export without conflating the two.

Initial atomic capabilities:

```text
windows.event.inventory
windows.event.system
windows.event.application
windows.event.security
windows.event.setup
windows.event.forwarded
windows.event.provider
windows.event.event_id
windows.event.channel
windows.event.display
windows.event.nvlddmkm
windows.event.whea
windows.event.kernel_power
windows.event.bugcheck
windows.event.wer
windows.event.powershell
windows.event.openssh
windows.event.export_channel
```

Rules:

1. Targeted tools filter after the user/router has requested a bounded view.
2. Full Event Viewer evidence dynamically enumerates available channels rather than relying on a fixed small list.
3. Native `.evtx` should be preserved for forensic-grade collection when requested.
4. Normalized JSON/XML views may be produced for indexing/correlation.
5. Disabled Analytic/Debug channels are recorded as disabled; evidence acquisition does not enable them automatically.
6. Custom Views are filters/views, not independent event stores; definitions may be inventoried, but underlying channels remain the evidence source.
7. Event-log clearing is never part of read-only acquisition.
8. Security log sensitivity is explicit.

A full Windows-event preset is composed from inventory/export micro-tools; it is not a separate monolithic implementation.

---

## 17. Linux/Ubuntu log tool family

Linux has no single Event Viewer equivalent. Evidence is distributed across journald and subsystem-specific logs.

Initial atomic capabilities:

```text
linux.journal.boot_current
linux.journal.boot_previous
linux.journal.kernel
linux.journal.service
linux.journal.priority
linux.kernel.dmesg
linux.auth.ssh
linux.auth.sudo
linux.audit.events
linux.storage.errors
linux.network.events
linux.service.status
linux.package.apt_history
linux.package.dpkg_history
linux.firewall.ufw
linux.container.docker_logs
linux.gpu.nvidia_smi
linux.gpu.kernel_events
```

Rules:

1. Previous-boot journal evidence is first-class for reboot/kernel/GPU RCA.
2. Missing/disabled audit sources are reported explicitly and are not enabled by a read-only collector.
3. Root-only evidence is not silently omitted.
4. Rotated/compressed logs are handled only when the requested scope and cost budget justify them.
5. Full Linux collection is a composition of these micro-tools.

---

## 18. Sensitive evidence policy

Examples of sensitive evidence include:

- Windows Security events;
- authentication records;
- usernames/SIDs/IPs/session identifiers;
- packet captures;
- process command lines;
- crash dumps;
- `MEMORY.DMP`;
- application logs containing business data.

Sensitive evidence remains local/confidential by default and inherits WorkSpace confidentiality boundaries.

`MEMORY.DMP` or equivalent high-sensitivity memory artifacts MUST require explicit operator intent/consent before raw collection or transfer into an analysis workflow.

A request for “GPU errors” must not opportunistically copy full memory dumps.

---

## 19. Timeouts, output bounds, and cancellation

Every executable ToolSpec must define bounded execution controls appropriate to the tool:

- timeout;
- maximum output size or record count where applicable;
- cancellation behavior;
- artifact destination;
- cleanup rules for incomplete temporary files.

A timeout returns structured evidence/limitation state; it must not be reported as successful empty output.

---

## 20. Tool lifecycle

Tool lifecycle must integrate with existing WorkSpace capability/security governance rather than create an independent authority system.

Conceptual states:

```text
candidate -> reviewed -> approved -> available -> revoked/disabled
```

A tool may be discoverable in development metadata without being executable in production.

Revocation/disable state must be checked before lazy executor loading.

---

## 21. Router ranking principles

Candidate ranking should initially be deterministic and explainable.

Inputs may include:

- platform compatibility;
- intent/tag match;
- requested subsystem;
- approval/revocation state;
- effect compatibility;
- privilege availability;
- target scope;
- cost class;
- prior evidence gaps;
- sensitivity.

Basic ordering principle:

```text
relevant + approved + lower-effect + lower-cost + sufficient
```

Do not use an LLM as the sole authority for policy/effect decisions.

---

## 22. Deep/full preset contract

Presets contain:

- preset ID;
- purpose;
- ordered/conditional tool IDs;
- per-tool bounded parameters;
- stopping conditions;
- maximum cost/scope;
- sensitivity warnings;
- required operator intent if applicable.

Presets MUST NOT contain raw shell/PowerShell snippets when an approved tool ID exists.

Example conceptual preset:

```yaml
id: windows.deep_rca
steps:
  - windows.event.inventory
  - windows.event.system
  - windows.event.application
  - windows.reliability.read
  - windows.gpu.nvidia_smi
  - windows.crashdump.inventory
stop_when: evidence_sufficient
```

This is orchestration metadata only.

---

## 23. Initial micro-tool catalog targets

The catalog should grow by operational need, not by arbitrary tool-count goals.

### Windows / host diagnostics

- Event channel inventory/query/export
- Reliability records
- service state
- process inventory
- driver inventory
- GPU status/events
- storage health/events
- network interface/state
- crash-dump inventory
- Defender/firewall read-only state

### Linux / host diagnostics

- journald views
- kernel/dmesg
- auth/audit
- service state
- package history
- storage/GPU/network evidence
- firewall read-only state
- container logs

### Network

- ICMP echo
- ARP/NDP inspection
- route inspection
- DNS resolution
- bounded TCP connect
- bounded trace/path checks
- interface counters
- LLDP/SNMP read-only views where policy permits

### Camera / CCTV

- ONVIF discovery/inspection
- RTSP probe
- stream/codec measurement
- firmware/time/network state

### Switch / PoE

- port state
- interface errors
- MAC/VLAN views
- PoE state
- LLDP/SNMP read-only evidence

Security-domain additions must remain aligned with `docs/SECURITY_ANALYST_HACKINGTOOL_DISTILLATION.md`.

---

## 24. Testing requirements

Every implementation item must have deterministic verifier evidence before being marked complete.

Minimum test families:

1. ToolSpec schema validation.
2. Duplicate tool ID rejection.
3. Registry discovery does not import executors.
4. Lazy loader imports only the selected executor.
5. Revoked/unapproved tool execution is denied before executor loading.
6. Effect mismatch is denied.
7. Input bounds are enforced.
8. Timeout/output bounds are represented correctly.
9. EvidenceRecord hash/provenance behavior is deterministic where applicable.
10. Partial/permission-denied results are distinguishable from empty success.
11. Windows event executor tests use fixtures/mocks when Windows is unavailable in CI.
12. Linux journal executor tests use fixtures/mocks when journald sources are unavailable in CI.
13. Presets contain tool IDs only and cannot bypass registry/policy gates.
14. Router prefers cheaper sufficient approved candidates.
15. Router does not silently enter deep/full mode.

Live-machine tests are additional evidence, not a replacement for deterministic unit/contract tests.

---

## 25. Implementation checklist

All new micro-tool runtime work MUST reference one or more IDs below in commit/PR descriptions or implementation notes.

| ID | Deliverable | Acceptance boundary | State |
|---|---|---|---|
| `MT-001` | Canonical architecture/implementation contract | This document exists, references existing governance, defines atomic/lazy/evidence-first invariants and ordered implementation work | ACTIVE |
| `MT-002` | Core ToolSpec model | Typed cost/effect/platform/privilege/sensitivity fields; deterministic validation; duplicate/version misuse rejected where applicable | PLANNED |
| `MT-003` | Metadata-only Tool Registry | Register/list/get/search/filter approved specs without importing executors | PLANNED |
| `MT-004` | Lazy executor loader | Resolve executor only after selection and policy approval; explicit import boundary tests | PLANNED |
| `MT-005` | EvidenceRecord contract | Normalized status/provenance/artifact/hash/limitations model with deterministic tests | PLANNED |
| `MT-006` | Tool execution gate | Validate approval/revocation, effect, privilege, target scope, timeout/output bounds before/around execution | PLANNED |
| `MT-007` | `workspace-tool` CLI | `list`, `show`, and guarded `run`; JSON output suitable for harness use | PLANNED |
| `MT-008` | Windows Event micro-tool family | Shared canonical executor + atomic ToolSpecs for inventory/channel/provider/event-id/targeted error views; no silent channel enabling | PLANNED |
| `MT-009` | Windows full-event preset | Dynamic channel inventory/export composed only from approved event micro-tools; native EVTX support when explicitly requested | PLANNED |
| `MT-010` | Linux journal micro-tool family | Shared canonical executor + atomic ToolSpecs for boot/kernel/service/priority views with explicit permission/source limitations | PLANNED |
| `MT-011` | Linux extended log micro-tools | auth/audit/storage/network/package/firewall/GPU bounded evidence readers | PLANNED |
| `MT-012` | Deterministic candidate router | Intent/tag/platform/effect/cost filtering and cheapest-sufficient candidate ordering | PLANNED |
| `MT-013` | Evidence sufficiency/escalation contract | Explicit stop/expand reasons; no hidden deep/full escalation | PLANNED |
| `MT-014` | Composite preset engine | Presets reference micro-tool IDs only; all steps pass normal registry/policy gates | PLANNED |
| `MT-015` | Host diagnostic presets | Quick/targeted/deep compositions for common Windows/Linux RCA without duplicate executor logic | PLANNED |
| `MT-016` | Network read-only micro-tools | Atomic bounded diagnostics such as DNS/TCP/route/ARP family integrated with existing monitoring policy | PLANNED |
| `MT-017` | Camera/switch/PoE read-only micro-tools | Atomic evidence capabilities with inventory/target allowlists and bounded network effects | PLANNED |
| `MT-018` | Tool lifecycle integration | Reuse/integrate existing capability approval/revocation authority; no parallel security authority | PLANNED |
| `MT-019` | Registry/router observability | Minimal audit metadata for selected tools, cost, escalation reason, duration, result status; no unnecessary confidential payload logging | PLANNED |
| `MT-020` | End-to-end acceptance pack | Quick request proves small tool count/low latency path; deep request proves composition; evidence and governance checks pass | PLANNED |

### Implementation order

Unless a dependency forces an evidence-backed replan, implement in this sequence:

```text
MT-001
  -> MT-002
  -> MT-003
  -> MT-004
  -> MT-005
  -> MT-006
  -> MT-007
  -> MT-008 + MT-010
  -> MT-012
  -> MT-013
  -> MT-014
  -> MT-009 + MT-011 + MT-015
  -> MT-016
  -> MT-017
  -> MT-018
  -> MT-019
  -> MT-020
```

Dependencies may be parallelized only when repository execution governance allows independent write sets and preserves one canonical functional authority.

---

## 26. Definition of done for each checklist item

An item is not complete merely because code exists.

For an `MT-*` item to be complete:

1. implementation maps to the stated acceptance boundary;
2. required deterministic tests/verifiers are executed;
3. verifier evidence is captured according to repository governance;
4. security/capability boundaries are not weakened;
5. no competing canonical implementation is introduced;
6. touched documentation/config/entrypoints remain consistent;
7. coherent repository mutation is committed;
8. exact-head evidence is checked before a READY claim.

If implementation reveals a missing architectural requirement, update this canonical document first or in the same coherent change, then implement against the revised item. Do not silently invent an undocumented parallel contract.

---

## 27. First coding milestone

The first coding milestone after this document is **MT-002 through MT-007**: establish the generic micro-tool contract, metadata-only registry, lazy loading, evidence model, execution gate, and CLI before adding large catalogs of OS-specific tools.

This prevents Windows/Linux scripts from becoming isolated special cases and gives every later tool the same safety, evidence, cost, and lazy-execution behavior.

The first domain milestone is **MT-008** (Windows Event micro-tools), followed by **MT-010** (Linux journal micro-tools).

---

## 28. Architectural acceptance examples

### Example A: narrow GPU question

User:

> Check whether the GPU has been failing recently.

Expected behavior:

```text
router
  -> windows.gpu.nvidia_smi
  -> windows.event.display
  -> windows.event.nvlddmkm
  -> sufficient? yes -> answer
```

Not expected:

```text
collect every Windows event + copy MEMORY.DMP + scan network + full DFIR
```

### Example B: reboot RCA

User:

> The Windows PC goes black and restarts. Find the cause.

Expected behavior:

```text
kernel-power + bugcheck + display + WHEA + reliability
  -> evaluate evidence
  -> if needed, add crashdump inventory / GPU driver evidence
  -> stop when sufficient
```

### Example C: explicit full Event Viewer acquisition

User:

> Collect all currently available Event Viewer evidence without changing the machine configuration.

Expected behavior:

```text
windows.event.inventory
  -> enumerate available/readable channels
  -> compose bounded export operations
  -> preserve native EVTX + manifest/hash where requested
  -> record disabled/unreadable channels as limitations
```

No channel is silently enabled and no log is cleared.

### Example D: Ubuntu reboot investigation

User:

> Why did this Ubuntu machine reboot?

Expected initial tools:

```text
linux.journal.boot_previous
linux.journal.kernel
linux.kernel.dmesg
```

Only expand to storage/GPU/service/auth evidence when the initial evidence indicates the need.

---

## 29. Final invariant

WorkSpace may eventually contain hundreds or thousands of micro-tool specifications while still remaining responsive because ordinary requests execute only a small relevant subset.

The scale target is therefore not “how many tools can run per request”. It is:

> **How reliably can WorkSpace select the smallest safe set of tools that produces sufficient evidence for the user's actual request?**

That principle governs all implementation work derived from this document.
