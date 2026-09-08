# Office IT Complaint-to-Micro-Tool Diagnostic Architecture v0.1

## 1. Purpose

This document converts the canonical Office IT support corpus into an implementation architecture for WorkSpace.

Baseline corpus:

- **650** normalized real-world complaint / symptom signatures: `IT-0001` ... `IT-0650`
- **32** diagnostic domains
- source catalog: [`OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG.md`](./OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG.md)
- existing capability selector: [`ADAPTIVE_MICRO_TOOL_REGISTRY_V0_2.md`](./ADAPTIVE_MICRO_TOOL_REGISTRY_V0_2.md)

The central design problem is that normal employees do **not** describe incidents using technical root-cause language. They say things such as:

- "My computer is slow."
- "The Internet is broken."
- "I cannot log in."
- "The camera disappeared."
- "Printing does not work."
- "Teams has no sound."
- "The shared folder is gone."

Those sentences are observations, not diagnoses. WorkSpace must therefore narrow uncertainty before selecting or executing any technical action.

The canonical doctrine is:

`vague complaint -> normalize -> candidate routes -> high-value clarification -> scope narrowing -> minimum read-only evidence -> ranked hypotheses -> authority gate -> bounded remediation -> verification -> audit`

---

## 2. Critical architectural decision: 650 routes, not 650 duplicated scripts

The 650 catalog records MUST NOT become 650 monolithic scripts.

Instead:

- each `IT-####` item becomes a **DiagnosticRoute**;
- routes reuse a shared library of small atomic **MicroTools**;
- a route defines clarification questions, discriminators, evidence tools, stop conditions and allowed remediation proposals;
- tools do one bounded job and return structured evidence;
- full/deep investigation remains composition of small tools, never one giant collector.

Expected relationship:

`650 complaint routes -> approximately 150-250 reusable evidence micro-tools -> separately gated remediation micro-tools`

This keeps startup fast, context small, behavior testable and future vendor additions manageable.

---

## 3. User-language doctrine

### 3.1 Never trust user wording as a root cause

User text is evidence about perceived behavior only.

Examples:

| User says | Must NOT immediately conclude |
|---|---|
| "Internet is down" | router failure |
| "PC is slow" | insufficient RAM |
| "camera is dead" | camera hardware failure |
| "password is wrong" | password actually incorrect |
| "printer is broken" | printer hardware failure |
| "server is down" | server powered off |
| "VPN does not work" | VPN gateway failure |

### 3.2 Preserve the original utterance

Every incident keeps:

- original text;
- detected language;
- normalized text;
- translated/internal semantic representation when needed;
- extracted entities;
- user certainty versus observed facts;
- timestamps.

The original user statement must never be silently rewritten into a technical diagnosis.

### 3.3 Multilingual aliases

Each route should eventually support at least:

- Vietnamese complaint aliases;
- Japanese complaint aliases;
- English complaint aliases;
- common abbreviations and misspellings;
- colloquial phrases used by non-technical employees.

Example route alias group:

```text
IT-0121
VI: "mất mạng", "không vào mạng được", "internet chết", "wifi không có mạng"
JA: "ネットが繋がらない", "インターネットが使えない", "Wi-Fiは繋がるけどネットがない"
EN: "internet is down", "no internet", "wifi connected but no internet"
```

---

## 4. Diagnostic narrowing state machine

WorkSpace should move an incident through explicit states.

### N0 — RAW_COMPLAINT

Only the user utterance is known.

Goal: identify likely object/service/domain candidates.

No diagnostic tool with system access should be selected solely because one keyword matched.

### N1 — DOMAIN_NARROWED

Likely domain(s) are known, but several root-cause families remain.

Goal: ask one or more high-information clarification questions and/or collect C0/C1 context.

### N2 — SCOPE_NARROWED

Affected object and blast radius are bounded.

Examples:

- one application;
- one user;
- one endpoint;
- several endpoints on one AP/VLAN;
- one branch site;
- whole organization;
- external SaaS only.

Goal: select the smallest evidence tools that can discriminate the remaining hypotheses.

### N3 — EVIDENCE_NARROWED

Structured read-only evidence exists and candidate hypotheses are ranked.

Goal: stop if sufficient; otherwise justify TARGETED escalation.

### N4 — DIAGNOSIS_BOUNDED

Evidence supports a bounded diagnosis with explicit confidence and alternatives.

Goal: present safe remediation proposal(s), required authority and verification plan.

### N5 — REMEDIATION_AUTHORIZED

A human or existing task authority explicitly permits a bounded mutating action.

Goal: execute the smallest remediation tool, then verify.

### N6 — VERIFIED_OR_ESCALATED

Either:

- remediation is verified;
- issue is unresolved but evidence package is complete;
- physical verification is required;
- vendor/escalation boundary is reached.

---

## 5. Clarification-question engine

The question engine is a first-class diagnostic component, not chat decoration.

### 5.1 Question objective

Ask the question that removes the largest number of plausible candidates with the least burden on the user.

A good question changes routing.

A bad question only collects trivia.

### 5.2 Question policy

1. Use plain language. Do not require the employee to know DNS, DHCP, VLAN, Kerberos, ODBC, MTU, GPO, PoE or certificate-chain terminology.
2. Prefer **1-3 questions per turn**, not a long questionnaire.
3. Ask only facts that cannot be collected automatically with safe read-only tools.
4. Prefer binary or small-choice questions when possible.
5. Always support "I don't know" without blocking the investigation.
6. Ask about **scope before root cause**.
7. Ask about **time/change before invasive evidence** when regression is plausible.
8. Ask for exact error text/screenshot only when it materially separates candidates.
9. Never ask the user to disable MFA, EDR, firewall, encryption or other controls as a diagnostic shortcut.
10. When software evidence cannot distinguish physical states, request explicit physical confirmation.

### 5.3 Universal discriminator dimensions

The following dimensions apply across most of the 650 routes.

| Dimension | Plain-language question | Why it matters |
|---|---|---|
| Affected object | "What exactly is not working: the whole PC, one app, Wi-Fi, printer, camera, or something else?" | selects domain |
| Blast radius | "Is it only you, or are other people nearby having the same problem?" | endpoint vs shared infrastructure |
| Start time | "When did it last work normally?" | timeline boundary |
| Recent change | "Did this start after an update, restart, password change, office move, cable change, or new device?" | regression/config branch |
| Reproducibility | "Does it fail every time or only sometimes?" | persistent vs intermittent |
| Alternate path | "Does it work from another PC/phone/network/browser?" | isolates endpoint/account/network/service |
| Power/physical | "Are there lights/power/display on the device?" | physical boundary |
| Location | "Are you in the office, at home, or another branch?" | LAN/VPN/WAN routing |
| Identity | "Can another user sign in on this device, or can you sign in on another device?" | account vs endpoint |
| Connectivity | "Can you open other internal or Internet services?" | local app vs network |
| Exact error | "What exact message or code appears?" | vendor-specific discriminator |
| Recent scope expansion | "Did anyone else report this today?" | potential incident/outage |

### 5.4 Question selection score

A future QuestionPlanner should score candidate questions using:

```text
question_value = expected_candidate_reduction
               + blast_radius_information
               + safety_value
               + evidence_cost_avoided
               - user_burden
               - redundancy
```

The planner should prefer the highest-value unanswered discriminator.

---

## 6. Complaint interpretation data model

Proposed machine-readable incident state:

```yaml
incident_id: INC-...
original_utterance: "may tinh cua toi cham lam"
language: vi
normalized_intent: endpoint_performance_problem
entities:
  device: current_endpoint
  application: null
scope:
  users_affected: unknown
  devices_affected: unknown
  site: unknown
timeline:
  first_seen: unknown
  last_known_good: unknown
  recent_change: unknown
candidate_routes:
  - IT-0041
  - IT-0042
  - IT-0043
  - IT-0044
  - IT-0045
  - IT-0046
  - IT-0047
clarifications:
  answered: []
  pending: []
evidence: []
hypotheses: []
confidence: 0.0
authority_state: diagnostic_read_only
physical_verification_required: false
```

---

## 7. DiagnosticRoute contract

Every `IT-####` record should become a route specification.

```yaml
route_id: IT-0041
domain: endpoint_performance
complaint_aliases:
  vi: ["may cham", "may tinh cham"]
  ja: ["PCが遅い"]
  en: ["computer is slow"]
clarification_dimensions:
  - affected_scope
  - start_time
  - recent_change
  - workload_specificity
initial_tools:
  - system.resource.snapshot
  - storage.capacity.snapshot
  - process.top.snapshot
targeted_tools:
  - windows.event.system
  - windows.update.history
  - storage.smart.read
stop_conditions:
  - evidence_sufficient
  - no_material_uncertainty_reduction
physical_boundary: false
remediation_candidates:
  - remediation_id_reference_only
```

A route is metadata. It does not grant execution authority.

---

## 8. MicroTool contract

Every evidence tool should have one bounded purpose.

Required metadata:

```text
id
platform
category
keywords / semantic aliases
cost C0..C5
risk
requires_admin
network_access
sensitive_outputs
effect
input schema
output schema
timeout
max output size
evidence timestamp
source provenance
failure reason codes
```

Additional rules:

- one tool should answer one diagnostic question;
- read-only tools must not mutate state as a side effect;
- tools must return structured output plus raw evidence reference when useful;
- failures are evidence and must be represented explicitly;
- no tool may convert "unreachable" into "device powered off" without proof;
- implementations must be loadable independently;
- implementations must not require a giant workflow to run.

---

## 9. Tool layers

### Layer Q — conversation / narrowing tools

Pure compute or incident-state tools; no host mutation.

Candidate ids:

```text
complaint.normalize
complaint.language.detect
complaint.entity.extract
complaint.route.candidates
scope.blast_radius.classify
timeline.change.extract
question.next.best
question.answer.normalize
hypothesis.rank
evidence.sufficiency.evaluate
physical.boundary.evaluate
```

### Layer E0 — zero/very-low-cost local context

```text
system.platform.identify
system.identity.current
system.boot_time
system.clock.snapshot
system.network.interfaces
system.resource.snapshot
system.storage.capacity
system.session.snapshot
```

### Layer E1/E2 — normal read-only evidence

Domain-specific collectors such as Windows events, DNS state, route table, printer queue, VPN status, update history, camera reachability, service health and application logs.

### Layer E3+ — targeted/deep evidence

Examples:

- longer event windows;
- packet capture;
- expensive inventory;
- broad fleet correlation;
- deep vendor diagnostics.

These require evidence-driven escalation and existing authority.

### Layer R — remediation tools

Mutating actions are a separate namespace and are never selected as diagnostic evidence.

Examples only:

```text
remediate.print.queue.clear
remediate.print.spooler.restart
remediate.dns.cache.flush
remediate.network.adapter.renew
remediate.application.profile.repair
remediate.service.restart
```

Each remediation tool requires explicit effect/resource authorization and post-action verification.

---

## 10. 32-domain routing and micro-tool plan

The following table is the coding map for all 650 routes.

| Issue range | Domain | Typical vague complaint | High-value clarification | Primary evidence micro-tool families |
|---|---|---|---|---|
| IT-0001–0020 | Identity / MFA | "I cannot log in" | one device or all devices; password changed; MFA prompt; another user/device | `identity.session.*`, `identity.account.*`, `identity.mfa.*`, `windows.event.security`, `time.sync.*` |
| IT-0021–0040 | Windows boot/login/update | "Windows is broken" | boots or not; before/after login; update/restart timing; exact recovery screen | `windows.boot.*`, `windows.event.system`, `windows.update.*`, `windows.profile.*`, `windows.bitlocker.*`, `windows.reliability.*` |
| IT-0041–0060 | Performance/storage | "PC is slow" | always or one app; after login; disk full; recent update; intermittent | `system.resource.*`, `process.top.*`, `storage.capacity.*`, `storage.io.*`, `storage.smart.*`, `windows.event.system` |
| IT-0061–0080 | Hardware/power/thermal | "The PC is dead" | lights/fan/display; charger; battery; heat; physical damage | `hardware.power.*`, `hardware.battery.*`, `hardware.thermal.*`, `hardware.memory.*`, `storage.presence.*`, physical confirmation |
| IT-0081–0100 | Dock/USB-C/display | "My monitor/dock does not work" | charging works; direct cable works; one/all displays; dock model; after firmware update | `display.topology.*`, `usb.inventory.*`, `dock.inventory.*`, `network.adapter.*`, `driver.status.*`, `firmware.version.*` |
| IT-0101–0120 | Printing/scanning | "Printer is broken" | one user/all users; offline/queue; other printer; scan or print; exact printer | `print.queue.*`, `print.spooler.*`, `print.port.*`, `print.driver.*`, `network.reachability.*`, `scan.endpoint.*` |
| IT-0121–0145 | LAN/Wi-Fi/DHCP/DNS | "No Internet" | Wi-Fi or cable; one device/area/site; IP vs names; internal vs public | `network.interface.*`, `network.link.*`, `network.ipconfig.*`, `network.dhcp.*`, `network.dns.*`, `network.route.*`, `network.latency.*` |
| IT-0146–0165 | VPN/remote access | "VPN does not work" | cannot connect vs connects/no resource; home/hotel; internal DNS; MFA | `vpn.client.*`, `vpn.route.*`, `vpn.dns.*`, `identity.mfa.*`, `network.path.*`, `certificate.client.*` |
| IT-0166–0185 | Outlook/Exchange | "Email is not working" | send/receive/both; web works; one mailbox; password prompt; shared mailbox | `outlook.profile.*`, `outlook.cache.*`, `mail.connectivity.*`, `mail.queue.client.*`, `identity.token.*`, `service.health.*` |
| IT-0186–0205 | Teams/Zoom | "Meeting has no sound" | mic/speaker/camera; all meetings; device selected; network quality | `audio.devices.*`, `camera.local.*`, `meeting.client.*`, `network.realtime.*`, `driver.media.*` |
| IT-0206–0225 | OneDrive/SharePoint | "Files are missing" | local/web; one library; sync icon/error; permissions; moved/renamed | `onedrive.sync.*`, `cloudfile.status.*`, `sharepoint.permission.*`, `storage.capacity.*`, `identity.token.*` |
| IT-0226–0245 | SMB/mapped drives/GPO | "Shared drive disappeared" | VPN/LAN; one share/all shares; name/IP; permissions; reboot/login timing | `smb.mapping.*`, `smb.connectivity.*`, `network.dns.*`, `kerberos.ticket.*`, `gpo.result.*`, `identity.group.*` |
| IT-0246–0265 | Software/browser/business apps | "The program does not run" | launch/crash/login; all users; web vs desktop; update/install timing | `application.process.*`, `application.event.*`, `application.version.*`, `browser.profile.*`, `license.status.*`, `dependency.runtime.*` |
| IT-0266–0285 | Security/phishing/EDR | "Security blocked me" | exact alert; user action; one file/site/app; organizational impact | `security.alert.*`, `security.edr.status.*`, `certificate.inspect.*`, `windows.event.security`, `browser.security.*`; no bypass |
| IT-0286–0300 | Mobile/MDM/BYOD | "Company mail does not work on my phone" | managed/unmanaged; enrollment; compliance; new phone; app only | `mobile.enrollment.*`, `mdm.compliance.*`, `identity.mfa.*`, `certificate.mobile.*`, `service.health.*` |
| IT-0301–0320 | Server/VM/storage/backup | "Server is down" | one service/host/VM; network reachable; power visibility; alerts; backup scope | `server.health.*`, `service.status.*`, `vm.status.*`, `storage.array.*`, `backup.job.*`, `network.reachability.*`, physical boundary |
| IT-0321–0335 | VoIP/headsets | "Phone has no sound" | desk phone/softphone; one-way/both; headset; one extension/site | `voip.registration.*`, `voip.media.*`, `audio.devices.*`, `network.realtime.*`, `sip.status.*` |
| IT-0336–0350 | User lifecycle/access | "I do not have access" | new user/change role; exact resource; approved entitlement; when granted | `identity.group.*`, `identity.role.*`, `license.assignment.*`, `access.audit.*`; remediation always authorized |
| IT-0351–0365 | Cloud/SaaS/licensing | "The website/service is broken" | only user/company; browser/device; license; status page; SSO | `service.health.*`, `identity.sso.*`, `license.status.*`, `network.dns.*`, `browser.connectivity.*` |
| IT-0366–0380 | Switch/PoE/physical network | "The device has no network" | port/link light; one endpoint/area; PoE; cable move; VLAN | `network.link.*`, `switch.port.read.*`, `switch.vlan.read.*`, `poe.port.read.*`, `network.mac.learned.*`, physical confirmation |
| IT-0381–0405 | Intune/Autopilot | "New PC setup is stuck" | OOBE/ESP stage; user/device phase; enrollment error; app/policy | `mdm.enrollment.*`, `autopilot.profile.*`, `intune.policy.*`, `intune.app.*`, `identity.device.*` |
| IT-0406–0425 | macOS/Jamf/FileVault | "My Mac says it is not managed" | enrollment; profile; FileVault; Secure Token; after upgrade | `macos.profile.*`, `jamf.enrollment.*`, `filevault.status.*`, `securetoken.status.*`, `macos.log.*` |
| IT-0426–0445 | UPS/power/facilities | "Everything in the room went down" | whole rack/site; UPS alarm; cooling; utility power; PDU | `ups.status.*`, `pdu.status.*`, `environment.temperature.*`, `server.reachability.*`; physical confirmation required when telemetry absent |
| IT-0446–0470 | Meeting-room A/V | "Meeting room does not work" | display/audio/camera; room PC vs BYOD; cable/wireless; one room | `room.display.*`, `room.audio.*`, `room.camera.*`, `room.controller.*`, `wireless.presentation.*`, physical input confirmation |
| IT-0471–0485 | FIDO2/smart card/VDI | "My security key/VDI does not work" | key detected; PIN/cert; one app; VDI launch/session/redirection | `fido.device.*`, `smartcard.reader.*`, `certificate.client.*`, `vdi.session.*`, `vdi.redirection.*` |
| IT-0486–0500 | Warehouse/barcode/label/serial | "Scanner/printer works sometimes" | station/device; symbology; pairing; COM port; moved hardware | `barcode.device.*`, `serial.port.*`, `label.queue.*`, `label.calibration.*`, `usb.inventory.*`, `application.binding.*` |
| IT-0501–0525 | AD/DNS/DHCP/GPO core | "Domain/login/policy is strange" | one DC/site/user; DNS; replication; new password; policy scope | `ad.replication.*`, `ad.dc.health.*`, `dns.server.*`, `dhcp.scope.*`, `gpo.result.*`, `kerberos.*`, `time.sync.*` |
| IT-0526–0550 | Office productivity | "Excel/Word is frozen" | one file/all files; safe mode; add-ins; network file; update | `office.version.*`, `office.addins.*`, `office.event.*`, `file.integrity.*`, `network.file.latency.*`, `license.status.*` |
| IT-0551–0575 | ERP/SQL/ODBC | "ERP is slow/not opening" | login vs query; one user/site; VPN; DB reachability; recent release | `database.tcp.*`, `database.latency.*`, `odbc.config.*`, `application.log.*`, `network.path.*`, `dns.resolve.*` |
| IT-0576–0600 | CCTV/NVR/access control | "Camera disappeared" | one/all cameras; live vs recording; ping/RTSP; PoE; NVR/VMS only | `camera.reachability.*`, `camera.rtsp.*`, `camera.onvif.*`, `nvr.channel.*`, `vms.service.*`, `poe.port.read.*`, `network.path.*` |
| IT-0601–0625 | PKI/TLS/SMTP identity | "Certificate/mail relay is broken" | expired/untrusted/name mismatch; one client/all; SMTP auth/TLS | `certificate.chain.*`, `certificate.expiry.*`, `tls.handshake.*`, `smtp.connectivity.*`, `dns.resolve.*`, `time.sync.*` |
| IT-0626–0650 | WAN/ISP/SD-WAN/remote sites | "Branch office is slow/down" | whole site; ISP link; internal/public; failover; time of day | `wan.interface.*`, `wan.gateway.*`, `sdwan.path.*`, `network.loss.*`, `network.latency.*`, `dns.resolve.*`, `site.reachability.*` |

---

## 11. Shared micro-tools should be reused across domains

Examples of cross-domain tools:

```text
network.dns.resolve
network.route.snapshot
network.interface.snapshot
network.reachability.internal
network.latency.internal
system.clock.snapshot
time.sync.status
certificate.chain.inspect
identity.current.snapshot
service.status.read
process.top.snapshot
storage.capacity.snapshot
windows.event.system
windows.event.security
```

A DNS collector can support VPN, Outlook, SMB, AD, ERP, camera/VMS, SaaS and WAN routes. It should therefore exist once.

---

## 12. Scope-first reasoning

Blast radius is one of the highest-value discriminators.

### One user only

Prioritize:

- account/token/profile;
- endpoint state;
- user-specific permission;
- application profile.

### One device only

Prioritize:

- local interface/driver/config;
- local hardware;
- endpoint policy;
- application install.

### Multiple users on one area/AP/VLAN

Prioritize:

- AP/switch/VLAN/DHCP;
- local infrastructure;
- common upstream path.

### Whole site

Prioritize:

- gateway/firewall/WAN/DNS/shared power;
- site services;
- provider status.

### Whole organization

Prioritize:

- identity/cloud/service outage;
- central policy/change;
- shared core infrastructure.

The system must not run endpoint-deep tools on 100 devices before checking whether the symptom is shared.

---

## 13. Timeline/change reasoning

Every route should consider:

```text
last known good
first known bad
OS/application update
password/MFA change
firmware change
network change
office move/cable change
new device/peripheral
policy/GPO/MDM change
vendor release
power event
```

A recent correlated change does not prove causality, but it materially changes evidence priority.

---

## 14. Automatic evidence versus user questions

WorkSpace should avoid asking a normal user technical questions when the endpoint can answer them safely.

Bad:

> "What DNS server are you using?"

Better:

> Automatically run `network.ipconfig.snapshot` and `network.dns.snapshot`.

Bad:

> "Is DHCP working?"

Better:

> Ask "Does Wi-Fi show connected?" only if needed, while automatically reading address/lease evidence.

Bad:

> "What is your default gateway?"

Better:

> Collect route/interface state automatically.

The user should mainly answer human-context facts:

- who/what is affected;
- where they are;
- when it started;
- what they were trying to do;
- visible physical state;
- exact message they can see;
- whether an alternative device/path works.

---

## 15. Confidence and stop policy

The system must carry uncertainty explicitly.

Suggested interpretation states:

```text
LOW       many plausible domains/routes remain
MEDIUM    domain and scope bounded, multiple hypotheses remain
HIGH      evidence strongly favors one bounded cause family
VERIFIED  post-action or direct evidence confirms expected state
UNKNOWN   evidence unavailable or contradictory
```

Rules:

- never turn UNKNOWN into a guessed cause;
- stop collecting when evidence is sufficient;
- stop when another tool cannot materially reduce uncertainty;
- request human/physical evidence when software cannot distinguish the state;
- escalate cost only when expected uncertainty reduction justifies it;
- C5 remains explicit/evidence-driven and human-gated under the existing registry contract.

---

## 16. Worked example A — "My computer is slow"

### Step 1 — candidate generation

Possible routes include:

`IT-0041`, `IT-0042`, `IT-0043`, `IT-0044`, `IT-0045`, `IT-0046`, `IT-0047`, `IT-0049`, `IT-0050`, `IT-0055`, `IT-0059`, `IT-0060`.

### Step 2 — clarification

Ask:

1. "Is the whole computer slow or mainly one program?"
2. "Did this start today/recently, or has it been slow for a long time?"
3. "Does it become slow only after you connect the dock/VPN/open a particular app?"

### Step 3 — minimum evidence

```text
system.resource.snapshot
process.top.snapshot
storage.capacity.snapshot
```

### Step 4 — targeted branches

- disk saturated -> `storage.io.snapshot`
- disk health suspicion -> `storage.smart.read`
- update correlation -> `windows.update.history`
- unexplained restart/error -> `windows.event.system`
- only one app -> application-specific collectors

No remediation is selected until evidence narrows the cause.

---

## 17. Worked example B — "No Internet"

### Clarification first

1. "Is it only your device or are coworkers nearby also offline?"
2. "Are you using Wi-Fi or a cable?"
3. "Can you open internal company services, or nothing at all?"

### Minimum evidence

```text
network.interface.snapshot
network.link.snapshot
network.ipconfig.snapshot
network.route.snapshot
network.dns.snapshot
```

### Branches

- no link -> physical/NIC/switch branch
- APIPA/no lease -> DHCP branch
- IP connectivity works but names fail -> DNS branch
- LAN works but Internet fails -> gateway/WAN branch
- one site impacted -> site infrastructure branch
- many sites impacted -> central/provider branch

"No Internet" by itself never proves router failure.

---

## 18. Worked example C — "The camera is gone"

### Clarification

1. "Is only one camera missing or are several/all cameras missing?"
2. "Is live view missing, recording missing, or both?"
3. "Did anyone move cables, change a switch/PoE device, or update the NVR/VMS?"

### Evidence sequence

```text
camera.reachability.read
network.path.read
poe.port.read        # when authorized/internal telemetry exists
camera.rtsp.read
camera.onvif.read
nvr.channel.read
vms.service.read
```

Interpretation examples:

- camera network unreachable + PoE port down -> physical/PoE hypothesis rises;
- network reachable + RTSP unavailable -> camera/service/config branch;
- RTSP healthy + VMS channel missing -> VMS/NVR branch;
- all cameras at one site unreachable -> switch/WAN/power branch before per-camera deep scans.

Missing telemetry is not proof that the camera has no power.

---

## 19. Worked example D — "I cannot print"

### Clarification

1. "Can other people print to the same printer?"
2. "Can you print to another printer?"
3. "Does the job appear in the queue or nothing happens?"

### Evidence

```text
print.queue.read
print.spooler.status
print.driver.read
print.port.read
network.reachability.internal
```

Possible bounded outcomes:

- user/client queue problem;
- shared print-server problem;
- driver/deployment problem;
- printer network/port problem;
- printer physical/media state requiring human verification.

Only after evidence and authorization may a remediation such as a spooler restart or queue clear be proposed/executed.

---

## 20. Worked example E — "I cannot log in"

### Clarification

1. "Where can you not log in: Windows, email, VPN, or another application?"
2. "Can you sign in from another device/browser?"
3. "Did you recently change your password or phone/MFA method?"

### Evidence branches

```text
identity.current.snapshot
identity.account.read
identity.mfa.status
windows.event.security
system.clock.snapshot
time.sync.status
identity.token.read
```

If security-log access requires admin authority and it is unavailable, the route returns an explicit authority/evidence gap. It does not silently substitute a privileged action.

---

## 21. Physical evidence boundary

Some complaints cannot be resolved reliably from software telemetry alone.

Examples:

- no utility power;
- UPS switched off;
- cable unplugged;
- damaged fiber/copper;
- failed PoE injector;
- wrong monitor input;
- broken laptop charger;
- liquid damage;
- printer out of paper/physical jam;
- server-room cooling failure;
- camera physically damaged or lens covered.

Required route response:

```text
PHYSICAL_EVIDENCE_REQUIRED
```

with a specific safe request, for example:

> "Please confirm whether the switch port/link light is on and whether the camera/PoE device has a power indicator. Do not unplug or reset anything yet."

---

## 22. Remediation architecture

Diagnostic and remediation capabilities must remain separate.

### Diagnostic route

```text
complaint -> questions -> evidence -> bounded diagnosis
```

### Remediation route

```text
bounded diagnosis -> proposed action -> authority check -> human decision when required -> execute one bounded tool -> verify
```

A diagnostic tool must never grant permission to a remediation tool.

Examples of future bounded remediation tool ids:

```text
remediate.print.spooler.restart
remediate.print.queue.clear
remediate.network.dhcp.renew
remediate.network.dns_cache.flush
remediate.application.restart
remediate.vpn.client.reconnect
remediate.onedrive.client.restart
remediate.service.restart
```

These examples are implementation targets, not blanket authorization.

---

## 23. Tool loading doctrine

Normal request:

```text
User complaint
  -> load complaint metadata
  -> load 1-3 relevant question/routing components
  -> load only selected evidence micro-tools
  -> stop when sufficient
```

Deep request:

```text
User explicitly requests deep investigation
  OR evidence justifies escalation
  -> compose additional micro-tools through existing registry
```

Do not load every Windows/Linux/network/security/camera collector for every request.

---

## 24. Proposed code organization

```text
src/three_agent/diagnostics/
  complaint_intake/
    normalize.py
    entity_extract.py
    route_candidates.py
  clarification/
    question_catalog.py
    question_planner.py
    answer_normalizer.py
    scope_classifier.py
  routes/
    identity/
    windows/
    performance/
    hardware/
    dock_display/
    printing/
    network/
    vpn/
    mail/
    meetings/
    cloud_files/
    smb_gpo/
    applications/
    security/
    mobile_mdm/
    server_backup/
    voip/
    lifecycle/
    saas/
    infrastructure/
    intune_autopilot/
    macos/
    facilities/
    room_av/
    auth_vdi/
    warehouse/
    ad_core/
    office/
    erp_database/
    cctv_access/
    pki_smtp/
    wan_remote/
  tools/
    common/
    windows/
    linux/
    network/
    identity/
    m365/
    hardware/
    camera/
    server/
    facilities/
  remediation/
    # separately gated mutating tools
```

Routes contain metadata and orchestration references; atomic implementation code stays under `tools/`.

---

## 25. Implementation sequence

### Phase 0 — documentation baseline

This document is the coding contract. Do not begin mass tool generation before this structure is accepted.

### Phase 1 — complaint schema

Implement:

- `DiagnosticRoute` schema;
- multilingual alias schema;
- incident narrowing state;
- candidate-route generation;
- structured question schema.

### Phase 2 — clarification engine

Implement:

- universal discriminator catalog;
- question value scoring;
- 1-3 question turn budget;
- "I don't know" handling;
- scope classifier;
- timeline/change extraction.

### Phase 3 — common evidence micro-tools

Build the highest-reuse atomic collectors first:

```text
system.platform.identify
system.resource.snapshot
system.storage.capacity
network.interface.snapshot
network.ipconfig.snapshot
network.route.snapshot
network.dns.snapshot
network.reachability.internal
system.clock.snapshot
time.sync.status
windows.event.system
windows.event.security
service.status.read
certificate.chain.inspect
```

### Phase 4 — domain packs

Implement the 32 domain families incrementally. Every new route reuses common tools before adding a domain-specific collector.

### Phase 5 — remediation tools

Only after diagnostic accuracy and authority gates are proven. Keep write/execute/control tools in separate namespaces and tests.

### Phase 6 — E2E complaint regression corpus

For every `IT-####` route add user-style prompts rather than only technical prompts.

Required examples per route should eventually include:

- clear technical wording;
- vague employee wording;
- Vietnamese;
- Japanese;
- English;
- misleading wording;
- insufficient-information case;
- authority-unavailable case;
- physical-evidence-required case where applicable.

---

## 26. Definition of Done for one complaint route

A route is complete only when all of the following are true:

1. `IT-####` mapping exists.
2. VI/JA/EN aliases exist.
3. vague complaint candidates are tested.
4. clarification questions can narrow the route.
5. scope/blast-radius behavior is tested.
6. minimum read-only evidence plan exists.
7. selected tools are atomic and reusable.
8. authority-unavailable behavior fails closed.
9. UNKNOWN remains UNKNOWN when evidence is missing.
10. physical-boundary behavior exists where relevant.
11. remediation is separated from diagnosis.
12. verification plan exists.
13. E2E regression test exists.
14. no external egress is introduced implicitly.
15. C5 is never entered automatically without existing policy requirements being satisfied.

---

## 27. Safety and trust invariants

These invariants apply to all 650 routes and all future tools:

- evidence before conclusion;
- question before expensive collection when the answer materially narrows scope;
- automatic safe evidence before asking a non-technical user for technical details;
- minimum necessary tool set;
- no authority widening;
- no prompt self-authorization;
- no implicit public/external scanning;
- no security-control bypass;
- no automatic C5 escalation;
- no fabricated physical-state conclusion;
- no destructive action hidden inside a diagnostic collector;
- exact timestamps and provenance retained;
- verification after every authorized mutation;
- complete audit trail.

---

## 28. Final implementation principle

The objective is not to make AI "guess the most likely fix."

The objective is to make WorkSpace behave like a disciplined support engineer:

```text
listen to the user's vague complaint
-> understand what object appears affected
-> determine who/what/how many are affected
-> ask the smallest useful clarification
-> collect the cheapest relevant evidence
-> eliminate hypotheses
-> ask again only if uncertainty remains
-> stop when evidence is sufficient
-> explain the bounded diagnosis in normal language
-> request authority for any mutating action
-> execute the smallest approved action
-> verify the result
-> leave evidence and audit history
```

This architecture turns the 650 real-world complaints into a maintainable diagnostic system without turning WorkSpace into a slow monolithic workflow.