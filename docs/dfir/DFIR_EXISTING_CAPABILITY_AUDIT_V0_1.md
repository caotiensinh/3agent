# WorkSpace DFIR Existing Capability Audit v0.1

Status: repository archaeology checkpoint  
Capability snapshot: `45beee6b1076900b4d02dc3cea1ee46644163515`  
Repository: `caotiensinh/3agent`  
Scope: WorkSpace core, Security Analyst, network/security monitoring, evidence/correlation, analyst harness, Network AI forensic blueprints, tests and release gates.

## 1. Audit rule

This audit exists to prevent duplicate implementation.

No DFIR implementation may start merely because a `DFIR-xx` class/file does not exist. Existing WorkSpace primitives must be classified and reused first.

Classification:

- `COMPLETE`: required semantics and gates are already present.
- `ADEQUATE`: implementation is substantially sufficient; only adapter/metadata/conformance work is expected.
- `PARTIAL`: useful implementation exists but important DFIR semantics are missing.
- `FOUNDATION`: reusable lower-level primitive exists and must not be duplicated.
- `OVERLAP`: parallel/candidate work exists and must be reconciled first.
- `GAP`: no useful runtime implementation was found in the audited main/merged history.
- `UNKNOWN`: evidence is insufficient; do not implement until resolved.

## 2. Executive result

WorkSpace is **not starting DFIR from zero**.

The current repository already contains a mature deterministic/security control plane and a substantial Security Analyst backend:

- closed security capability taxonomy and registry;
- approved-inventory-only monitoring policy;
- typed operation planning and authorization;
- reviewed operation binding layer;
- typed invocation gate;
- append-only hash-chained analyst workflow audit;
- deterministic monitoring collectors and passive sensors;
- normalized observations/events/findings;
- checkpoints and deterministic replay;
- health state/hysteresis;
- temporal behavior scenarios;
- deterministic rule compiler/work clustering;
- discovery candidate/enrollment boundary;
- Flow -> Process attribution;
- optional authenticated read-only edge evidence transport;
- typed/hash entity references;
- DNS -> FLOW -> AUTH -> PROCESS and IDS corroboration graph;
- bounded Network Incident Triage;
- deterministic DNS behavior intelligence;
- reviewed internal flow analysis v0.9;
- bounded task-authorized classic-PCAP evidence reader v0.7.1;
- deterministic incident timeline v0.10;
- Security Analyst UI/read models/reporting;
- local chat integration with bounded Security Monitoring context;
- three independent Network AI forensic specialist blueprints;
- deterministic/unit/adversarial/cross-platform release harnesses.

Correct DFIR integration path:

```text
DFIR Skill Pack
      |
      v
existing SecurityCapabilityRegistry
      |
existing plan / binding / invocation / workflow-audit harness
      |
existing MonitoringStore / evidence refs / replay / entity graph / timeline
      |
add only missing forensic contracts + adapters + fixtures
```

Creating a second DFIR orchestrator, capability registry, policy engine, audit system, correlation graph or timeline engine would be a regression.

## 3. Current major subsystem inventory

| Subsystem | Current state | Classification | Required action |
|---|---|---|---|
| Confidential/local-first trust boundary | Confidential Core has no default public egress; public research is separately bounded | `COMPLETE foundation` | Reuse unchanged |
| Task contracts / capability authority | Deterministic typed budgets, capabilities and monotonic authority | `COMPLETE foundation` | Reuse unchanged |
| Handoff sanitization / validator ledger | D1/D2 trust and structured validation are implemented | `COMPLETE foundation` | Reuse for DFIR handoffs |
| Evaluation / golden / replay / promotion gates | D7 infrastructure exists with regression/adversarial evidence | `COMPLETE foundation` | Add DFIR fixtures to existing harness |
| Security capability taxonomy | Network/auth/endpoint/threat-hunting/triage/forensics categories exist | `COMPLETE foundation` | Map DFIR operations onto it |
| Operation plan/binding | Closed reviewed operations; unsupported paths remain explicitly unbound | `COMPLETE foundation` | Preserve fail-closed default |
| Typed invocation v0.5 | No arbitrary shell/argv/path/target/credential from routed requests | `COMPLETE foundation` | Reuse as DFIR runtime gate |
| Analyst workflow v0.6 | Append-only JSONL, SHA-256 per record + previous-record hash, single-writer locking | `ADEQUATE foundation` | Extend case/evidence lineage; do not replace |
| Security Monitoring runtime | Collectors, passive sensors, storage, findings, reports, schedule/UI | `ADEQUATE/PARTIAL` | Extend, not rewrite |
| Checkpoint + deterministic replay | Stable source identity/cursor/replay primitives | `COMPLETE foundation` | Reuse for forensic reproducibility |
| Health/hysteresis/temporal behavior | Deterministic monitoring state/scenario logic | `COMPLETE monitoring / FOUNDATION DFIR` | Keep separate from forensic conclusion semantics |
| Rule compiler/work clustering | Deterministic, bounded and policy-separated | `COMPLETE foundation` | Reuse for future rule adapters |
| Discovery boundary | Candidate != approved inventory; no automatic authority | `COMPLETE foundation` | Reuse |
| Flow -> Process attribution | Typed endpoint refs + deterministic graph bridge | `PARTIAL DFIR` | Add richer process/session evidence |
| DNS/FLOW/AUTH/PROCESS graph | Exact entity-linked correlation; time-only linkage denied | `ADEQUATE foundation` | Extend node/event families only |
| Network Incident Triage | Deterministic/advisory and strict graph validation | `ADEQUATE foundation` | Reuse for candidate findings/paths |
| DNS behavior intelligence | Typed hashes + baselines/risk | `ADEQUATE` | Add forensic transaction semantics only |
| Flow analysis v0.9 | Bounded normalized `CorrelationEvent` analysis with required evidence refs | `ADEQUATE` | Reuse directly |
| PCAP evidence read v0.7.1 | Hardened bounded classic-PCAP read, hashes, path/symlink/root/mutation controls | `ADEQUATE/PARTIAL` | Preserve reader; add protocol/session adapters separately |
| Incident timeline v0.10 | Merged by `45beee6...`; deterministic correlation required; evidence-linked, advisory-only | `ADEQUATE/PARTIAL` | Extend time provenance/clock uncertainty for DFIR super-timeline semantics |
| Security Analyst UI/config/chat | Configuration bootstrap + bounded chat awareness merged | `PARTIAL E2E` | Continue strict closure checklist |
| Network AI forensic blueprints | `intrusion-trace-hunting`, `log-incident-diagnosis`, `host-log-forensics` | `FOUNDATION` | Runtime promotion only after evidence/eval gates |
| Canonical forensic chain of custody | Hash/evidence/audit primitives exist; unified forensic `EvidenceObject`/custody contract not found | `PARTIAL` | Add compatible schema extension |
| Generic hypothesis state engine | Contradiction discipline exists conceptually; generic runtime state engine not found | `GAP` | Implement after evidence contract |
| Native endpoint forensic adapters | Registry has auth/endpoint/forensics operations but they remain unbound by default | `PARTIAL/GAP runtime` | Bind reviewed adapters incrementally |
| Filesystem forensic artifacts | No runtime MFT/Prefetch/Amcache/Shimcache/SRUM pipeline found | `GAP` | Future P1 adapter lane |
| Memory forensics | No runtime memory-image forensic pipeline found | `GAP` | Future P1 external-engine lane |

## 4. Security Analyst strict E2E state

`docs/SECURITY_ANALYST_E2E_CHECKLIST_V001.md` was written before the latest closure slice and therefore has stale baseline statuses.

Baseline accepted SA-01 = 10/100. Commit `d94e9325b29063ed62412a0ef7cf1429248e64a7` merged PR #243, whose explicit closure scope covers:

- SA-02 Security Configuration Center = 12%;
- SA-03 installer/runtime bootstrap = 8%;
- SA-09 Chat <-> Security Analyst integration = 10%.

Together with SA-01, the **minimum strict accepted E2E score is 40/100** under the existing weighted checklist, assuming no later regression. Backend engineering maturity is materially higher, but remaining weight must stay unearned until exact acceptance evidence exists.

Remaining strict E2E acceptance:

- SA-04 approved asset onboarding;
- SA-05 collector lifecycle E2E;
- SA-06 authorized real-LAN read-only collection;
- SA-07 data pipeline/migration/retention closure;
- SA-08 operational dashboard UX;
- SA-10 analyst/correlation surfacing;
- SA-11 alerts/reports operationalization;
- SA-12 exact-head + authorized real-LAN release gate.

Synthetic/unit/CI evidence must never be represented as production-LAN acceptance.

## 5. OSS Network/Security roadmap state

The markdown checkboxes in `docs/architecture/OSS_NETWORK_SECURITY_IMPLEMENTATION_CHECKLIST.md` are stale. Merged source/tests through PR #211 provide the implementation families for the full weighted roadmap:

1. checkpoint/compatibility;
2. deterministic replay;
3. health state/hysteresis;
4. temporal behavior;
5. rule compiler/work clustering;
6. discovery candidates/enrollment;
7. Flow -> Process attribution;
8. optional authenticated read-only edge agent.

These are reusable foundations, not missing work.

## 6. Current reviewed binding posture

The current default `SecurityOperationBindingRegistry` intentionally stays conservative. It contains 15 approved operations and keeps unsupported/newer operations explicitly unbound in the default profile.

Default reviewed handlers cover:

- interface counter read;
- local flow evidence read;
- fixed passive telemetry read;
- DNS evidence analysis;
- local AI incident triage.

Additional reviewed opt-in profiles now exist for:

- two PCAP read operations through v0.7/v0.7.1;
- flow analysis v0.9;
- incident timeline v0.10.

That means reviewed runtime paths exist for **at least 9/15 operations (60%)**, while the default registry deliberately remains more restrictive. This fail-closed architecture must be preserved; DFIR should add reviewed profiles rather than globally binding everything.

Still-default-unbound areas include configuration snapshot, authentication analysis, endpoint analysis, IDS triage, threat hunting and generic forensic analysis.

## 7. DFIR Skill Pack v0.1 overlap matrix

| DFIR | Skill | Existing WorkSpace evidence | Classification | Decision |
|---|---|---|---|---|
| 01 | `evidence_preservation` | SHA-256 refs, PCAP hashes, replay/checkpoint receipts, workflow hash chain | `PARTIAL` | Add canonical evidence/custody contract on existing stores/audit |
| 02 | `incident_scope_builder` | inventory, typed entity context, graph/store readers, bounded windows | `PARTIAL` | Compose existing primitives; add explicit case scope snapshot |
| 03 | `network_session_reconstruction` | Zeek/Suricata events, flow graph, PCAP metadata | `PARTIAL` | Extend session semantics; reuse existing flow/correlation/PCAP |
| 04 | `pcap_forensic_analysis` | hardened classic-PCAP metadata reader v0.7.1 | `PARTIAL/ADEQUATE` | Preserve secure reader; add protocol/session adapter |
| 05 | `dns_trace_analysis` | DNS features, typed refs, exact DNS -> FLOW correlation | `PARTIAL/ADEQUATE` | Add query/answer/TTL/resolver transaction model only |
| 06 | `tls_connection_analysis` | no dedicated runtime TLS forensic analyzer found | `GAP` | Add adapter after session contract |
| 07 | `http_transaction_trace` | no dedicated runtime HTTP forensic transaction analyzer found | `GAP` | Add adapter after session contract |
| 08 | `network_flow_correlation` | flow analysis, correlation graph/store, Zeek/Suricata evidence | `ADEQUATE` | Reuse; add source adapters only |
| 09 | `authentication_forensics` | AUTH correlation exists; capability registered but default-unbound | `PARTIAL` | Add reviewed auth adapter/binding |
| 10 | `windows_event_forensics` | host-forensics blueprint + Windows evidence domains; no runtime EVTX adapter found | `FOUNDATION/GAP runtime` | Implement bounded adapter |
| 11 | `process_tree_reconstruction` | AUTH -> PROCESS graph + Flow -> Process attribution | `PARTIAL` | Extend current graph with process identity/start/parent edges |
| 12 | `persistence_hunt` | host-forensics blueprint covers service/task/registry/WMI | `FOUNDATION/GAP runtime` | Implement after Windows adapter |
| 13 | `filesystem_artifact_analysis` | no runtime forensic filesystem pipeline found | `GAP` | Add bounded read-only adapter lane |
| 14 | `memory_forensics` | no runtime memory-image pipeline found | `GAP` | Add separately reviewed external-engine lane |
| 15 | `malware_indicator_analysis` | rule compiler/governance foundation; no dedicated static forensic matcher runtime found | `PARTIAL foundation` | Reuse rule provenance; add static indicator adapter |
| 16 | `lateral_movement_trace` | entity graph + AUTH/PROCESS/FLOW + forensic blueprints | `PARTIAL` | Compose existing graph with dedicated fixtures |
| 17 | `credential_abuse_trace` | auth context + host-forensics blueprint | `PARTIAL` | Extend auth + hypothesis layer |
| 18 | `exfiltration_analysis` | behavior intelligence includes large outbound transfer candidates | `PARTIAL` | Add process/session/baseline/counterevidence semantics |
| 19 | `anti_forensics_detection` | health/data-gap primitives + visibility-gap blueprint | `PARTIAL` | Add explicit clearing/tamper observations + benign rotation fixtures |
| 20 | `super_timeline_builder` | deterministic incident timeline v0.10 merged on main | `ADEQUATE/PARTIAL` | Reuse; extend original-time/timezone/clock-uncertainty semantics, never rewrite |
| 21 | `ioc_pivot_graph` | typed entity refs + deterministic IncidentGraph | `PARTIAL/ADEQUATE` | Extend entity/relation coverage on current graph |
| 22 | `attack_path_reconstruction` | IncidentGraph + Network Incident Triage + intrusion-trace blueprint | `PARTIAL` | Add candidate/alternate path layer only |
| 23 | `hypothesis_testing` | contradiction philosophy exists; generic runtime state engine not found | `GAP` | Add deterministic hypothesis contract over existing evidence refs |
| 24 | `forensic_case_reporter` | deterministic reports, AI analyst, evidence refs/citation allowlists | `PARTIAL` | Extend existing reporter with forensic case semantics |

## 8. Components explicitly forbidden to rewrite

Unless a failing test proves a concrete defect, the next DFIR work must reuse:

1. `SecurityCapabilityRegistry` and security taxonomy.
2. Monitoring policy / approved-inventory authority.
3. Security operation plan compiler.
4. Operation binding registry and fail-closed default.
5. Typed operation invocation gate.
6. Security workflow audit hash chain.
7. MonitoringStore and normalized monitoring contracts.
8. Source checkpoint / deterministic replay.
9. Existing collectors/passive sensor adapters.
10. Typed entity refs / entity-context storage.
11. DNS -> FLOW -> AUTH -> PROCESS / IDS correlation graph.
12. Flow -> Process attribution.
13. Network Incident Triage.
14. DNS behavior intelligence.
15. Flow analysis v0.9.
16. Hardened PCAP evidence reader v0.7.1.
17. Incident timeline v0.10.
18. Health/hysteresis/temporal scenario engine.
19. Rule compiler + work clustering.
20. Discovery/enrollment boundary.
21. Optional authenticated edge envelope.
22. Security Analyst UI/read-model/reporting foundation.
23. Chat read-only Security Monitoring integration.
24. Existing D7/golden/replay/adversarial/exact-head CI governance.
25. Existing Network AI forensic specialist blueprints.

## 9. Next plan derived from actual gaps

This plan contains extension/gap work only.

### P0-A — Canonical DFIR Evidence/Case contract

Owners: DFIR-01, DFIR-02.

Add versioned contracts compatible with existing MonitoringStore/audit/timeline:

- `CaseRecord` and case authorization;
- raw vs derived `EvidenceObject`;
- acquisition/transport/content SHA-256;
- provenance + collector/parser version;
- append-only custody events;
- original timestamp/timezone/clock uncertainty;
- resolvable evidence references from current monitoring, PCAP and audit records.

Do **not** create a replacement evidence store or audit journal.

### P0-B — DFIR conformance fixtures/harness

Reuse existing D7/harness CI. Add C1/C2/T1 first with:

- hash mismatch fail-closed;
- missing provenance fail-closed;
- broken evidence ref fail-closed;
- input permutation deterministic graph/timeline;
- contradiction cannot be hidden;
- no target execution/remediation/egress authority.

### P0-C — Extend incident timeline to forensic time semantics

Owner: DFIR-20.

Use merged v0.10. Add only missing semantics:

- original timestamp;
- original timezone;
- clock source;
- clock uncertainty;
- explicit conflicts/gaps;
- deterministic ordering under uncertainty.

No second timeline implementation.

### P0-D — Formal hypothesis engine

Owner: DFIR-23.

```text
open -> supported | contradicted | inconclusive -> confirmed-by-human
```

Requirements:

- evidence IDs must resolve;
- support and contradiction are first-class;
- confidence cannot hide material contradiction;
- human confirmation is a separately audited action.

### P0-E — Forensic case report extension

Owner: DFIR-24.

Extend the current deterministic report path with:

- case/evidence manifest digest;
- hypotheses/findings;
- support + contradiction refs;
- limitations/data gaps;
- timeline refs;
- skill/rule/parser versions;
- review state;
- broken-reference negative test.

### P1-A — Windows/auth endpoint forensic adapter

Owners: DFIR-09, 10, 11, 12, 16, 17, 19.

Use the existing `host-log-forensics` blueprint and current capability registry. Implement one bounded Windows evidence family first, then bind:

- `security.authentication.analyze#analyze_authentication_evidence`;
- `security.endpoint.analyze#analyze_endpoint_evidence`.

No raw secrets. Extend existing graph; do not create a second process graph.

### P1-B — Network protocol forensic enrichment

Owners: DFIR-03, 04, 05, 06, 07, 08.

Reuse PCAP v0.7.1, Zeek/Suricata parsing and flow v0.9. Add canonical observations in order:

```text
session -> DNS transaction -> TLS metadata -> HTTP transaction
```

Raw packet payload must not enter analyst/model surfaces by default.

### P1-C — Filesystem/memory/static indicator adapters

Owners: DFIR-13, 14, 15.

Only after EvidenceObject/custody/sandbox contracts stabilize:

- filesystem artifacts read-only;
- memory engine behind separately reviewed process/license boundary;
- static indicator matching with rule-corpus digest/version/license;
- never execute samples.

### P1-D — Movement / attack-path composition

Owners: DFIR-16, 21, 22.

Use current entity graph + timeline + hypothesis engine. Add candidate/alternate paths and explicit missing links. Never invent an edge.

## 10. Execution order

```text
1. Evidence/Case contracts
2. C1/C2/T1 conformance harness
3. Timeline forensic-time extension on v0.10
4. Hypothesis engine
5. Forensic case-report extension
6. Windows/auth endpoint adapter
7. Session/DNS/TLS/HTTP enrichment
8. Persistence/lateral/credential/anti-forensics composition
9. Filesystem adapter
10. Memory/static-indicator adapter
11. Attack-path composition
12. End-to-end T1 replay
13. Security review + DFIR analyst review + exact-head CI
```

## 11. Measured state

### WorkSpace core

D0/D1/D2 and the main D6/D7 governance foundations are already implemented. They are dependencies, not DFIR backlog.

### Security Analyst E2E

Strict weighted accepted score from the existing checklist after #243: **minimum 40/100**. Technical backend maturity is higher, but unverified acceptance weight remains unearned.

### Security operation runtime

At least **9/15 reviewed operations (60%)** have a reviewed default or opt-in runtime path after PCAP v0.7.1, flow v0.9 and timeline v0.10. Default binding remains intentionally stricter.

### DFIR v0.1

Strong reusable foundations already exist for policy, invocation, audit, network monitoring, replay, entity correlation, PCAP evidence read, DNS/flow analysis, incident triage, timeline and reporting.

Largest genuine gaps are:

1. canonical forensic Evidence/Case + chain-of-custody semantics;
2. formal hypothesis state engine;
3. runtime Windows/auth/endpoint forensic adapters;
4. filesystem forensic artifacts;
5. memory forensic adapter;
6. protocol enrichments such as TLS/HTTP;
7. forensic case-report/review completion.

Progress must be measured by enabled skills passing contract + fixtures + provenance + permission + contradiction + human-review gates, not by creating 24 class names.

## 12. Immediate next checkpoint

The next implementation checkpoint is:

> **DFIR P0-A — Canonical Evidence/Case Contract v1**, implemented as an extension over the current WorkSpace monitoring/evidence/audit primitives.

Timeline v0.10 is already merged and must be reused, not rebuilt.