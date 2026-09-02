# WorkSpace DFIR Existing Capability Audit v0.1

Status: repository archaeology checkpoint  
Audit snapshot: `d847b36b63bf1d6c68ca85e5045b55999cd34949`  
Repository: `caotiensinh/3agent`  
Scope: existing WorkSpace core, Security Analyst, network/security monitoring, evidence/correlation, analyst harness, Network AI specialist blueprints, tests and release gates.

## 1. Audit rule

This document exists to prevent duplicate implementation.

No DFIR implementation may be started merely because `DFIR-xx` does not yet exist as a file or class. Existing WorkSpace primitives must be classified first and reused whenever they already provide compatible semantics.

Classification:

- `COMPLETE`: existing implementation already satisfies the relevant required contract.
- `ADEQUATE`: function is substantially sufficient; only adapter/metadata/conformance work is expected.
- `PARTIAL`: useful implementation exists but important DFIR semantics are missing.
- `FOUNDATION`: reusable lower-level primitive exists and must not be duplicated.
- `OVERLAP`: existing/candidate work covers the same semantic area and must be reconciled before new code.
- `GAP`: no useful runtime implementation was found in the audited main snapshot/merged history.
- `UNKNOWN`: repository evidence is insufficient; do not implement until resolved.

## 2. Executive result

WorkSpace is **not starting DFIR from zero**.

The current repository already contains a mature deterministic/security control plane and a substantial Security Analyst backend:

- closed security capability taxonomy and registry;
- approved-inventory-only monitoring policy;
- typed operation planning and authorization;
- reviewed handler binding layer;
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
- bounded task-authorized classic-PCAP evidence reader with hardened file mutation/symlink/root containment controls;
- Security Analyst UI/read models/reporting;
- local chat integration with bounded Security Monitoring context;
- three independent Network AI forensic specialist blueprints;
- extensive deterministic/unit/adversarial/cross-platform release harnesses.

The correct DFIR architecture is therefore:

```text
DFIR Skill Pack
      |
      v
existing SecurityCapabilityRegistry
      |
existing plan / binding / invocation / workflow-audit harness
      |
existing MonitoringStore / evidence refs / replay / entity graph
      |
add only missing forensic contracts + adapters + fixtures
```

Creating a second DFIR orchestrator, second capability registry, second correlation graph, second policy engine, or second audit system would be a regression.

## 3. Current major subsystem inventory

| Subsystem | Current state | Audit classification | Action |
|---|---|---|---|
| Confidential/local-first trust boundary | Core has no default public egress; public research is a separate OS/data zone | `COMPLETE foundation` | Reuse unchanged |
| Task contracts / capability authority | Deterministic typed budgets, capabilities and monotonic security limits | `COMPLETE foundation` | Reuse unchanged |
| Handoff sanitization / evidence validation | D1 trust boundaries and deterministic validator ledger are implemented | `COMPLETE foundation` | Reuse for DFIR handoffs |
| Evaluation / golden / replay / promotion gates | D7 infrastructure exists with deterministic/adversarial evidence | `COMPLETE foundation` | Extend with DFIR fixtures, do not create new CI philosophy |
| Security capability taxonomy | Closed `SECURITY_TAXONOMY` includes network, auth, endpoint, threat hunting, triage and forensics | `COMPLETE foundation` | Map DFIR skills onto existing taxonomy |
| Security operation planning/binding | Closed reviewed operations; unsupported operations remain explicitly unbound | `COMPLETE foundation` | Preserve fail-closed behavior |
| Typed operation invocation v0.5 | Requests cannot supply arbitrary shell/argv/path/target/credential; policy rechecked before handler | `COMPLETE foundation` | Reuse as DFIR invocation boundary |
| Audited analyst workflow v0.6 | Append-only local JSONL audit, per-record SHA-256 + previous-record hash, single-writer locking | `ADEQUATE foundation` | Extend with DFIR case/evidence lineage; do not replace |
| Security Monitoring runtime | Collectors, passive sensors, storage, findings, reports, scheduling and UI exist | `ADEQUATE/PARTIAL` | Extend, not rewrite |
| Source checkpoint + deterministic replay | Source identity/cursor/replay primitives exist | `COMPLETE foundation` | Reuse for forensic reproducibility |
| Health/hysteresis/temporal behavior | Deterministic health and bounded temporal scenarios exist | `COMPLETE for monitoring`, `FOUNDATION for DFIR` | Keep monitoring semantics separate from forensic timeline |
| Rule compiler/work clustering | Deterministic, bounded and policy-separated | `COMPLETE foundation` | Reuse for Sigma-like future adapters |
| Discovery candidate boundary | Candidate != inventory asset, no auto authority | `COMPLETE foundation` | Reuse |
| Flow -> Process attribution | Typed endpoint refs and deterministic graph bridge exist | `PARTIAL DFIR` | Extend to richer process/session evidence |
| DNS/FLOW/AUTH/PROCESS graph | Exact entity-based correlation, no time-only correlation | `ADEQUATE foundation` | Extend node/event families; do not build a competing graph |
| Network incident triage | Local deterministic/advisory triage with strict graph validation | `ADEQUATE foundation` | Reuse for candidate findings/attack paths |
| DNS behavior intelligence | Privacy-preserving typed hashes + baseline/risk logic | `ADEQUATE` | Reuse; add forensic transaction semantics only where missing |
| Flow analysis v0.9 | Deterministic normalized `CorrelationEvent` analysis; bounded events/entities/edges; evidence refs required | `ADEQUATE` | Reuse directly for DFIR flow analysis |
| PCAP evidence read v0.7.1 | Bounded classic PCAP reader, hashes packet payloads, path/symlink/root/file-mutation hardening | `ADEQUATE/PARTIAL` | Extend protocol/session parsing separately; do not rewrite secure file reader |
| Security Analyst UI/config/chat | Configuration bootstrap and chat integration merged; query-only/read-only posture | `PARTIAL E2E` | Continue closure checklist |
| Network AI forensic blueprints | `intrusion-trace-hunting`, `log-incident-diagnosis`, `host-log-forensics` exist as advisory candidate blueprints | `FOUNDATION` | Promote only after runtime evidence + held-out gates |
| Incident timeline | PR #248 implements deterministic incident timeline v0.10 but is open and not merged at audit snapshot | `OVERLAP` | Reconcile PR #248; do not independently implement DFIR-20 |
| Canonical forensic chain of custody | Hashes/evidence refs/audit chains exist, but no unified DFIR EvidenceObject/custody contract was found | `PARTIAL` | Add compatible schema/service extension |
| Formal generic hypothesis engine | Blueprint methods mention hypotheses/contradictions, but no generic runtime hypothesis state engine found | `GAP` | Implement after evidence/timeline contracts stabilize |
| Native endpoint forensic adapters | Auth/endpoint/forensics operations exist in registry but remain unbound by default | `PARTIAL/GAP runtime` | Bind reviewed EVTX/host adapters incrementally |
| Filesystem forensic artifacts | No runtime MFT/Prefetch/Amcache/Shimcache/SRUM pipeline found | `GAP` | Future P1 adapter lane |
| Memory forensics | No runtime memory-image analysis adapter found | `GAP` | Future P1 adapter lane with license review |

## 4. Security Analyst strict E2E state

The existing `docs/SECURITY_ANALYST_E2E_CHECKLIST_V001.md` baseline predates the latest closure commit and therefore contains stale statuses.

Its weighted baseline accepted only SA-01 = 10/100. Commit `d94e9325b29063ed62412a0ef7cf1429248e64a7` merged PR #243, whose explicit scope closes:

- SA-02 Security Configuration Center;
- SA-03 installer/runtime bootstrap;
- SA-09 chat awareness/integration.

Those weights are 12% + 8% + 10%. Combined with SA-01, the **minimum strict accepted E2E score is therefore 40/100**, subject to keeping the same acceptance semantics and no later regression.

The backend engineering maturity is materially higher than 40%, but the remaining checklist items should not receive acceptance credit before their exact acceptance evidence exists.

Remaining strict E2E work:

- SA-04 approved asset onboarding closure;
- SA-05 collector lifecycle E2E closure;
- SA-06 real-LAN read-only collection acceptance;
- SA-07 data pipeline closure/migrations/retention acceptance;
- SA-08 dashboard operational UX closure;
- SA-10 analyst/correlation surfacing closure;
- SA-11 alert/report operationalization;
- SA-12 final exact-head + authorized real-LAN release gate.

Important: synthetic/unit/CI evidence must not be represented as real production-LAN acceptance.

## 5. OSS Network/Security roadmap state

The weighted roadmap in `docs/architecture/OSS_NETWORK_SECURITY_IMPLEMENTATION_CHECKLIST.md` still contains unchecked markdown boxes, but merged implementation history through PR #211 contains source and tests for all planned phases:

1. source checkpoint contracts and compatibility;
2. deterministic replay integration;
3. health state + hysteresis;
4. temporal behavior;
5. rule compiler + authorized work clustering;
6. discovery candidates/enrollment;
7. Flow -> Process attribution;
8. optional authenticated read-only edge agent.

Therefore the markdown checkbox state is stale and must not be used to conclude these phases are missing. The implementations should be treated as reusable foundations and revalidated, not rewritten.

## 6. Existing binding coverage

The current default `SecurityOperationBindingRegistry` deliberately remains conservative.

The registry contains 15 approved operations. Default bindings include reviewed runtime handlers for:

- interface counter read;
- local flow evidence read;
- fixed passive telemetry read;
- DNS evidence analysis;
- local AI incident triage.

Default-unbound operations include PCAP read, configuration snapshot, generic flow analysis, authentication analysis, endpoint analysis, IDS triage, incident timeline, threat hunting and generic forensic analysis.

This does **not** mean all unbound functions are absent. WorkSpace intentionally uses opt-in reviewed profiles for higher-risk/newer paths:

- PCAP task-read profile v0.7/v0.7.1 binds the existing bounded PCAP reader;
- flow analysis profile v0.9 binds the existing deterministic flow analyzer;
- incident timeline v0.10 exists as open PR #248 but is not on `main` at this snapshot.

The default fail-closed registry should stay fail-closed. DFIR work should add reviewed profiles/bindings, not make every operation globally executable.

## 7. DFIR Skill Pack v0.1 overlap matrix

| DFIR | Skill | Existing WorkSpace evidence | Classification | Implementation decision |
|---|---|---|---|---|
| 01 | `evidence_preservation` | SHA-256 evidence refs, PCAP hashes, replay/checkpoint receipts, workflow hash chain | `PARTIAL` | Add canonical evidence/custody schema on existing stores/audit |
| 02 | `incident_scope_builder` | inventory, typed entity context, graph/store readers, bounded windows | `PARTIAL` | Compose existing primitives; add explicit case scope snapshot |
| 03 | `network_session_reconstruction` | Zeek/Suricata normalized events, flow graph, PCAP metadata | `PARTIAL` | Extend session semantics; reuse flow/correlation/PCAP reader |
| 04 | `pcap_forensic_analysis` | hardened classic-PCAP metadata reader v0.7.1 | `PARTIAL/ADEQUATE` | Keep secure reader; add protocol/session adapter, pcapng only behind new review |
| 05 | `dns_trace_analysis` | DNS features, DNS typed refs, exact DNS -> FLOW correlation | `PARTIAL/ADEQUATE` | Add query/answer/TTL/resolver transaction model only |
| 06 | `tls_connection_analysis` | no dedicated runtime TLS forensic analyzer found | `GAP` | New adapter after network session contract |
| 07 | `http_transaction_trace` | no dedicated runtime HTTP transaction forensic analyzer found | `GAP` | New adapter after session contract |
| 08 | `network_flow_correlation` | `flow_analysis.py`, correlation graph/store, Zeek/Suricata evidence | `ADEQUATE` | Reuse; expand source adapters only |
| 09 | `authentication_forensics` | AUTH stage correlation exists; registry operation exists but is default-unbound | `PARTIAL` | Add reviewed auth forensic adapter/binding |
| 10 | `windows_event_forensics` | host-log-forensics blueprint + Windows evidence domains; no runtime EVTX forensic adapter found | `FOUNDATION/GAP runtime` | Implement adapter, not another skill philosophy |
| 11 | `process_tree_reconstruction` | AUTH -> PROCESS graph + Flow -> Process attribution | `PARTIAL` | Extend existing graph with process identity/start-time/parent edges |
| 12 | `persistence_hunt` | host-log-forensics blueprint covers service/task/registry/WMI persistence | `FOUNDATION/GAP runtime` | Implement runtime observations/findings after Windows adapter |
| 13 | `filesystem_artifact_analysis` | no runtime forensic filesystem artifact pipeline found | `GAP` | New bounded read-only adapter lane |
| 14 | `memory_forensics` | no runtime memory-image forensic pipeline found | `GAP` | New bounded external-engine lane; license review required |
| 15 | `malware_indicator_analysis` | generic rule/compiler foundation exists; no dedicated YARA/hash forensic corpus runtime found | `PARTIAL foundation` | Reuse rule provenance/governance; add static indicator adapter |
| 16 | `lateral_movement_trace` | entity correlation, AUTH/PROCESS/FLOW graph, intrusion/host-forensics blueprints | `PARTIAL` | Compose existing graph; add dedicated semantics/fixtures |
| 17 | `credential_abuse_trace` | auth context + host-forensics blueprint; no dedicated runtime analyzer | `PARTIAL` | Extend auth adapter + hypothesis logic |
| 18 | `exfiltration_analysis` | network behavior intelligence includes large outbound transfer candidate signals | `PARTIAL` | Add process/session/baseline/counterevidence semantics |
| 19 | `anti_forensics_detection` | health/data-gap primitives + host-forensics visibility-gap blueprint | `PARTIAL` | Add explicit clearing/tamper evidence adapter and benign rotation counterexamples |
| 20 | `super_timeline_builder` | temporal primitives on main; deterministic incident timeline v0.10 in open PR #248 | `OVERLAP` | Reconcile/review #248 first; do not create another timeline implementation |
| 21 | `ioc_pivot_graph` | typed entity refs + deterministic IncidentGraph | `PARTIAL/ADEQUATE` | Extend entity types/relations; reuse graph/store |
| 22 | `attack_path_reconstruction` | IncidentGraph + Network Incident Triage + intrusion-trace blueprint | `PARTIAL` | Add ranked candidate-path layer only after timeline |
| 23 | `hypothesis_testing` | contradiction discipline exists in blueprints/triage philosophy; no generic runtime state engine found | `GAP` | New deterministic hypothesis contract on existing evidence refs |
| 24 | `forensic_case_reporter` | deterministic reports, AI analyst, evidence refs/citation allowlists | `PARTIAL` | Extend report schema with case manifest, contradictions, limitations and review |

## 8. Components explicitly forbidden to rewrite

The next DFIR plan must treat the following as existing assets unless a failing test proves a specific defect:

1. `SecurityCapabilityRegistry` and security taxonomy.
2. Monitoring policy / approved-inventory authority.
3. Security operation plan compiler.
4. Operation binding registry and fail-closed default behavior.
5. Typed operation invocation gate.
6. Security workflow audit journal/hash chain.
7. MonitoringStore and existing normalized monitoring contracts.
8. Source checkpoint / deterministic replay.
9. Existing passive collectors/sensor adapters.
10. Typed entity references / entity-context storage.
11. DNS -> FLOW -> AUTH -> PROCESS / IDS correlation graph.
12. Flow -> Process attribution primitives.
13. Network Incident Triage.
14. DNS behavior intelligence.
15. Flow analysis v0.9.
16. Hardened PCAP evidence reader v0.7.1.
17. Health/hysteresis/temporal scenario engine.
18. Rule compiler + authorized work clustering.
19. Discovery candidate/enrollment boundary.
20. Optional authenticated edge evidence envelope.
21. Security Analyst read models/UI/reporting foundation.
22. Chat read-only Security Monitoring integration.
23. Existing golden/replay/adversarial/exact-head CI governance.
24. Existing Network AI forensic specialist blueprints.

## 9. Next plan derived from the audit

The plan below contains only extension/gap work. It intentionally excludes capabilities already implemented well.

### P0-A — Reconcile existing timeline work before new timeline code

Owner capability: DFIR-20.

- Re-read PR #248 exact head/base/current main.
- Reconcile its four files with current `main` without overwriting concurrent work.
- Preserve opt-in reviewed binding and default `UNBOUND_TIMELINE_ADAPTER_REQUIRED` behavior.
- Run exact-head harness/deployment gates.
- Merge only if the reconciled exact head passes.

**Do not implement another timeline builder.**

### P0-B — Canonical DFIR evidence/case contract as an extension

Owner capabilities: DFIR-01, DFIR-02.

Add versioned contracts for:

- `CaseRecord` / case authorization;
- `EvidenceObject` raw/derived distinction;
- acquisition + transport + content SHA-256;
- provenance + collector/parser versions;
- append-only custody events;
- original timestamp/timezone/clock uncertainty;
- evidence refs resolvable from current MonitoringStore/PCAP/audit records.

Do not replace MonitoringStore or workflow audit. Add adapters/migrations only where needed.

### P0-C — DFIR conformance harness and synthetic fixtures

Reuse D7/harness CI. Add fixture manifests and golden/negative/determinism/security tests for C1/C2/T1 first.

Required first gates:

- evidence hash mismatch fail-closed;
- missing provenance fail-closed;
- broken evidence reference fail-closed;
- input permutation gives deterministic timeline/graph;
- contradiction cannot be hidden;
- no skill can gain target execution/remediation/egress authority.

### P0-D — Formal hypothesis engine

Owner: DFIR-23.

Implement a deterministic contract over existing observation/evidence refs:

```text
open -> supported | contradicted | inconclusive -> confirmed-by-human
```

No LLM-created evidence IDs. Supporting and contradicting evidence are first-class fields. Human confirmation remains a separate audited action.

### P0-E — Forensic case report extension

Owner: DFIR-24.

Extend existing deterministic reporting rather than build a second report subsystem. Require:

- case/evidence manifest digest;
- findings + hypotheses;
- support + contradiction refs;
- limitations/data gaps;
- timeline references;
- skill/rule/parser versions;
- review state;
- broken-reference negative tests.

### P1-A — Bind endpoint/authentication forensic evidence

Owners: DFIR-09, 10, 11, 12, 16, 17, 19.

Implement one bounded endpoint evidence adapter family first, preferably Windows log evidence because the existing `host-log-forensics` blueprint already defines the reasoning/output requirements.

- bind `security.authentication.analyze#analyze_authentication_evidence` only after contract+fixtures pass;
- bind `security.endpoint.analyze#analyze_endpoint_evidence` only after contract+fixtures pass;
- keep raw secrets out;
- extend current entity graph rather than create a second process graph.

### P1-B — Network protocol forensic enrichment

Owners: DFIR-03, 04, 05, 06, 07, 08.

Reuse the current PCAP reader, Zeek/Suricata parser path and flow analyzer. Add canonical session/DNS/TLS/HTTP observations in that order.

Do not expose raw packet payloads to analyst/model surfaces by default.

### P1-C — Filesystem and memory forensic adapters

Owners: DFIR-13, DFIR-14, DFIR-15.

Only after EvidenceObject/custody/sandbox contracts are stable:

- filesystem artifacts read-only;
- memory image adapter behind a separately reviewed external process/license boundary;
- static indicator matching with rule corpus digest/version/license;
- no sample execution.

### P1-D — Attack path and movement reconstruction

Owners: DFIR-16, DFIR-21, DFIR-22.

Use the existing typed entity graph + reconciled timeline + hypothesis engine. Add candidate/alternate path semantics and explicit missing links. Never invent graph edges.

## 10. Execution order

```text
0. Reconcile existing PR #248 timeline work
1. Evidence/case contracts
2. DFIR conformance fixtures/harness
3. Hypothesis engine
4. Forensic case report extension
5. Windows/auth endpoint adapter
6. Session/DNS/TLS/HTTP enrichment
7. Persistence/lateral/credential/anti-forensics composition
8. Filesystem adapter
9. Memory/static indicator adapter
10. Attack-path composition
11. End-to-end T1 case replay
12. Security review + DFIR analyst review + exact-head CI
```

## 11. Measurement

### WorkSpace core

Core deterministic control-plane phases D0/D1/D2 and the main D6/D7 governance foundations are already implemented. They are dependencies, not new DFIR backlog.

### Security Analyst E2E

Strict weighted accepted score after the #243 closure slice: **minimum 40/100**. The technical backend is further along, but remaining weight stays unearned until exact acceptance evidence is produced.

### DFIR v0.1

At audit snapshot:

- strong reusable foundation exists for network monitoring, evidence references, policy, invocation, audit, correlation, PCAP-read, DNS/flow analysis and reporting;
- several DFIR skills are `PARTIAL/ADEQUATE` orchestration over those primitives;
- the largest genuine runtime gaps are canonical chain-of-custody/case semantics, formal hypothesis testing, native endpoint forensic adapters, filesystem artifacts and memory forensics;
- DFIR-20 already has overlapping implementation work in PR #248 and is therefore **not a greenfield task**.

Progress for DFIR must be measured by **enabled skills passing contract + fixtures + evidence provenance + permission + human-review gates**, not by counting 24 class names.

## 12. Immediate next checkpoint

The first implementation checkpoint after this audit is **not** a new DFIR skill.

It is:

> Safely reconcile the already-written deterministic incident timeline v0.10 (PR #248) onto the current main, validate it on the exact reconciled head, and only then move to the canonical DFIR Evidence/Case contract.

This preserves completed work, avoids duplicate implementation, and makes the next DFIR foundation depend on actual repository state rather than a parallel design.