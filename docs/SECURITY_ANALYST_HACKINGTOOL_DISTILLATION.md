# WorkSpace Security Analyst — HackingTool Distillation and Integration Blueprint

Status: **architecture/integration baseline**  
Decision: **ADOPT CONCEPTS — DO NOT VENDOR THE HACKINGTOOL RUNTIME**  
Target product: **WorkSpace local-first enterprise runtime**  
Primary domain: **network analysis, cybersecurity monitoring, incident triage and evidence-backed diagnostics**

## 1. Purpose

This document extracts the highest-value architectural ideas from `Z4nzu/hackingtool` and translates them into WorkSpace-native security capabilities.

The objective is not to turn WorkSpace into a penetration-testing distribution and not to import a large offensive-tool dependency tree. The objective is to reuse the engineering ideas that improve operator reliability:

- declarative tool/capability catalogs;
- closed taxonomies instead of free-form tool invention;
- curated-first command/runbook selection;
- AI planning that cannot mint execution authority;
- explicit approval before active operations;
- structured audit trails;
- evidence-only AI triage and reporting;
- untrusted-tool-output handling;
- safe discovery/promotion of new tools;
- local/offline model support and graceful deterministic fallback.

This blueprint is designed to fit the existing WorkSpace principles: constraint-first engineering, capability/authority separation, immutable task authority, evidence provenance, local inference, default-deny networking and enterprise review gates.

## 2. Source provenance

Upstream project reviewed:

- Repository: `https://github.com/Z4nzu/hackingtool`
- Reviewed upstream head observed during this design pass: `ef5334f8d37e5be2eecbf56e334f5e3f0f6817ec`
- License: MIT
- Relevant upstream areas reviewed:
  - `README.md`
  - `SECURITY.md`
  - `src/hackingtool/registry.py`
  - `src/hackingtool/ai_recommend.py`
  - `src/hackingtool/ai_command.py`
  - `src/hackingtool/ai_goal.py`
  - `src/hackingtool/ai_summary.py`
  - `src/hackingtool/catalog/forensics.yaml`

WorkSpace does **not** copy the upstream runtime or its catalog wholesale. This document distills architecture and operating principles into a new WorkSpace-native design.

## 3. Architectural decision

### Adopt

WorkSpace SHOULD adopt these patterns:

1. **Closed intent taxonomy** — AI maps requests to approved capability identifiers, not arbitrary tool names.
2. **Declarative capability registry** — tools are data with explicit inputs, effects, risk, scope and evidence contracts.
3. **Curated-first behavior** — reviewed runbooks/templates are selected before model-generated suggestions.
4. **Model-as-proposer** — a model may propose a plan or bounded arguments but can never authorize execution.
5. **Stepwise execution** — active work is decomposed into independently validated and auditable steps.
6. **Evidence-only analysis** — AI analyzes real normalized evidence and may not invent findings.
7. **Untrusted-output envelope** — log/tool/PCAP-derived text is data, never authority or instructions.
8. **Inert discovery** — newly discovered tools cannot become executable merely because metadata was found.
9. **Supply-chain verification** — reviewed version/hash/SBOM/provenance are required before a capability is promoted.
10. **Local-first inference** — security analysis uses local WorkSpace model routing by default.

### Reject

WorkSpace production MUST NOT inherit these characteristics from a general hacking toolkit:

- a monolithic catalog of hundreds of third-party offensive tools;
- arbitrary `git clone`, `pip install`, `go install`, package installation or shell snippets at runtime;
- generic shell authority;
- DDoS tooling;
- RAT tooling;
- phishing tooling;
- payload creation;
- credential cracking as an autonomous production capability;
- exploit frameworks as a normal WorkSpace runtime dependency;
- wireless attack tooling;
- SQL injection/XSS exploitation tooling;
- post-exploitation tooling;
- any capability whose primary purpose is persistence, evasion, destructive action or unauthorized access.

These categories may exist only as external threat-reference knowledge or isolated authorized lab research, never as default WorkSpace enterprise runtime authority.

## 4. Core WorkSpace security principle

The central invariant is:

> Capability knowledge is not capability authority.

A skill may know that `nmap`, `tshark`, `mtr`, Zeek or Suricata exists. A model may know how those tools work. Neither fact authorizes execution.

All active behavior must remain bounded by the existing WorkSpace authority chain:

```text
TaskContract
  -> immutable task/model authority
  -> Capability Broker
  -> SecurityCapability decision
  -> scope/effect/parameter validation
  -> optional human approval
  -> execution gateway
  -> evidence capture
```

Prompt text, model output, tool output, log content, PCAP payload content and web/file content are never authority inputs.

## 5. Target subsystem

The integration target is a new logical subsystem:

**WorkSpace Security Analyst Harness**

It is not a new all-powerful agent. It is a collection of deterministic capabilities and evidence-backed analysis stages that can be invoked by existing WorkSpace workflows.

```text
                       NETWORK / HOST TELEMETRY

 Syslog   SNMP   NetFlow/IPFIX   DNS   Windows   Sysmon   IDS   PCAP
    \       |        |            |       |        |      |      /
     \------|--------|------------|-------|--------|------|-----/
                            |
                            v
                    +---------------+
                    |  Collectors   |
                    +-------+-------+
                            |
                            v
                    +---------------+
                    | Normalization |
                    +-------+-------+
                            |
                            v
                    +---------------+
                    | Evidence Store|
                    +-------+-------+
                            |
                  +---------+---------+
                  |                   |
                  v                   v
          +---------------+   +---------------+
          | Correlation   |   | Baseline /    |
          | Engine        |   | Anomaly Logic |
          +-------+-------+   +-------+-------+
                  |                   |
                  +---------+---------+
                            |
                            v
                 +---------------------+
                 | Security Analyst AI |
                 | evidence only       |
                 +----------+----------+
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          Facts / findings       Hypotheses / gaps
                 |                     |
                 +----------+----------+
                            |
                            v
                 Recommendation / Report
```

## 6. Closed security taxonomy

The first implementation should use a small, stable taxonomy. Model outputs outside the taxonomy are rejected.

Recommended v0.1 taxonomy:

```text
network.inventory
network.health
network.latency
network.path
network.interface
network.dns
network.flow
network.pcap
network.device
network.service
security.ids
security.authentication
security.endpoint
security.threat_hunting
security.incident_triage
security.forensics
security.vulnerability_assessment
security.configuration_review
```

The taxonomy is intentionally capability-oriented. It does not expose arbitrary binaries to the model.

Example:

```text
User: "Why is 192.168.11.93 intermittently losing packets?"
   -> network.health
   -> network.latency
   -> network.path
   -> approved diagnostic plan
```

The model does not jump directly from free text to an unrestricted command.

## 7. SecurityCapability registry

HackingTool's declarative catalog is useful, but WorkSpace needs a stricter enterprise schema.

Recommended logical schema:

```yaml
schema_version: workspace-security-capability/v1
capability_id: network.pcap.read
name: Passive PCAP Analysis
category: network.pcap
status: approved
risk_level: L0
execution_mode: read_only
required_effect: read
allowed_tools:
  - tshark
inputs:
  - pcap_file
network_scope: none
write_scope: evidence_staging_only
approved_operations:
  - summarize_protocols
  - extract_dns_queries
  - extract_flow_tuples
  - follow_stream_metadata
parameter_policy:
  arbitrary_shell: false
  shell_operators: false
  external_paths: false
  max_input_bytes: bounded_by_file_policy
evidence_contract:
  provenance_required: true
  raw_output_retained: true
  normalized_events_required: true
review:
  security_review_required: true
  exact_tool_version_required: true
  digest_required: true
```

A registry entry describes what the capability is allowed to do. It is not an installer script.

## 8. Authority levels

Use four production authority levels.

| Level | Name | Examples | Human approval |
| --- | --- | --- | --- |
| L0 | Observe | read logs, PCAP, metrics, configs | normally no |
| L1 | Analyze | correlate, classify, baseline, summarize | no side-effect approval |
| L2 | Diagnose | bounded ping, traceroute/mtr, SNMP query | policy-dependent |
| L3 | Active Test | scoped nmap/service/vulnerability checks | required by default |

There is deliberately no L4 offensive/exploitation production authority.

### L0 — Observe

Permitted effects are local read/compute only. Examples:

- parse PCAP already provided to WorkSpace;
- parse Cisco/network syslog;
- parse Windows Event Log/Sysmon exports;
- read SNMP/NetFlow data already collected;
- inspect interface statistics;
- inspect stored configuration snapshots.

### L1 — Analyze

No network mutation. Examples:

- correlate DNS -> flow -> authentication -> process evidence;
- construct incident timelines;
- identify baseline deviations;
- deduplicate IDS alerts;
- calculate loss/latency/error-rate trends;
- rank hypotheses with explicit confidence and evidence gaps.

### L2 — Diagnose

Limited active network reads only, against inventory-approved targets. Examples:

- ICMP echo;
- bounded traceroute/mtr;
- SNMP GET against approved devices;
- bounded service reachability checks.

### L3 — Active Test

Explicitly scoped and auditable. Examples:

- Nmap against approved inventory assets;
- selected vulnerability templates under a reviewed policy;
- controlled service/version checks.

L3 requires stronger scope validation, rate limiting, explicit plan visibility and operator approval unless an enterprise policy grants a narrowly predefined recurring authorization.

## 9. Curated-first runbooks

A critical upstream idea is that reviewed commands should beat model-generated commands.

WorkSpace order of preference:

```text
approved deterministic runbook
  > approved parameterized command template
  > deterministic capability-specific generator
  > model proposal constrained to known schema/verbs
  > refuse / ask for operator action
```

Never use:

```text
free-text request -> LLM -> shell string -> execute
```

For a model-assisted parameter proposal, every field must be validated against the selected capability schema before it reaches the execution gateway.

## 10. Plan generation

The model may draft a diagnostic or investigation plan, but the plan is untrusted until validation.

Recommended plan object:

```json
{
  "objective": "diagnose intermittent packet loss",
  "asset_refs": ["asset:..."],
  "steps": [
    {
      "capability_id": "network.health.icmp",
      "operation": "bounded_ping",
      "parameters": {
        "asset_ref": "asset:...",
        "count": 10
      },
      "reason": "measure immediate packet loss"
    }
  ]
}
```

Validation rules:

- every capability ID must exist and be approved;
- target assets must exist and be enabled in enterprise inventory;
- parameters must conform to the capability schema;
- requested effects must not exceed TaskContract authority;
- L2/L3 actions must obey rate/time/resource limits;
- shell operators, redirections, command substitution and arbitrary executable names are rejected;
- the plan must not create network/write authority that the task does not already possess;
- approval state is stored separately from model output.

## 11. Evidence-only analyst contract

This is the most important pattern for cybersecurity analysis.

The analyst model consumes normalized evidence, not uncontrolled raw context wherever possible.

Every material conclusion must be represented as one of:

- **observed** — directly supported by evidence;
- **derived** — deterministically calculated from observed evidence;
- **candidate** — a hypothesis with supporting and contradicting evidence;
- **unknown** — insufficient evidence.

The model must never silently convert a candidate into an observed fact.

Recommended finding object:

```json
{
  "finding_id": "finding:...",
  "kind": "candidate_lateral_movement",
  "status": "candidate",
  "severity": "medium",
  "asset_refs": ["asset:..."],
  "account_refs": ["identity:..."],
  "supporting_evidence_ids": ["ev:..."],
  "contradicting_evidence_ids": [],
  "evidence_gaps": ["missing endpoint process telemetry"],
  "confidence": 0.63,
  "recommended_next_evidence": ["sysmon_process_events"]
}
```

This aligns with the existing `network_skills/intrusion-trace-hunting.json` doctrine: separate observed facts from inferred attack steps and stop when continuity is insufficient.

## 12. Treat all telemetry as untrusted data

Security telemetry may contain attacker-controlled text. DNS names, HTTP headers, filenames, process arguments, log messages, terminal output and packet payloads can carry prompt-injection strings.

Rules:

1. Raw telemetry is never concatenated into system instructions.
2. Tool/log content is wrapped and typed as untrusted evidence.
3. Control characters and invalid encodings are normalized before model use.
4. The model is instructed and mechanically constrained to treat evidence as data only.
5. Evidence cannot grant capabilities, change policy, install skills, alter memory or request network access.
6. Raw evidence IDs/hashes remain available so summaries can be audited.

The protection boundary must be deterministic; prompt wording is defense-in-depth only.

## 13. Evidence normalization

Recommended normalized event envelope:

```json
{
  "event_id": "ev:sha256:...",
  "source_type": "syslog|dns|flow|ids|windows|sysmon|pcap|snmp",
  "collector_id": "collector:...",
  "observed_at": "RFC3339 timestamp",
  "ingested_at": "RFC3339 timestamp",
  "asset_ref": "asset:...",
  "identity_refs": [],
  "network": {
    "src_ref": "ip-hash:...",
    "dst_ref": "ip-hash:...",
    "src_port": 0,
    "dst_port": 0,
    "protocol": "tcp"
  },
  "event_type": "...",
  "facts": {},
  "raw_artifact_ref": "artifact:sha256:...",
  "parser_version": "...",
  "provenance": {}
}
```

Sensitive identity/address representation should follow existing WorkSpace typed-reference and privacy rules. Raw values should not be copied into broad audit metadata when a stable typed/hash reference is sufficient.

## 14. Correlation before narration

LLM reasoning should not replace deterministic correlation that can be expressed as code.

Prefer deterministic correlation for:

- same asset/IP within a bounded window;
- DNS query -> resolved address -> network flow;
- authentication -> process -> outbound connection;
- interface errors -> packet loss -> path change;
- IDS alert -> flow -> host/process context;
- repeated service failures;
- time-window and entity limits;
- graph-edge limits;
- duplicate alert grouping.

The model receives the compact correlated result plus selected supporting evidence. This follows the WorkSpace principle: eliminate work before accelerating it and keep context as working memory rather than storage.

## 15. Initial approved tool set

Do not chase the upstream count of hundreds of tools. Start with the smallest sufficient production set.

### Passive/read-only first

Recommended first-wave integrations:

- `tshark` — PCAP parsing and structured extraction;
- `tcpdump` — controlled capture only when capture authority is explicitly granted;
- `ip` — local interface/route state;
- `ss` — local socket state;
- `ethtool` — interface/link counters where available;
- `journalctl`/structured Linux log readers;
- Windows Event Log parser;
- Sysmon parser;
- Syslog collector/parser;
- SNMP collector/parser;
- NetFlow/IPFIX parser;
- DNS log parser.

### Monitoring engines

Add as separate collector/detection integrations, not generic shell tools:

- Zeek;
- Suricata.

### Active diagnostics

Only through scoped L2/L3 capabilities:

- ping;
- traceroute;
- mtr;
- nmap.

No tool is approved merely because it appears in this document. Each tool still requires capability review, packaging/version pinning, tests and registry admission.

## 16. Continuous monitoring workflow

HackingTool is primarily operator-driven; WorkSpace must add a continuous monitoring plane.

```text
collect
  -> parse
  -> normalize
  -> retain provenance
  -> deterministic correlation
  -> baseline/anomaly checks
  -> create bounded candidate incident
  -> analyst triage
  -> evidence-backed report/recommendation
```

The monitoring plane must not automatically escalate from detection to active testing. A detected anomaly creates evidence and a candidate task; it does not mint L2/L3 authority.

## 17. Interactive analyst workflow

Example request:

`Why did camera VLAN connectivity degrade between 10:00 and 10:20?`

Expected flow:

```text
request
 -> taxonomy router
 -> network.health + network.flow + network.interface
 -> load bounded time-range evidence
 -> deterministic correlation
 -> identify missing evidence
 -> analyst reasoning
 -> output facts / hypotheses / unknowns
 -> propose next evidence
 -> optional L2 diagnostic request
 -> Capability Broker decision
 -> operator approval if required
 -> capture new evidence
 -> re-analysis
```

The analyst should prefer requesting the smallest additional evidence needed to distinguish competing hypotheses.

## 18. Tool discovery and promotion lifecycle

The upstream `/find` concept is valuable only if discovered metadata remains inert.

WorkSpace lifecycle:

```text
candidate discovered
 -> metadata/provenance captured
 -> license review
 -> maintenance/security review
 -> threat/use-case classification
 -> isolated lab evaluation
 -> exact-version pin
 -> SBOM/dependency review
 -> capability schema drafted
 -> test corpus created
 -> security gate
 -> approved registry digest
 -> production admission
```

Discovery must never directly create executable fields in the production registry.

A candidate that fails review remains research metadata only.

## 19. Supply-chain requirements

For every executable third-party capability:

- pin an exact reviewed version or immutable digest;
- record upstream repository and license;
- prefer distribution channels with signatures/provenance;
- generate/store SBOM where practical;
- do not use `curl | bash` installation paths;
- do not allow runtime self-update;
- do not allow a model to choose an unreviewed download URL;
- isolate dependencies where possible;
- treat upstream changes as re-review triggers;
- enterprise deployment must pin the WorkSpace commit as already required by `WORKSPACE_SECURITY_ARCHITECTURE.md`.

## 20. WorkSpace component mapping

| Distilled pattern | WorkSpace target |
| --- | --- |
| closed tags/taxonomy | security taxonomy module |
| declarative catalog | approved `SecurityCapability` registry |
| AI tool recommendation | capability router, schema-constrained |
| curated command examples | reviewed runbooks/templates |
| AI goal planner | bounded diagnostic/investigation plan builder |
| per-step confirmation | Capability Broker + approval policy |
| run log | WorkSpace audit/evidence lineage |
| AI findings summary | evidence-only analyst/triage stage |
| prompt-injection data wrapper | typed untrusted evidence envelope |
| tool discovery | inert candidate registry + promotion gate |
| local Ollama support | existing WorkSpace local model gateway |
| safe fetch/pinning ideas | WorkSpace supply-chain admission policy |

Existing WorkSpace components remain authoritative. This blueprint must integrate with, not bypass:

- `docs/WORKSPACE_SECURITY_ARCHITECTURE.md`;
- `docs/WORKSPACE_DESIGN_PRINCIPLES.md`;
- `docs/CAPABILITY_BROKER.md`;
- `network_skills/intrusion-trace-hunting.json`;
- `network_skills/log-incident-diagnosis.json`;
- `network_skills/host-log-forensics.json`.

## 21. Proposed package layout

A future implementation may use the following layout while preserving current module conventions:

```text
src/three_agent/security/
  taxonomy.py
  capability_schema.py
  capability_registry.py
  router.py
  plan.py
  policy.py
  evidence.py
  correlation.py
  analyst.py
  reporting.py
  collectors/
    syslog.py
    snmp.py
    netflow.py
    dns.py
    windows.py
    sysmon.py
    pcap.py
  integrations/
    zeek.py
    suricata.py
  tools/
    passive.py
    diagnostics.py
```

Data/config candidates:

```text
config/security_capabilities.yaml
config/security_taxonomy.yaml
skills/security/
evaluation/security/
tests/security/
```

This layout is a design target, not permission to bypass existing package/API boundaries.

## 22. Required security invariants

Implementation must fail closed on all of the following:

1. Unknown capability IDs.
2. Capability absent from immutable task authority.
3. Effect mismatch.
4. Asset absent from approved inventory for network actions.
5. Disabled asset.
6. Target outside declared network scope.
7. L2/L3 request above rate/time/entity limits.
8. Arbitrary shell or foreign executable proposal.
9. Unreviewed tool/version/digest.
10. Missing evidence provenance for a material finding.
11. AI finding without supporting evidence IDs.
12. Tool/log content attempting to alter policy or instructions.
13. Candidate tool metadata attempting to become executable.
14. Confidential evidence attempting public egress.
15. Monitoring alert attempting to self-authorize active scanning/remediation.

## 23. Reporting contract

Security reports should separate four sections:

### Confirmed observations

Only evidence-backed facts.

### Derived measurements

Deterministically computed values such as packet loss, latency percentiles, interface error deltas, flow counts or alert frequencies.

### Candidate explanations

Ranked hypotheses with supporting evidence, contradicting evidence and confidence.

### Evidence gaps / next action

The smallest additional evidence or approved diagnostic needed to reduce uncertainty.

No remediation should be presented as already applied unless a separate authorized write/remediation capability actually executed and produced verifiable evidence.

## 24. Test and release gates

### Registry tests

- schema validation;
- unique capability IDs;
- taxonomy membership;
- known effect mapping;
- no forbidden executable/install fields in candidate metadata;
- approved version/digest present for executable tools.

### Authority tests

- unknown capability denied;
- missing TaskContract authority denied;
- effect escalation denied;
- write/network scope escalation denied;
- inventory miss denied;
- disabled asset denied;
- L3 without required approval denied.

### AI boundary tests

- fabricated taxonomy values dropped;
- fabricated tool names cannot execute;
- model-generated shell operators rejected;
- evidence prompt injection cannot change authority;
- unsupported confirmed finding rejected;
- candidate/unknown states preserved;
- no-evidence case returns insufficient evidence rather than fabrication.

### Monitoring tests

- collector provenance retained;
- parser version recorded;
- bounded windows enforced;
- entity/edge limits enforced;
- duplicate events handled deterministically;
- alerts do not create execution authority.

### Supply-chain tests

- exact version/digest check;
- SBOM/provenance check where configured;
- no runtime self-install/self-update path;
- no unapproved network download during confidential operation.

## 25. Evaluation metrics

Add security-specific metrics to the existing WorkSpace measurement doctrine:

- evidence coverage ratio;
- unsupported confirmed finding count — target **0**;
- candidate-to-confirmed promotion accuracy;
- false-positive triage rate;
- evidence retrieval precision;
- correlation precision/recall on held-out cases;
- mean time to bounded diagnosis;
- active-diagnostic invocation rate;
- denied unauthorized-action count;
- tool/version provenance coverage — target **100%** for executable production capabilities;
- analyst report citation/evidence completeness — target **100%** for material findings.

A stronger model does not compensate for failing an authority or evidence gate.

## 26. Delivery roadmap

### v0.1 — Security Analyst foundation

Deliver:

- closed security taxonomy;
- `SecurityCapability` schema;
- approved registry loader;
- capability router;
- evidence-only analyst output schema;
- execution policy adapter to Capability Broker;
- initial read-only PCAP/log capabilities;
- anti-fabrication and authority tests.

Exit criteria:

- no arbitrary executable path;
- zero unsupported confirmed findings in held-out tests;
- candidate catalog entries remain inert;
- L0/L1 workflows operate without shell authority.

### v0.2 — Network diagnostics

Deliver:

- inventory-bound ping/traceroute/mtr/SNMP capabilities;
- rate/time bounds;
- L2 approval policy;
- evidence capture from each diagnostic;
- deterministic diagnostic plan templates.

### v0.3 — Continuous network evidence

Deliver:

- Syslog collector;
- NetFlow/IPFIX parser;
- DNS telemetry parser;
- SNMP metrics ingestion;
- bounded correlation engine;
- incident candidate generation.

### v0.4 — Detection integrations

Deliver:

- Zeek integration;
- Suricata integration;
- alert normalization/deduplication;
- IDS -> flow -> host correlation.

### v0.5 — Enterprise analyst workflow

Deliver:

- investigation workspace;
- evidence timeline;
- hypothesis ranking;
- analyst report;
- approval UX for L2/L3 actions;
- audit/export package.

### v1.0 — Production acceptance

Required:

- independent security review;
- held-out network/incident evaluation suite;
- supply-chain inventory/SBOM coverage;
- resource/load testing;
- failure/recovery testing;
- policy regression suite;
- deployment evidence on representative enterprise network environments;
- documented upgrade/revocation process.

## 27. Definition of done for this blueprint

This architecture is considered successfully implemented only when a normal WorkSpace user can request network/security analysis in plain language and the system:

1. routes the request to a closed approved capability set;
2. uses existing evidence before requesting active collection;
3. distinguishes facts, derived values, hypotheses and unknowns;
4. cites evidence for every material confirmed finding;
5. cannot invent or directly execute arbitrary tools/commands;
6. cannot scan assets outside approved inventory/scope;
7. cannot turn monitoring alerts into autonomous active attacks/remediation;
8. keeps confidential telemetry inside the confidential trust boundary;
9. records enough provenance to reproduce and audit the result;
10. remains useful with local models and deterministic fallbacks.

## 28. Final decision

The HackingTool project is valuable to WorkSpace primarily as an **operator-harness design reference**, not as a runtime dependency.

The integration strategy is therefore:

```text
learn the pattern
  -> rewrite it as WorkSpace-native capability/evidence contracts
  -> reduce the tool set
  -> strengthen deterministic authority
  -> add continuous monitoring/correlation
  -> keep local-first enterprise confidentiality
  -> measure and security-review every promotion
```

This preserves the useful ideas — tool taxonomy, declarative registry, curated-first operation, stepwise planning, evidence-only AI and auditability — while avoiding the offensive surface area and supply-chain complexity of embedding a general hacking toolkit into an enterprise WorkSpace runtime.
