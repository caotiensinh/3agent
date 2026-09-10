# Network, Security, and Analyst Adaptive Learning Knowledge

Version: 1.0
Status: KNOWLEDGE-ONLY / NOT IMPLEMENTED
Domains: Network Monitoring, Security Analysis, Analyst workflows

## 1. Why these domains should receive adaptive learning first

Network, Security, and Analyst work repeatedly encounters the same structural problem:

- large volumes of noisy evidence;
- vendor/version/environment-specific behavior;
- recurring incident patterns;
- high cost of repeating the same diagnosis;
- high cost of false confidence;
- strong need for provenance;
- strong need to distinguish observation, hypothesis, and verified fact.

These domains benefit greatly from experience-driven procedural learning, but they are also the domains where unsafe autonomy can cause the most damage.

Therefore the WorkSpace rule is:

> Learn aggressively from evidence; act conservatively under explicit authority.

The learning system should make Network/Security/Analyst reasoning faster and more accurate without turning learned knowledge into autonomous infrastructure authority.

## 2. Production-network invariant

For real production LANs, the learning design must preserve the existing WorkSpace operational constraint:

**Default production observation is passive or explicitly approved read-only collection.**

Do not treat learning as permission to perform active discovery, load generation, injection, configuration, or remediation.

Explicitly out of scope for autonomous learning/runtime behavior:

- `nmap` or equivalent active scanning;
- `iperf`, speedtest, stress/load generation;
- packet injection;
- ARP spoofing or poisoning;
- exploit/probe traffic;
- switch/router/firewall configuration changes;
- service disruption;
- automatic remediation;
- autonomous shell commands against production devices;
- credential experimentation;
- opening new network paths.

Permitted future evidence sources must be separately authorized and may include, depending on deployment policy:

- existing syslog;
- existing application logs;
- exported device logs/config snapshots handled as data;
- passive packet captures supplied to WorkSpace for offline analysis;
- existing monitoring/telemetry exports;
- approved read-only status/show output;
- approved read-only inventory data;
- synthetic fixtures and lab captures.

The knowledge layer never grants access to these sources. Capability policy does.

## 3. Domain learning pipeline

Recommended common pipeline:

```text
Raw authorized evidence
        |
        v
Deterministic normalize / redact / hash
        |
        v
Evidence facts
        |
        v
Analyst hypotheses
        |
        v
Cross-check / contradiction search
        |
        v
Diagnosis or finding
        |
        v
Post-task reflection
        |
        v
Knowledge candidate
        |
        v
Offline validation / replay
        |
        v
Human or domain gate
        |
        v
Reusable playbook / pattern
```

The critical separation is:

```text
Evidence != hypothesis != conclusion != reusable rule
```

Every layer must remain distinguishable in logs and artifacts.

## 4. Network Monitoring learning

### 4.1 What the Network domain should learn

Good reusable knowledge includes:

- log parsing rules for known device families and versions;
- interpretation of common interface/link state transitions;
- DHCP/DNS/routing symptom correlation patterns;
- safe methods for determining whether evidence is sufficient before escalating;
- methods for building topology from already-authorized inventory/evidence;
- vendor-specific timestamp/timezone normalization;
- methods for correlating switch, router, host, camera, and application logs;
- known benign patterns that reduce repeated false positives;
- known diagnostic dead ends, but only after a verified working alternative exists;
- evidence collection checklists that remain read-only;
- report formats that separate observed facts from likely cause.

### 4.2 What should be memory vs skill vs reference

Example:

```text
Memory:
  Site A uses an approved device naming convention X.

Skill:
  Procedure for analyzing repeated link-up/link-down events.

Reference:
  Cisco CBS250 log message examples and version-specific notes.

Evidence:
  Actual 2026-08-30 device log export and its hash.
```

Do not place a large raw log into persistent skill instructions.

### 4.3 Network pattern candidate example

```text
Candidate: possible physical/link instability

Observed signals:
- repeated interface down/up events;
- no corresponding planned maintenance marker;
- same port involved repeatedly;
- endpoint/application interruption aligns in time.

Counter-signals:
- device reboot explains all ports simultaneously;
- administrative shutdown is recorded;
- timestamp source is inconsistent.

Required conclusion form:
- Observation: ...
- Hypothesis: ...
- Confidence: ...
- Missing evidence: ...
- Safe next read-only check: ...
```

The system should learn the **analysis pattern**, not automatically learn "port X is bad forever".

### 4.4 Baseline learning

WorkSpace may learn normal operational baselines from approved historical telemetry, but baseline knowledge must be scoped by:

- site;
- device group;
- time window;
- software/firmware version;
- workload period;
- collection method.

A baseline becomes stale when major environment/version changes occur.

## 5. Security Analysis learning

### 5.1 What Security should learn

High-value learning targets:

- authentication-failure correlation patterns;
- log-source normalization and field mapping;
- repeated benign-event suppression criteria backed by evidence;
- incident timeline construction;
- credential exposure indicators in local artifacts;
- suspicious process/log sequence patterns from approved evidence;
- mapping between alerts and confirming/contradicting evidence;
- safe triage checklists;
- evidence-preservation procedures;
- failure modes in prior analysis that created false positives or false negatives;
- patterns for identifying prompt injection or malicious instructions inside files/logs/web content.

### 5.2 Security learning is proposal-first

Security is a high-impact domain. Background learning should be able to:

- propose a new detection pattern;
- propose a skill patch;
- propose a new correlation rule;
- propose a false-positive suppression criterion;
- propose a reference update.

It should not autonomously:

- deploy firewall rules;
- block accounts;
- kill processes;
- quarantine hosts;
- alter EDR configuration;
- rotate credentials;
- change ACLs;
- suppress production alerts globally;
- enable network access;
- change trusted security policy.

### 5.3 Detection-rule promotion

A security candidate requires stronger validation than a formatting/workflow skill.

Recommended minimum:

```text
Candidate detection pattern
 -> replay on known-positive fixtures
 -> replay on known-benign fixtures
 -> measure FP/FN
 -> contradiction review
 -> sensitivity / data-classification review
 -> SEC/domain approval
 -> limited-scope release
 -> monitored outcome
 -> broader promotion if evidence supports it
```

A single incident is normally insufficient to create an enterprise-wide detection rule.

### 5.4 False-positive memory

Do not solve false positives by storing broad permanent exclusions such as:

```text
"Ignore source X"
```

Prefer bounded conditions:

```text
"Pattern Y was benign only when condition A+B+C held on version V during approved process P. Revalidate after version/process change."
```

## 6. Analyst learning

The Analyst domain is the bridge between Network/Security evidence and decision-quality output.

### 6.1 Analyst should learn methods, not unsupported conclusions

Good learning targets:

- how to decompose a question into testable hypotheses;
- how to identify missing evidence early;
- how to distinguish correlation from causation;
- how to rank evidence quality;
- how to identify contradictions;
- how to state uncertainty;
- how to produce a concise incident/root-cause report;
- how to avoid repeating already-invalidated hypotheses;
- how to decide when more model reasoning is unnecessary because deterministic evidence is sufficient.

### 6.2 Canonical analyst output model

Future Analyst procedures should prefer a structure such as:

```text
1. Question
2. Known facts
3. Evidence and provenance
4. Hypotheses
5. Evidence for / against each hypothesis
6. Most likely explanation
7. Confidence
8. Unknowns / missing evidence
9. Safe next observation
10. Decision / recommendation boundary
```

This structure itself can become a reusable skill because it improves truthfulness and auditability.

### 6.3 Analyst confidence

Confidence must be tied to evidence coverage, not model certainty.

Recommended conceptual scoring inputs:

- number/quality of independent evidence sources;
- directness of evidence;
- contradiction count;
- time alignment quality;
- completeness of the relevant time window;
- known parser/collection limitations;
- reproducibility on historical fixtures.

Do not expose a numerical confidence score unless its calculation is defined and validated. Otherwise use bounded labels with explicit reasons.

## 7. Cross-domain correlation

The greatest value comes from learning reusable relations between domains.

Example:

```text
Network:
  switch port flap at 10:31:05

System:
  host loses default gateway at 10:31:06

Application:
  camera stream disconnects at 10:31:08

Security:
  no authentication anomaly

Analyst conclusion:
  evidence favors network/link interruption over account compromise
```

The reusable knowledge is the correlation method and evidence ordering — not the specific device/IP from one incident.

## 8. Sensitive facts and generalizable knowledge

Network and Security evidence often contains sensitive identifiers.

Separate:

### Local protected facts

Examples:
- real IP addresses;
- MAC addresses;
- hostnames;
- usernames;
- internal domains;
- switch ports tied to named employees;
- topology details;
- incident identifiers.

These may be retained only where authorized and classified.

### Generalizable procedural knowledge

Examples:
- how to correlate DHCP failure symptoms;
- how to interpret a specific vendor log code;
- how to verify a link-flap hypothesis;
- how to preserve evidence provenance.

Generalizable knowledge should avoid unnecessary protected identifiers.

## 9. Required provenance for domain knowledge

Every promoted Network/Security/Analyst item should be traceable to evidence.

Recommended metadata:

```text
item_id
domain
scope
source_task_ids
evidence_hashes
source_types
device_vendor_family
firmware_or_software_versions
time_window
collection_mode
parser_version
policy_version
validated_against
false_positive_result
false_negative_result
last_validated_at
owner
reviewer
status
```

For confidential evidence, do not put raw content into the audit ledger. Store references/hashes and approved minimal metadata.

## 10. Read-before-write learning rule

Before a background learner patches an existing Network/Security/Analyst skill, it must load the current authoritative version of that skill in the same review context.

Purpose:

- prevent patching stale/inferred content;
- preserve concurrent/manual corrections;
- force the model to reason from the exact current procedure;
- make diffs reviewable.

A failed read-before-write gate should result in one explicit reload/retry, not an infinite loop.

## 11. Protect manually curated and enterprise-pinned knowledge

Three ownership classes are recommended:

```text
system/bundled
user/team-owned
learner-managed
```

Background curation should manage only `learner-managed` content unless an operator explicitly adopts another item.

Pinned Network/Security procedures are immutable to unattended learning.

Examples worth pinning:

- incident evidence-preservation rules;
- approved production read-only constraints;
- credential handling;
- confidentiality boundaries;
- escalation contacts/process;
- approved device-access methods;
- release/security acceptance criteria.

## 12. Curator rules for these domains

A domain curator should detect:

- duplicated device/vendor notes;
- obsolete version-specific knowledge;
- patterns contradicted by new evidence;
- overly broad false-positive suppressions;
- skills that have not produced successful reuse;
- narrow one-incident skills that should become reference entries;
- related Network/Security/Analyst procedures that should be consolidated.

The curator may propose or stage changes. It must not silently remove pinned/enterprise knowledge.

Archive, do not hard-delete, by default.

## 13. Contradiction handling

New evidence can invalidate old knowledge.

Recommended behavior:

```text
new evidence contradicts active knowledge
 -> mark contradiction
 -> reduce promotion confidence
 -> stop automatic propagation
 -> schedule revalidation
 -> retain both evidence trails
 -> patch or supersede only after review
```

Do not overwrite history to make the newest conclusion appear always correct.

## 14. Learning from failures

A failure is useful only when the final lesson is validated.

Bad learning:

```text
Tried A -> failed
Tried B -> failed
Tried C -> failed
Therefore save A/B/C as troubleshooting procedure
```

Good learning:

```text
A/B/C failed
D succeeded and was verified
Save:
- triggering conditions;
- verified D procedure;
- why A/B/C are not recommended in this specific scope, only if evidence supports that claim.
```

If no method succeeded, keep the issue unresolved; do not manufacture a skill.

## 15. Offline/synthetic-first validation

Before applying adaptive learning to real LAN acceptance, build a fixed offline corpus.

Minimum categories should include:

### Network fixtures

- normal interface state;
- link flap;
- DHCP failure;
- DNS failure;
- gateway/routing symptoms;
- device reboot vs isolated port event;
- timestamp/timezone mismatch;
- camera/RTSP interruption correlated with network events.

### Security fixtures

- normal login failures;
- repeated brute-force-like attempts;
- expired credential cases;
- benign service-account noise;
- suspicious credential strings in logs/files;
- prompt-injection text embedded inside untrusted evidence;
- conflicting alerts across sources.

### Analyst fixtures

- insufficient evidence;
- contradictory evidence;
- misleading temporal correlation;
- complete root-cause case;
- case where the correct result is "unknown".

Every learning change should replay against this corpus before high-risk promotion.

## 16. Domain metrics

### Network

- root-cause accuracy on labeled fixtures;
- evidence coverage;
- incorrect escalation rate;
- repeated-diagnosis reduction;
- time/model-call reduction;
- percentage of findings that preserve passive/read-only boundaries.

### Security

- false-positive rate;
- false-negative rate;
- unsupported finding rate;
- contradiction detection rate;
- percentage of high-impact changes correctly held for human review.

### Analyst

- fact/hypothesis separation accuracy;
- citation/evidence coverage;
- unsupported conclusion count;
- correction rate;
- ability to return "insufficient evidence" when appropriate.

## 17. Suggested future components

This document does not implement them, but the eventual architecture can be decomposed into small deterministic components:

```text
ExperienceRecorder
ReflectionPlanner
KnowledgeCandidateStore
DomainClassifier
NetworkKnowledgeValidator
SecurityKnowledgeValidator
AnalystKnowledgeValidator
PromotionGate
KnowledgeRetriever
UsageTracker
Curator
KnowledgeLedger
RollbackManager
```

The model may propose content. The deterministic control plane owns transitions and authorization.

## 18. Example future lifecycle: Network incident

```text
1. Existing syslog + offline packet evidence are ingested.
2. Analyst identifies a verified recurring link-flap diagnosis workflow.
3. Reflection creates a candidate procedure.
4. Candidate contains source task IDs and evidence hashes.
5. Network validator replays the procedure against fixed fixtures.
6. Security validator confirms no active/disruptive step was introduced.
7. Human reviewer approves the procedure as a reusable Network skill.
8. Future tasks retrieve only the short skill summary first.
9. Detailed vendor reference loads only when relevant.
10. Reuse outcome is measured.
11. If the procedure later regresses, curator marks review_due and rollback remains available.
```

## 19. Example future lifecycle: Security false positive

```text
1. Repeated alert is investigated.
2. Evidence proves a narrowly defined benign condition.
3. Learner proposes a scoped suppression/triage pattern.
4. Replay runs against benign and malicious fixtures.
5. A broad suppression that hides malicious fixtures fails validation.
6. A narrower condition passes.
7. SEC/domain reviewer approves it as analyst guidance.
8. Production enforcement remains unchanged unless separately implemented through the normal security-control process.
```

## 20. Non-negotiable acceptance rules before implementation

Adaptive learning for these domains is not ready for production until all of the following exist:

- fixed candidate schema;
- explicit ownership/provenance;
- offline/synthetic test corpus;
- deterministic promotion state machine;
- high-risk human/domain gate;
- audit ledger;
- rollback;
- contradiction handling;
- knowledge scope/versioning;
- context-size limits;
- prompt-injection scanning;
- production passive/read-only enforcement outside the model;
- evidence that learned procedures improve verified outcomes without weakening security boundaries.

Until then, these documents are architectural knowledge only.
