# WorkSpace Adaptive Self-Improvement Doctrine

Version: 1.0
Status: KNOWLEDGE-ONLY / NOT IMPLEMENTED
Scope: WorkSpace architecture, memory, skills, analyst workflows, validation, curation

## 1. Purpose

WorkSpace needs to become more useful after repeated real work without weakening its enterprise security model. The desired form of self-improvement is **experience-driven behavioral improvement under deterministic control**, not unrestricted self-modification.

The key design principle is:

> Improve knowledge, procedures, evidence handling, and routing first. Keep trusted authority and core security policy outside the learning loop.

This doctrine is inspired by the architectural ideas observed in Hermes Agent: persistent memory, procedural skills, post-task reflection, skill evolution, curation, provenance, and rollback. WorkSpace adapts those ideas to a stricter local-first enterprise security model.

No Hermes source code or prompt text is copied by this document.

## 2. What "learning" means in WorkSpace

WorkSpace must distinguish four different concepts that are often incorrectly grouped under "self-learning".

### 2.1 Persistent factual memory

Small, durable facts that improve future work.

Examples:
- approved project conventions;
- stable environment facts;
- recurring operator preferences;
- known local topology facts when classified and authorized;
- previously validated operational constraints.

Memory answers: **What should I remember?**

### 2.2 Procedural knowledge / skills

Validated instructions for how to perform a class of task.

Examples:
- how to analyze a switch log without changing device state;
- how to correlate authentication failures across approved log sources;
- how to build an incident timeline from evidence;
- how to verify a report before release.

Skills answer: **How should this class of work be done?**

### 2.3 Analytical models and hypotheses

Reusable analytical patterns that remain explicitly probabilistic.

Examples:
- symptoms commonly associated with DNS failure;
- patterns that may indicate link flapping;
- correlation features useful for brute-force detection;
- evidence combinations that raise or lower confidence.

Analytical knowledge answers: **What patterns are worth testing against evidence?**

It must never silently convert a hypothesis into a deterministic security rule.

### 2.4 Model-weight training

Fine-tuning, SFT, RL, adapters, or replacement of model weights.

This is a separate engineering pipeline and is **not part of the default WorkSpace self-improvement loop**. Any future weight-training path requires an explicit dataset, privacy review, evaluation suite, model provenance, rollback, and deployment gate.

## 3. Core learning loop

The canonical loop is:

```text
Task / observation
      |
      v
Experience record
      |
      v
Reflection
      |
      +--> Nothing durable -> discard candidate
      |
      v
Knowledge candidate
      |
      v
Evidence validation
      |
      +--> fail / unresolved -> retain as non-authoritative observation or discard
      |
      v
Promotion gate
      |
      v
Approved memory / skill / analytical playbook
      |
      v
Future reuse
      |
      v
Measured outcome
      |
      +--> improvement -> retain
      +--> drift / regression -> patch, stale, archive, rollback
```

The loop must optimize for **verified task quality**, not for the number of learned entries.

## 4. Authority separation

Learning is not authority.

A learned item can describe a useful procedure, but it cannot grant itself access to capabilities.

The existing WorkSpace hierarchy remains authoritative:

```text
Deterministic security policy
  > operator-approved configuration
  > task/workflow contracts
  > reviewed knowledge and skills
  > model output
  > untrusted files/web content
```

Consequences:

- a learned network skill cannot enable network access;
- a learned security skill cannot change firewall rules;
- a learned script cannot execute merely because the model created it;
- a memory entry cannot override RBAC or a capability contract;
- a learned recommendation cannot bypass validators;
- public research content cannot become trusted instruction by being saved into memory.

## 5. No unattended core self-modification

The background learning path must not have general permission to modify the trusted WorkSpace core.

The future self-improvement worker should be mechanically restricted to operations such as:

- read approved task/evidence summaries;
- read approved knowledge/skill entries;
- create or patch staged knowledge candidates;
- update learning metadata;
- propose consolidation;
- request validation.

It should not possess by default:

- unrestricted shell;
- direct Git push;
- deployment authority;
- package installation;
- production network write access;
- credential access;
- firewall/router/switch configuration authority;
- service restart authority;
- direct mutation of trusted policy or validator code.

Core-code improvement should use a separate development pipeline:

```text
Repeated systemic issue
 -> improvement proposal
 -> isolated developer sandbox
 -> code change
 -> tests
 -> security review
 -> benchmark
 -> human / policy gate
 -> normal Git merge and deployment
```

## 6. Reflection rules

Reflection exists to distill durable lessons, not to narrate every task.

A task is a learning signal when one or more of the following occurred:

- the user/operator corrected a workflow;
- a previously documented procedure was incomplete or wrong;
- a non-trivial working diagnostic sequence was discovered;
- multiple evidence sources revealed a reusable correlation pattern;
- a repeated failure was solved with a verified method;
- a reusable parsing, validation, or evidence-normalization technique was established;
- measured outcomes show a known procedure can be improved.

Do not promote:

- unresolved failures;
- guesses that were never verified;
- transient environment breakage as a permanent rule;
- one-off task narratives;
- raw log dumps;
- credentials or secrets;
- broad negative rules such as "tool X never works" based on a temporary failure;
- conclusions derived only from model confidence;
- remediation steps that were never safely tested and approved.

## 7. Knowledge candidate contract

Future implementation should represent a learning proposal using a deterministic schema similar to:

```text
KnowledgeCandidate
- candidate_id
- domain
- kind: memory | skill | analytical_pattern | reference
- title
- normalized_claim_or_procedure
- source_task_ids[]
- evidence_refs[]
- evidence_hashes[]
- sensitivity_class
- environment_scope
- tool_versions
- parser_versions
- policy_version
- created_at
- proposed_by
- validation_status
- confidence
- contradiction_refs[]
- supersedes
- expires_or_review_after
```

The content is not trusted simply because this schema exists. The schema creates traceability.

## 8. Evidence-first promotion

A candidate should be promoted because evidence supports it, not because a model writes persuasive prose.

Minimum questions:

1. What exact task/evidence produced the lesson?
2. Was the task actually successful?
3. Is the lesson generalizable or environment-specific?
4. Does contradictory evidence exist?
5. Does the proposed knowledge violate a policy or capability boundary?
6. Can the claim be validated deterministically?
7. Does reuse improve verified outcome, cost, latency, or analyst quality?

For procedural improvements, prefer before/after evaluation:

```text
baseline procedure
 vs
candidate procedure
```

Measure where applicable:

- verified success rate;
- first-pass success;
- false-positive / false-negative rate;
- evidence coverage;
- unresolved-claim count;
- token cost;
- model calls;
- latency;
- RAM/VRAM;
- operator correction rate.

## 9. Promotion levels

Recommended lifecycle:

### L0 — Session observation

Ephemeral. Useful only inside the current task.

### L1 — Candidate

Persisted proposal with provenance. Not used as authoritative procedure.

### L2 — Validated local knowledge

Evidence checked; allowed as contextual reference in its defined scope.

### L3 — Approved reusable skill/playbook

May shape future workflows, but still cannot grant capabilities.

### L4 — Enterprise baseline

High-confidence procedure used broadly. Requires explicit review when it affects Network, Security, data movement, compliance, or release decisions.

Promotion must be monotonic through gates. A model cannot self-label a candidate as L4.

## 10. Domain ownership and scope

Every learned item needs a scope.

Examples:

```text
domain=network
scope=read-only-switch-log-analysis
platform=Cisco CBS250 family
```

or:

```text
domain=security
scope=authentication-log-correlation
source_types=syslog, application-auth-log
```

Avoid global rules when the evidence is device-, vendor-, version-, site-, or environment-specific.

## 11. Separate facts from procedures

WorkSpace should not overload one store with everything.

Recommended conceptual separation:

```text
Memory
  small durable facts

Skills
  procedural workflow

References
  detailed domain notes, vendor/version details, examples

Evidence store
  immutable or append-only task evidence and hashes

Analytical patterns
  hypotheses/correlation models with confidence and validation metadata
```

This keeps working context small and prevents raw evidence from becoming permanent prompt baggage.

## 12. Progressive disclosure

Only the smallest relevant knowledge should enter model context.

Recommended retrieval stages:

```text
Level 0: title + domain + short trigger
Level 1: procedure summary
Level 2: exact reference or evidence excerpt
```

Do not load the full knowledge library into every request.

This follows the existing WorkSpace constraint-first rule:

```text
avoid > reuse > precompute > compact > parallelize > accelerate > scale hardware
```

## 13. Curation

Self-improvement without curation becomes knowledge pollution.

A future curator should track:

- last use;
- use count;
- validation date;
- patch history;
- contradiction count;
- successful reuse count;
- failure-after-reuse count;
- version/vendor/environment scope;
- pinned status;
- dependency/reference links.

Recommended lifecycle:

```text
active -> review_due -> stale -> archived
```

Rules:

- archive is recoverable;
- do not automatically hard-delete learned knowledge;
- pinned enterprise procedures cannot be changed by background learning;
- user-owned/manual knowledge remains protected unless explicitly adopted;
- overlapping narrow entries should be consolidated into class-level playbooks;
- support details belong in references, not dozens of nearly identical skills.

## 14. Rollback and audit

Every mutation to promoted knowledge should be auditable.

Record at minimum:

```text
actor
origin
candidate_id
item_id
operation
before_hash
after_hash
source_task_ids
validation_receipt
policy_version
timestamp
```

Rollback must support restoring the prior validated state.

Learning telemetry is useful, but security enforcement must not depend on telemetry being writable. Policy gates should fail closed independently.

## 15. Confidentiality rules for learning

The learning system inherits the WorkSpace confidential/public separation.

### Confidential Core

Learning may use confidential evidence locally, but learned artifacts remain within the authorized confidential store unless explicitly classified otherwise.

### Public Research

Public research cannot read confidential learning stores. Public results imported inward remain untrusted evidence until inspected.

### No raw cross-zone learning transfer

Do not send the following from Confidential Core to Public Research merely to improve a skill:

- raw prompts;
- internal logs;
- IP/MAC inventories;
- credentials;
- customer/company identifiers;
- internal filenames/paths;
- incident evidence;
- chat history.

A public query may contain only separately compiled, policy-authorized public terms.

## 16. Security scanning of learned content

Learned content is a potential persistence channel for prompt injection and malicious instructions.

Before promotion, scan for at least:

- prompt-injection directives;
- attempts to weaken policy;
- credential exfiltration instructions;
- hidden Unicode/control characters;
- unexpected network destinations;
- shell commands outside the declared procedure class;
- persistence or privilege-escalation instructions;
- active content references;
- instructions to bypass approval or logging.

Security scanning supplements authority separation; it does not replace it.

## 17. Default enterprise posture

For WorkSpace, the safe initial posture is:

```text
background reflection: enabled
candidate creation: enabled
candidate validation: enabled
silent promotion of high-risk knowledge: disabled
Network/Security skill mutation without approval: disabled
core source mutation: disabled
capability expansion by learned content: impossible by design
rollback/audit: required before broad promotion
```

The system can become more autonomous later only after measured evidence demonstrates that the promotion gates are reliable.

## 18. Definition of successful self-improvement

A learning feature is successful when future verified tasks become better while authority remains unchanged.

Preferred success equation:

```text
better verified outcome
+ fewer repeated mistakes
+ less operator correction
+ lower token/model/tool cost where possible
+ preserved confidentiality and least privilege
```

Not success:

```text
more memories
more skills
more autonomous actions
more model calls
```

## 19. Implementation boundary for the next phase

This document deliberately stops before runtime implementation.

Before code is added, the next design phase must define and test:

1. deterministic `ExperienceRecord` and `KnowledgeCandidate` schemas;
2. storage/classification rules;
3. read/write approval policy;
4. domain validators;
5. promotion state machine;
6. audit ledger and rollback;
7. curation lifecycle;
8. context-retrieval limits;
9. Network/Security passive-only capability mapping;
10. fixed offline/synthetic evaluation corpus.

Only after those contracts are reviewed should WorkSpace add an automatic learning worker.
