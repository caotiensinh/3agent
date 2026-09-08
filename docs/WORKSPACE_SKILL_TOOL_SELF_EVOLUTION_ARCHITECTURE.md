# WorkSpace Skill + Tool Self-Evolution Architecture

Status: normative implementation plan for controlled enterprise self-learning.

## Baseline

- Repository: `caotiensinh/3agent`
- Audited `main`: `1a2206eed88b05b645e1231b106f13648f75aaf1`
- Comparative reference: `NousResearch/hermes-agent` tool/skill architecture, studied as an open-source design input rather than copied as a runtime trust model.
- Existing WorkSpace canonical primitives remain authoritative. This document extends them; it does not create a parallel security, learning, evidence, or execution authority stack.

## Goal

WorkSpace should gain the useful adaptive behavior of a modern agent runtime:

1. discover relevant skills and tools without loading the entire catalog;
2. learn from verified completed work;
3. create new skill candidates automatically;
4. improve, patch, supersede, merge, retire, and recover skills over time;
5. measure whether learned skills actually improve outcomes;
6. expose only the minimum relevant toolset for each task;
7. add external capabilities through a controlled adapter/quarantine path;
8. preserve enterprise least privilege, provenance, evidence, review, rollback, and audit.

The target is **controlled self-evolution**, not unrestricted self-modification.

## Core invariants

### Skill, tool, authority, and workflow are different objects

- **Skill** = procedural knowledge: how to reason about or perform a class of task.
- **Tool / capability** = a callable operation exposed by the runtime.
- **Authority** = permission to call a capability against a bounded resource with a bounded effect.
- **Workflow / execution plan** = ordering, dependency, retry, aggregation, and validation of work.
- **Evidence** = immutable or content-addressed observations proving what happened.

A skill may recommend a tool. It never grants the right to call the tool.

### The model may propose; the runtime decides

The model may propose:

- a skill to load;
- a candidate skill;
- a revision to an existing skill;
- a toolset or capability route;
- a workflow step;
- an interpretation of evidence.

The model may not mint:

- filesystem scope;
- network scope;
- credential scope;
- device scope;
- approval state;
- promotion authority;
- production registry membership.

### Child authority never exceeds parent authority

Any delegated agent, worker, or execution node must use `TaskCapabilityAuthority` or its canonical successor and preserve the existing `child <= parent` invariant.

### Self-learning must be evidence-bound

No candidate skill may be created from an unverified conversation alone. Production learning starts from the existing deterministic learning admission boundary and evidence-backed completed work.

### No self-reinforcement by replay

Repeated observation of the same source identity must not create artificial confidence. Candidate identity, evidence hashes, task lineage, and evaluation sets must prevent replay from being counted as independent corroboration.

## Existing WorkSpace primitives to keep

The following already provide most of the enterprise control plane and must remain canonical:

- `TaskContract` / `TaskContractCompiler`
- `TaskContext`
- `TaskCapabilityAuthority`
- capability revocation and monitoring policy gates
- `ApprovedSkillLoader`
- `VerifiedLearningSourceEnvelope`
- `ExperienceRecord`
- `KnowledgeCandidate`
- adaptive-learning reflection, curation, revision, evaluation, effectiveness, checkpoint, and promotion modules
- validator ledger and evidence/provenance modules
- immutable checkpoint and audit patterns

The implementation strategy is:

`existing canonical primitive -> normalize/extend -> bind at runtime boundary -> regression tests -> CI evidence`

## Lessons adopted from Hermes-style skill systems

WorkSpace should adopt the following behavior patterns:

- compact skill index;
- progressive disclosure (`list -> view -> reviewed reference`);
- categories/tags and task-relevance metadata;
- skill usage telemetry;
- agent/profile/platform filtering;
- a managed skill-creation interface;
- skill revision after new verified experience;
- discoverable tool registry;
- named toolsets;
- dynamic availability checks;
- adapter/plugin namespaces;
- external capability discovery with explicit include/exclude selection;
- bounded tool-result sizes;
- explicit side-effect classification.

WorkSpace must not copy permissive trust assumptions. The same feature can exist with stronger controls.

## Target architecture

```text
User Request
    |
    v
TaskContext + TaskContract
    |
    v
Intent / Capability Routing
    |
    +--------------------------+
    |                          |
    v                          v
Skill Catalog             Capability Catalog
(index/search/view)        (tools/toolsets/adapters)
    |                          |
    +-------------+------------+
                  |
                  v
             ExecutionPlan
                  |
                  v
          TaskCapabilityAuthority
                  |
                  v
             Capability Adapter
                  |
                  v
              Observation
                  |
                  v
                Evidence
                  |
                  v
               Validator
                  |
                  v
             Audit Receipt
                  |
                  v
       Verified Learning Admission
                  |
                  v
              Experience
                  |
                  v
          CandidateSkill / Revision
                  |
                  v
       Evaluation + Security Review
                  |
                  v
       Approved/Enterprise Promotion
                  |
                  v
           Production Skill Catalog
```

## Skill architecture

### 1. Progressive disclosure

Production skills must no longer require all useful knowledge to be injected into every model call.

Target surfaces:

- `skill_list(agent_id, filters...)` -> compact metadata only;
- `skill_view(agent_id, skill_id)` -> reviewed main procedure;
- `skill_reference_view(agent_id, skill_id, reference_id)` -> one reviewed supporting reference;
- `skill_search(...)` -> bounded search over metadata, not arbitrary filesystem discovery.

Every view revalidates approval, agent scope, integrity, and repository bounds.

### 2. Production skill package

Target reviewed package:

```text
skills/<skill-id>/
  SKILL.md
  references/
    <reference>.md
```

Production E2 rules:

- `SKILL.md` remains compact and procedural;
- `references/` is optional, read-only, individually hashed, size-bounded, and provenance-bound;
- no symlinks;
- no executable scripts in E2 production skills;
- no authority-bearing frontmatter;
- no raw credentials or secret literals;
- no external runtime URL that bypasses approved gateways;
- references are loaded only on demand.

Templates/assets may be introduced only under a later reviewed tier. Executable skill scripts remain prohibited unless a separate capability adapter and authority policy is created.

### 3. CandidateSkill lifecycle

`KnowledgeCandidate(kind="skill")` is the canonical base for a runtime `CandidateSkill` view. Do not add a second independent learning object if an adapter/view can represent the required semantics.

Lifecycle:

```text
verified experience
    -> candidate:create
    -> candidate validation
    -> held-out evaluation
    -> validated
    -> security/provenance review
    -> approved
    -> optional enterprise review
    -> enterprise
```

Improvement lifecycle:

```text
new verified experience
    -> effectiveness/contradiction check
    -> candidate:patch or candidate:supersede
    -> compare old vs candidate on held-out cases
    -> promote only if quality/safety gates pass
    -> retain rollback lineage
```

### 4. Automatic skill creation

The agent may automatically create a **candidate**, not a production skill.

Automatic candidate creation requires:

- exact `VerifiedLearningSourceEnvelope`;
- verified-success evidence for persistent `skill` candidates;
- domain binding;
- bounded reflection packet;
- no capability grants in the reflection input;
- isolated/no-tool reflection worker;
- deterministic parent-side construction;
- staging through the authenticated learning store.

This reuses the current adaptive-learning admission/reflection architecture.

### 5. Automatic skill improvement

WorkSpace should automatically consider revision when one or more of these conditions are met:

- repeated verified failure under a skill;
- new verified success that contradicts an existing procedure;
- vendor/version drift;
- effectiveness score falls below threshold;
- a narrower procedure beats a broad procedure on held-out cases;
- a safer procedure preserves quality while reducing authority/tool use;
- a skill is repeatedly loaded but not useful;
- a skill is stale beyond a configured review horizon.

The revision worker proposes only content changes. It cannot alter tool/network/write/credential authority.

### 6. Self-evolution safety gates

No direct `candidate -> production` transition.

Required gates should include, according to risk/tier:

- schema validation;
- prompt-injection/content scan;
- provenance completeness;
- secret/credential scan;
- authority metadata scan;
- duplicate/replay detection;
- held-out evaluation;
- regression evaluation against prior production version;
- evidence coverage threshold;
- domain review for network/security;
- authenticated human or enterprise promotion ceremony;
- production SHA/integrity registration;
- checkpoint/journal update;
- rollback linkage.

### 7. Skill effectiveness and decay

Each production skill should accumulate audit-safe counters such as:

- selected count;
- viewed count;
- execution association count;
- verified-success count;
- verified-failure count;
- abstention/no-route count;
- validator pass rate;
- tool-call reduction/increase;
- latency/resource delta;
- contradiction count;
- last verified date;
- applicable vendor/version distribution.

Raw sensitive task content is not required for these metrics.

A skill can be automatically marked `candidate_for_revision`, `candidate_for_retirement`, or `quarantined`, but production removal still follows policy.

## Tool / capability architecture

### 1. Generic CapabilityDescriptor

WorkSpace needs one runtime descriptor view over existing tools, programs, gateways, specialist agents, and approved external adapters.

Minimum fields:

- `capability_id`
- `kind` (`tool`, `program`, `gateway`, `agent`, `provider`, `adapter`)
- `name`
- `description`
- `taxonomy`
- `effect`
- `risk_class`
- `platforms`
- `handler_id`
- `evidence_required`
- `availability_probe_id`
- `required_env_names` (names only, never secret values)
- `credential_class` (if applicable)
- `network_behavior`
- `write_behavior`
- `result_size_limit`
- `provenance`
- `version`
- `status`

The descriptor describes a capability. It does not authorize it.

### 2. Generic CapabilityRegistry

The registry should:

- register reviewed built-ins;
- reject duplicate IDs;
- expose immutable descriptors;
- support namespaces;
- resolve toolsets;
- perform bounded availability checks;
- separate discovery from authority;
- fail closed for unknown/plugin/external effects;
- fingerprint the effective registry for audit.

Existing security/monitoring registries remain domain adapters until convergence is complete.

### 3. Toolsets

Toolsets are named capability groups used to reduce context and runtime exposure.

Initial target toolsets:

- `windows_diagnostics`
- `linux_diagnostics`
- `network_diagnostics`
- `camera_diagnostics`
- `security_forensics_readonly`
- `repository_coding`
- `document_analysis`
- `research_public`

A toolset is a selection convenience, not an authority grant. The final callable subset is always intersected with task authority.

### 4. Effect classification

At minimum:

- `read`
- `compute`
- `local_read`
- `network_read`
- `execute_readonly`
- `write_staging`
- `write`
- `network_write`
- `device_control`
- `credential_use`
- `destructive`

Unknown external/plugin/MCP capabilities are treated as effect-capable/high-risk until reviewed.

### 5. Availability checks

Availability checks may inspect only bounded local/runtime state required to decide whether a capability can be advertised. They must not silently perform the capability itself.

Examples:

- operating system matches;
- command/package exists;
- local service socket is reachable;
- required device interface exists;
- configured credential reference exists (without reading secret value);
- approved adapter is enabled.

Results may be TTL-cached, but scope/profile identity must be part of any cache key where availability is profile-specific.

### 6. Capability invocation

Target flow:

```text
model/tool selection
    -> descriptor resolve
    -> TaskCapabilityAuthority.require(...)
    -> optional domain policy gate
    -> adapter invocation
    -> bounded result
    -> normalized observation
    -> evidence record
    -> validator/audit
```

No `model -> shell/network/device` shortcut is admitted.

## External tool / MCP compatibility

WorkSpace should support MCP or similar external capability protocols, but through quarantine and admission:

```text
external server
    -> discover schemas
    -> quarantine snapshot
    -> classify effects
    -> operator/include-exclude selection
    -> provenance + endpoint/transport review
    -> capability descriptors
    -> authority binding
    -> runtime exposure
```

Rules:

- discovery never equals authorization;
- remote tool descriptions are untrusted data;
- mutating/unknown tools are disabled by default;
- secrets are stored outside prompts and descriptors;
- OAuth identity does not itself grant WorkSpace authority;
- external tools cannot override built-ins without explicit reviewed policy;
- configuration changes are audited;
- tool schema/version changes trigger re-review or quarantine according to policy.

## Enterprise self-learning loop

The complete desired loop is:

```text
1. Task executes under bounded authority.
2. Runtime records observations/evidence.
3. Validators establish verified outcome.
4. Learning admission decides whether the task can teach the system.
5. Reflection extracts a bounded experience/candidate proposal.
6. Candidate is staged, never made production directly.
7. Similar experiences are deduplicated and contradictions are recorded.
8. Candidate/revision is evaluated against held-out evidence.
9. Security/provenance/policy gates run.
10. Required reviewer promotion occurs.
11. Production catalog version advances atomically with integrity metadata.
12. Runtime uses the skill through progressive disclosure.
13. Effectiveness telemetry measures real benefit.
14. Weak/stale/contradicted skills re-enter revision or retirement review.
```

This creates genuine improvement while keeping runtime authority outside model control.

## Initial implementation order

1. Progressive approved skill catalog (`list/view`) without weakening current skill admission.
2. Reviewed skill reference packs.
3. Canonical `CandidateSkill` adapter/view over `KnowledgeCandidate(kind="skill")`.
4. Automatic skill candidate creation API backed by existing reflection/staging.
5. Automatic patch/supersede improvement API backed by current revision pipeline.
6. Held-out skill evaluation and effectiveness feedback.
7. Controlled production skill materialization/registry promotion.
8. Generic `CapabilityDescriptor` and `CapabilityRegistry`.
9. Toolsets and availability filtering.
10. Authority-bound capability invocation and normalized evidence receipts.
11. External/MCP quarantine and admission.
12. UX/API surfaces for discovery, learning status, approval, rollback, and audit.

Detailed status is tracked in `docs/WORKSPACE_SKILL_TOOL_SELF_EVOLUTION_CHECKLIST.md`.

## Non-goals

This architecture does not authorize:

- unrestricted production self-modification;
- self-granted tool/network/write/credential permissions;
- arbitrary downloaded skill scripts;
- direct execution of commands embedded in skill text;
- bypass of human/domain review for high-risk promotion;
- auto-installation of unknown MCP/plugin tools into an enterprise production profile;
- replacement of existing domain-specific forensic evidence semantics.

## Success definition

WorkSpace reaches the intended target when it can safely demonstrate this end-to-end behavior:

> A verified task teaches the system a new or improved skill; the candidate is evaluated and promoted through enterprise gates; a later relevant task discovers and loads only that skill and the minimum authorized toolset; execution remains bounded by `TaskCapabilityAuthority`; the result produces evidence; and effectiveness telemetry can prove whether the learned skill improved the outcome without granting the model new authority.
