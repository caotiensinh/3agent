# WorkSpace Skill + Tool Self-Evolution Checklist

Status: active implementation checklist.

Baseline branch: `feat/skill-tool-self-evolution-v1-20260908`

Baseline `main`: `1a2206eed88b05b645e1231b106f13648f75aaf1`

Architecture: `docs/WORKSPACE_SKILL_TOOL_SELF_EVOLUTION_ARCHITECTURE.md`

Legend:

- `[x]` complete in current branch or already satisfied by canonical source
- `[~]` in progress
- `[ ]` not started
- `[!]` blocked / requires an explicit dependency or policy decision

## A. Architecture and source convergence

- [x] **A-01** Audit Hermes-style Skill system: progressive disclosure, skill management, supporting resources, self-created skills, scanner/trust model.
- [x] **A-02** Audit Hermes-style Tool system: central registry, toolsets, availability checks, side-effect classification, plugin/MCP discovery.
- [x] **A-03** Audit WorkSpace skill admission: `ApprovedSkillLoader`, registry SHA, provenance, agent scope, instruction-only E2 policy.
- [x] **A-04** Audit WorkSpace adaptive learning: admission, reflection, candidate create/patch/supersede, evaluation, checkpoint, promotion.
- [x] **A-05** Audit WorkSpace authority/evidence primitives and preserve them as canonical.
- [x] **A-06** Publish normative architecture document for controlled Skill + Tool self-evolution.
- [x] **A-07** Define invariant: Skill = knowledge, Tool = capability, Authority = permission, Workflow = orchestration, Evidence = proof.
- [x] **A-08** Define invariant: model may propose candidates and selections but cannot mint runtime authority.

## B. Skill progressive disclosure

- [~] **S-01** Add a compact approved skill catalog for one agent (`list_for_agent`) with no skill body in the index.
- [~] **S-02** Add explicit single-skill on-demand view (`view_for_agent`) that reuses full existing admission/integrity checks.
- [ ] **S-03** Add bounded metadata search/filter by name, description, category/tag, risk/domain where reviewed metadata exists.
- [ ] **S-04** Integrate the catalog into agent/runtime selection so default prompt injection stays minimal.
- [ ] **S-05** Add telemetry for list/view/selected counts without raw prompt/content logging.

Acceptance for S-01/S-02:

- wrong-agent skills are not listed and cannot be viewed;
- disabled/unapproved skills are not listed;
- integrity/review/authority validation still fails closed;
- catalog metadata does not contain skill procedure/body;
- on-demand view cannot bypass `MAX_SKILLS_PER_LOAD` or prompt-size limits;
- existing `load_for_agent` behavior remains backward compatible.

## C. Reviewed supporting references

- [ ] **S-10** Define registry schema for reviewed per-reference metadata (`path`, SHA-256, size, provenance, content class).
- [ ] **S-11** Permit only `references/` under E2 production skills; keep `scripts/` prohibited.
- [ ] **S-12** Reject symlinks, path traversal, unregistered reference files, unexpected directories, and unreviewed bytes.
- [ ] **S-13** Add per-reference and total-reference size limits.
- [ ] **S-14** Add `skill_reference_list` and `skill_reference_view` progressive disclosure surfaces.
- [ ] **S-15** Add security scanning for external URLs, credential paths, secret literals, prompt injection, executable command blocks, and hidden Unicode in references.
- [ ] **S-16** Add reference provenance and version/vendor applicability metadata.
- [ ] **S-17** Add tests proving an altered reference fails SHA/integrity validation.

## D. Automatic CandidateSkill creation

Existing canonical foundation already present:

- [x] **L-01** Deterministic learning admission from evidence-backed completed workflows.
- [x] **L-02** `KnowledgeCandidate(kind="skill")` contract.
- [x] **L-03** Candidate actions include `create`, `patch`, and `supersede`.
- [x] **L-04** Persistent `skill` candidates require verified-success experience.
- [x] **L-05** Isolated/no-tool reflection path exists.
- [x] **L-06** Candidate persistence is parent-side/staging controlled.
- [x] **L-07** Authenticated promotion boundary and checkpoint/state binding exist.

Required convergence work:

- [ ] **L-10** Add canonical `CandidateSkill` view/adapter over `KnowledgeCandidate(kind="skill")`; do not introduce a duplicate learning object.
- [ ] **L-11** Define deterministic mapping from candidate content to proposed `SKILL.md` fields.
- [ ] **L-12** Add agent-facing `skill_candidate_create` operation that can create candidates only from a verified learning source.
- [ ] **L-13** Ensure the candidate operation has zero production registry write authority.
- [ ] **L-14** Add candidate duplicate/similarity detection and replay suppression.
- [ ] **L-15** Add candidate provenance summary and source-evidence coverage metrics.
- [ ] **L-16** Add candidate security scan receipt.

## E. Automatic skill improvement / self-evolution

- [ ] **E-01** Bind `patch` proposals to the exact current production skill SHA/version.
- [ ] **E-02** Bind `supersede` proposals to explicit lineage and rollback target.
- [ ] **E-03** Trigger revision candidates from verified contradictions.
- [ ] **E-04** Trigger revision candidates from repeated verified failure.
- [ ] **E-05** Trigger revision candidates from vendor/version drift.
- [ ] **E-06** Trigger revision candidates when effectiveness drops below policy threshold.
- [ ] **E-07** Compare candidate revision against current production skill on held-out cases.
- [ ] **E-08** Prefer safer/narrower candidates when quality is non-inferior and authority/tool cost is lower.
- [ ] **E-09** Prevent learning from its own generated candidate text unless independently re-grounded in verified evidence.
- [ ] **E-10** Record contradiction/resolution lineage.
- [ ] **E-11** Support quarantine/retirement recommendation without automatic destructive deletion.
- [ ] **E-12** Add rollback to last verified production version.

## F. Skill evaluation, promotion, and production materialization

- [ ] **P-01** Define held-out skill benchmark contract.
- [ ] **P-02** Require deterministic schema/security/provenance checks before evaluation.
- [ ] **P-03** Require regression comparison with previous production version for patch/supersede.
- [ ] **P-04** Define minimum evidence diversity / independent-source policy.
- [ ] **P-05** Reuse authenticated domain reviewer promotion for `network` / `security` skills.
- [ ] **P-06** Add deterministic production materializer from an approved candidate to `skills/<name>/SKILL.md` plus registry metadata.
- [ ] **P-07** Materializer must not accept arbitrary filesystem paths.
- [ ] **P-08** Production SHA/integrity metadata must be generated from exact materialized bytes.
- [ ] **P-09** Promotion must be atomic or checkpoint-recoverable.
- [ ] **P-10** Preserve prior version and rollback lineage.
- [ ] **P-11** No candidate can directly modify `skills/registry.json` outside the promotion/materialization boundary.

## G. Skill effectiveness and autonomous maintenance

- [ ] **M-01** Count skill listed/viewed/selected/associated task events.
- [ ] **M-02** Bind verified outcomes to the exact skill version used.
- [ ] **M-03** Compute success/failure/validator-pass rates.
- [ ] **M-04** Measure tool-call count, latency, and resource delta where telemetry already exists.
- [ ] **M-05** Track contradictions and last verified date.
- [ ] **M-06** Add vendor/version applicability statistics.
- [ ] **M-07** Generate `candidate_for_revision`, `candidate_for_retirement`, and `quarantined` recommendations.
- [ ] **M-08** Add stale-skill review policy.
- [ ] **M-09** Add bounded autonomous maintenance scheduler; recommendations only unless promotion authority is explicitly present.

## H. Generic Tool / Capability Descriptor

- [ ] **T-01** Define runtime-wide immutable `CapabilityDescriptor` view over existing canonical capability/tool sources.
- [ ] **T-02** Support kinds: `tool`, `program`, `gateway`, `agent`, `provider`, `adapter`.
- [ ] **T-03** Define effect taxonomy: `read`, `compute`, `local_read`, `network_read`, `execute_readonly`, `write_staging`, `write`, `network_write`, `device_control`, `credential_use`, `destructive`.
- [ ] **T-04** Unknown/plugin/external effects fail closed to effect-capable/high-risk until reviewed.
- [ ] **T-05** Descriptor may contain required environment variable names but never secret values.
- [ ] **T-06** Descriptor must declare result-size limit and evidence requirement.
- [ ] **T-07** Descriptor must not grant authority.
- [ ] **T-08** Add stable descriptor fingerprint/provenance/version metadata.

## I. Generic Capability Registry

- [ ] **T-10** Add closed built-in registry over reviewed descriptors.
- [ ] **T-11** Reject duplicate capability IDs and unreviewed overrides.
- [ ] **T-12** Add namespaces for adapters/plugins/providers.
- [ ] **T-13** Add immutable registry fingerprint.
- [ ] **T-14** Add compact agent/task capability listing.
- [ ] **T-15** Add exact capability resolve/view operation.
- [ ] **T-16** Preserve domain-specific security registry as an adapter, not a discarded duplicate.

## J. Toolsets and availability

- [ ] **T-20** Add `ToolsetDescriptor` / named capability groups.
- [ ] **T-21** Initial `windows_diagnostics` toolset.
- [ ] **T-22** Initial `linux_diagnostics` toolset.
- [ ] **T-23** Initial `network_diagnostics` toolset.
- [ ] **T-24** Initial `camera_diagnostics` toolset.
- [ ] **T-25** Initial `security_forensics_readonly` toolset.
- [ ] **T-26** Initial `repository_coding` toolset.
- [ ] **T-27** Add platform/profile/task filtering.
- [ ] **T-28** Add bounded availability probes.
- [ ] **T-29** Add TTL cache only when cache identity is correctly scoped.
- [ ] **T-30** Toolset membership never grants capability authority.

## K. Authority-bound invocation and evidence

- [ ] **T-40** Capability selection must resolve descriptor before invocation.
- [ ] **T-41** Every invocation must intersect with canonical `TaskCapabilityAuthority`.
- [ ] **T-42** Apply domain-specific policy gate where required.
- [ ] **T-43** Add adapter invocation contract with no raw model-selected shell command path.
- [ ] **T-44** Bound tool result size and error disclosure.
- [ ] **T-45** Normalize invocation output to runtime `Observation`.
- [ ] **T-46** Bind observation to content-addressed evidence.
- [ ] **T-47** Emit audit-safe capability decision and invocation receipt.
- [ ] **T-48** Preserve revocation/cancellation behavior across long-running adapters.

## L. External / MCP capability compatibility

- [ ] **X-01** Add external capability discovery snapshot format.
- [ ] **X-02** Treat remote descriptions/schemas as untrusted data.
- [ ] **X-03** Quarantine newly discovered tools before runtime exposure.
- [ ] **X-04** Classify effect/risk and require explicit include/exclude selection.
- [ ] **X-05** Disable mutating or unknown external tools by default.
- [ ] **X-06** Separate OAuth/provider identity from WorkSpace authority.
- [ ] **X-07** Keep secret values outside model-visible descriptor data.
- [ ] **X-08** Detect schema/version drift and trigger re-review/quarantine.
- [ ] **X-09** Prevent external capability override of built-ins without explicit reviewed policy.
- [ ] **X-10** Add provenance/audit for installation, enablement, disablement, and reconfiguration.

## M. Domain tool migration

These should be implemented as small capabilities, not one giant diagnostic workflow.

### Windows

- [ ] **D-WIN-01** Event Viewer read/evidence capability.
- [ ] **D-WIN-02** system/hardware inventory.
- [ ] **D-WIN-03** driver/GPU inventory.
- [ ] **D-WIN-04** storage health/read-only metadata.
- [ ] **D-WIN-05** service/process status read.
- [ ] **D-WIN-06** network/interface/status read.
- [ ] **D-WIN-07** crash dump metadata/read-only collector.

### Linux

- [ ] **D-LNX-01** journal read/evidence capability.
- [ ] **D-LNX-02** dmesg/kernel read.
- [ ] **D-LNX-03** PCI/GPU inventory.
- [ ] **D-LNX-04** storage health/read-only metadata.
- [ ] **D-LNX-05** service/process status read.
- [ ] **D-LNX-06** network/interface/status read.

### Network / Camera

- [ ] **D-NET-01** ARP/neighbor evidence read.
- [ ] **D-NET-02** SNMPv3 reviewed read capability.
- [ ] **D-NET-03** fixed passive flow/telemetry adapters.
- [ ] **D-CAM-01** ONVIF discovery/identity capability.
- [ ] **D-CAM-02** RTSP health probe capability.
- [ ] **D-CAM-03** camera identity/vendor/model capability.
- [ ] **D-CAM-04** PoE/status read where supported.
- [ ] **D-CAM-05** vendor-specific reviewed runbook skills + reference packs.

## N. UI / operator experience

- [ ] **U-01** Show compact available skills and why they matched.
- [ ] **U-02** Show selected toolset and effective authorized capability subset.
- [ ] **U-03** Show candidate skill creation/revision status.
- [ ] **U-04** Show evidence/evaluation summary for promotion.
- [ ] **U-05** Show exact production skill version/hash and rollback lineage.
- [ ] **U-06** Show quarantined/retirement recommendations.
- [ ] **U-07** Provide operator approval/rejection with reason codes.
- [ ] **U-08** Never show raw credentials or unnecessary sensitive evidence in browser projections.

## O. CI / security gates

- [ ] **C-01** Skill catalog progressive-disclosure regression tests.
- [ ] **C-02** Reference pack integrity/path/symlink tests.
- [ ] **C-03** Candidate create/patch/supersede contract tests.
- [ ] **C-04** Replay/self-reinforcement resistance tests.
- [ ] **C-05** Held-out evaluation tests.
- [ ] **C-06** Promotion/materialization atomicity tests.
- [ ] **C-07** Generic capability registry duplicate/override tests.
- [ ] **C-08** Authority intersection tests.
- [ ] **C-09** Unknown external tool fail-closed tests.
- [ ] **C-10** MCP schema drift/quarantine tests.
- [ ] **C-11** Tool-result bounding/error-redaction tests.
- [ ] **C-12** Observation/evidence lineage tests.
- [ ] **C-13** Python 3.11 and 3.12 full regression.
- [ ] **C-14** Installer/deployment regression.
- [ ] **C-15** Windows/Linux platform-specific smoke where a runner is available.

## Current execution slice

This branch starts with the smallest safe runtime change that unlocks Hermes-style progressive disclosure without relaxing production trust:

1. [~] S-01 compact approved skill catalog.
2. [~] S-02 on-demand approved skill view.
3. [~] C-01 focused regression tests.
4. [ ] exact-head PR CI.
5. [ ] merge only after exact-head verification.

After that slice is merged, continue with `S-10..S-17` (reviewed references), then `L-10..L-16` (automatic CandidateSkill creation), then the improvement/promotion loop, before starting the generic Tool Registry. This ordering keeps self-learning useful while avoiding a second parallel authority system.
