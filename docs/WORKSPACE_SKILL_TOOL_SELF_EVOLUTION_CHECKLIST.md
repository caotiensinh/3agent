# WorkSpace Skill + Tool Self-Evolution Checklist

Status: active implementation checklist, reconciled against live `main` on 2026-09-08.

Current verified `main`: `43a26e0b833e313ceef361d8d00640a408f142f5`

Architecture: `docs/WORKSPACE_SKILL_TOOL_SELF_EVOLUTION_ARCHITECTURE.md`

## Reconciliation checkpoint

The older version of this checklist lagged behind merged implementation. The status below now reflects the canonical source present on the verified `main` above.

Merged lifecycle milestones used for this reconciliation:

- PR #371 — approved skill catalog progressive disclosure;
- PR #379 — CandidateSkill approval queue / authenticated human review boundary;
- PR #382 — Adaptive Micro-Tool Registry v0.2;
- PR #383 — runtime P0 stateful security convergence gate;
- PR #385 — approved learned-skill production materialization;
- PR #388 — exact runtime reuse of materialized learned skills;
- PR #389 — immutable production supersession and operator rollback mirror;
- PR #390 — bounded recommendation-only maintenance advisor over Phase 4H/4I;
- PR #391 — self-evolution checklist reconciliation against merged canonical state;
- PR #392 — bounded metadata-only approved skill catalog search/filter;
- PR #393 — metadata-only list/view/selected catalog telemetry on the existing activity ledger;
- PR #396 — deterministic recommendation-only stale active-skill review policy.

Important interpretation rules:

- `[x]` means the exact requirement is satisfied by canonical source and merged verification evidence.
- `[~]` means a meaningful canonical portion exists, but the wording of the requirement is broader than what is currently proven.
- `[ ]` means the remaining requirement has not yet been proven complete.
- No item is marked complete merely because an adjacent subsystem exists.

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

- [x] **S-01** Add a compact approved skill catalog for one agent (`list_for_agent`) with no skill body in the index. Merged via PR #371.
- [x] **S-02** Add explicit single-skill on-demand view (`view_for_agent`) that reuses full existing admission/integrity checks. Merged via PR #371.
- [x] **S-03** Add bounded metadata search/filter by name, description, category/tag, risk/domain where reviewed metadata exists. Merged via PR #392; search is metadata-only and canonical registry audit remains mandatory before filtering.
- [x] **S-04** Integrate the catalog into agent/runtime selection so default prompt injection stays minimal. `adaptive_learning_skill_reuse.py` and `agents/research_compiled.py` use adaptive retrieval first and load at most the exact materialized production skill selected for synthesis.
- [x] **S-05** Add telemetry for list/view/selected counts without raw prompt/content logging. Merged via PR #393; list/search record count plus deterministic identity-set digest, while view/selected record exact production name/SHA only.

Acceptance preserved:

- wrong-agent skills are not listed and cannot be viewed;
- disabled/unapproved skills are not listed;
- integrity/review/authority validation still fails closed;
- catalog metadata does not contain skill procedure/body;
- on-demand view cannot bypass `MAX_SKILLS_PER_LOAD` or prompt-size limits;
- existing `load_for_agent` behavior remains backward compatible.

## C. Reviewed supporting references

- [x] **S-10** Define registry schema for reviewed per-reference metadata (`path`, SHA-256, size, provenance, content class).
- [x] **S-11** Permit only `references/` under E2 production skills; keep `scripts/` prohibited.
- [x] **S-12** Reject symlinks, path traversal, unregistered reference files, unexpected directories, and unreviewed bytes.
- [x] **S-13** Add per-reference and total-reference size limits.
- [x] **S-14** Add `skill_reference_list` and `skill_reference_view` progressive disclosure surfaces through canonical approved skill catalog/loader reference APIs.
- [x] **S-15** Add security scanning for external URLs, credential paths, secret literals, prompt injection, executable command blocks, and hidden Unicode in references.
- [x] **S-16** Add reference provenance and version/vendor applicability metadata.
- [x] **S-17** Add tests proving an altered reference fails SHA/integrity validation.

Current E2 reference policy:

- maximum 8 references per production skill;
- maximum 16 KiB canonical UTF-8 per reference;
- maximum 64 KiB total canonical UTF-8 reference content per skill;
- only registered `references/*.md` regular files are admitted;
- every reference is pinned by canonical SHA-256, canonical size, provenance and content class;
- optional vendor family/version applicability is model-visible metadata;
- `scripts/`, symlinks, traversal, extra files, unregistered directories and executable authority remain denied.

## D. Automatic CandidateSkill creation

Existing canonical foundation:

- [x] **L-01** Deterministic learning admission from evidence-backed completed workflows.
- [x] **L-02** `KnowledgeCandidate(kind="skill")` contract.
- [x] **L-03** Candidate actions include `create`, `patch`, and `supersede`.
- [x] **L-04** Persistent `skill` candidates require verified-success experience.
- [x] **L-05** Isolated/no-tool reflection path exists.
- [x] **L-06** Candidate persistence is parent-side/staging controlled.
- [x] **L-07** Authenticated promotion boundary and checkpoint/state binding exist.

Required convergence work:

- [x] **L-10** Add canonical `CandidateSkill` view/adapter over `KnowledgeCandidate(kind="skill")`; do not introduce a duplicate learning object.
- [x] **L-11** Define deterministic mapping from candidate content to proposed `SKILL.md` fields.
- [~] **L-12** Add agent-facing `skill_candidate_create` operation that can create candidates only from a verified learning source. The verified reflection/staging service exists; a distinct generic agent operation surface is not yet proven complete.
- [x] **L-13** Ensure the candidate operation has zero production registry write authority.
- [~] **L-14** Add candidate duplicate/similarity detection and replay suppression. Immutable candidate identity and several receipt/replay barriers exist; semantic similarity detection is not yet complete.
- [x] **L-15** Add candidate provenance summary and source-evidence coverage metrics.
- [x] **L-16** Add candidate security scan receipt.

## E. Automatic skill improvement / self-evolution

- [x] **E-01** Bind `patch` proposals to the exact current production skill SHA/version. Phase 4J/4K bind exact base knowledge; PR #389 binds exact production lineage before publication.
- [x] **E-02** Bind `supersede` proposals to explicit lineage and rollback target. PR #389 preserves immutable prior production versions and exact rollback lineage.
- [ ] **E-03** Trigger revision candidates from verified contradictions.
- [x] **E-04** Trigger revision candidates from repeated verified failure. Phase 4H thresholds -> Phase 4I review -> Phase 4J revision path are present; PR #390 closes bounded recommendation orchestration.
- [ ] **E-05** Trigger revision candidates from vendor/version drift.
- [x] **E-06** Trigger revision candidates when effectiveness drops below policy threshold.
- [~] **E-07** Compare candidate revision against current production skill on held-out cases. Phase 4K compares exact base/revised versions and post-activation effectiveness, but a dedicated held-out benchmark remains open.
- [ ] **E-08** Prefer safer/narrower candidates when quality is non-inferior and authority/tool cost is lower.
- [~] **E-09** Prevent learning from its own generated candidate text unless independently re-grounded in verified evidence. Verified-success/evidence lineage is mandatory, but a dedicated self-reinforcement resistance gate remains to be completed.
- [~] **E-10** Record contradiction/resolution lineage. Canonical contradiction contracts exist; complete maintenance-driven resolution lineage remains open.
- [~] **E-11** Support quarantine/retirement recommendation without automatic destructive deletion. PR #390 emits revision-or-retirement review recommendations; explicit quarantine state is not yet implemented.
- [x] **E-12** Add rollback to last verified production version. Phase 4K keeps rollback operator-only and PR #389 mirrors completed learning rollback into immutable production state.

## F. Skill evaluation, promotion, and production materialization

- [ ] **P-01** Define held-out skill benchmark contract.
- [x] **P-02** Require deterministic schema/security/provenance checks before evaluation. Phase 4K performs deterministic exact-lineage and domain/safety evaluation.
- [~] **P-03** Require regression comparison with previous production version for patch/supersede. Exact base/revised comparison exists; dedicated held-out regression policy remains open.
- [ ] **P-04** Define minimum evidence diversity / independent-source policy.
- [x] **P-05** Reuse authenticated domain reviewer promotion for `network` / `security` skills.
- [x] **P-06** Add deterministic production materializer from an approved candidate to `skills/<name>/SKILL.md` plus registry metadata. Merged via PR #385.
- [x] **P-07** Materializer must not accept arbitrary filesystem paths.
- [x] **P-08** Production SHA/integrity metadata must be generated from exact materialized bytes.
- [x] **P-09** Promotion/materialization must be atomic or checkpoint-recoverable. Canonical checkpoint mutation plus atomic registry commit/rollback behavior is present.
- [x] **P-10** Preserve prior version and rollback lineage. Merged via PR #389.
- [x] **P-11** No candidate can directly modify `skills/registry.json` outside the promotion/materialization/supersession boundary.

## G. Skill effectiveness and autonomous maintenance

- [x] **M-01** Count skill listed/viewed/selected/associated task events. PR #393 records bounded list/search/view/selected catalog observations on `TaskStore.activities`; exact associated-task reuse remains bound by `LearningReuseReceipt`.
- [x] **M-02** Bind verified outcomes to the exact skill version used. `LearningReuseReceipt` binds task + item + exact knowledge SHA before synthesis, and Phase 4H joins authoritative task/validator outcome.
- [~] **M-03** Compute success/failure/validator-pass rates. Exact success/failure/waiting/unverified counts and advisory thresholds exist; explicit normalized rate projections remain open.
- [ ] **M-04** Measure tool-call count, latency, and resource delta where telemetry already exists.
- [~] **M-05** Track contradictions and last verified date. Contradiction contracts exist; last-verified maintenance projection is not complete.
- [ ] **M-06** Add vendor/version applicability statistics.
- [~] **M-07** Generate `candidate_for_revision`, `candidate_for_retirement`, and `quarantined` recommendations. Revision/retirement review recommendations exist via PR #390; quarantine recommendation remains open.
- [x] **M-08** Add stale-skill review policy. PR #396 adds a deterministic exact-version policy using authenticated active learning state plus canonical reuse receipts, current-tenure activation/rollback freshness, explicit UTC `as_of`, bounded fail-closed scanning, and recommendation-only human/domain review.
- [x] **M-09** Add bounded autonomous maintenance scheduler/advisor; recommendations only unless promotion authority is explicitly present. PR #390 adds bounded `run_once()` recommendation-only orchestration and no mutation surface.

## H. Generic Tool / Capability Descriptor

- [~] **T-01** Define runtime-wide immutable `CapabilityDescriptor` view over existing canonical capability/tool sources. `ToolMetadata` provides the micro-tool foundation, but the broader multi-kind descriptor is not complete.
- [ ] **T-02** Support kinds: `tool`, `program`, `gateway`, `agent`, `provider`, `adapter`.
- [~] **T-03** Define effect taxonomy. Micro-Tool Registry v0.2 has deterministic `read`, `network_read`, `compute`, `write`, `execute`, `control`, `delete`; broader runtime effect convergence remains open.
- [~] **T-04** Unknown/plugin/external effects fail closed to effect-capable/high-risk until reviewed. Unknown cost/risk/effect metadata is rejected, but external capability quarantine remains open.
- [ ] **T-05** Descriptor may contain required environment variable names but never secret values.
- [ ] **T-06** Descriptor must declare result-size limit and evidence requirement.
- [x] **T-07** Descriptor/registry selection must not grant authority. Micro-Tool Registry v0.2 explicitly preserves `TaskCapabilityAuthority` as the execution boundary.
- [ ] **T-08** Add stable descriptor fingerprint/provenance/version metadata.

## I. Generic Capability Registry

- [~] **T-10** Add closed built-in registry over reviewed descriptors. Deterministic `MicroToolRegistry` exists; full runtime-wide capability source convergence remains open.
- [~] **T-11** Reject duplicate capability IDs and unreviewed overrides. Duplicate IDs fail closed; generalized reviewed override policy remains open.
- [ ] **T-12** Add namespaces for adapters/plugins/providers.
- [ ] **T-13** Add immutable registry fingerprint.
- [~] **T-14** Add compact agent/task capability listing. Metadata-only compact registry view and authority-aware selection exist; generalized agent/task projection remains open.
- [x] **T-15** Add exact capability resolve/view operation. `MicroToolRegistry.get()` provides exact validated lookup.
- [~] **T-16** Preserve domain-specific security registry as an adapter, not a discarded duplicate. Office-IT specs are consumed through `from_specs`; broader domain adapters remain open.

## J. Toolsets and availability

- [x] **T-20** Add `ToolsetDescriptor` / named capability groups. V0.2 `ToolPreset` is the composition-only named group primitive.
- [ ] **T-21** Initial `windows_diagnostics` toolset.
- [ ] **T-22** Initial `linux_diagnostics` toolset.
- [ ] **T-23** Initial `network_diagnostics` toolset.
- [ ] **T-24** Initial `camera_diagnostics` toolset.
- [ ] **T-25** Initial `security_forensics_readonly` toolset.
- [ ] **T-26** Initial `repository_coding` toolset.
- [~] **T-27** Add platform/profile/task filtering. Platform, cost, admin, network scope and task-authority prefiltering exist; full profile/task convergence remains open.
- [ ] **T-28** Add bounded availability probes.
- [ ] **T-29** Add TTL cache only when cache identity is correctly scoped.
- [x] **T-30** Toolset membership never grants capability authority.

## K. Authority-bound invocation and evidence

- [~] **T-40** Capability selection must resolve descriptor before invocation. Registry selection is descriptor-first; generalized invocation convergence is not complete.
- [~] **T-41** Every invocation must intersect with canonical `TaskCapabilityAuthority`. Existing execution authority is canonical and registry selection prefilters it; universal generic-adapter enforcement remains open.
- [~] **T-42** Apply domain-specific policy gate where required. Existing network scope/domain gates exist in specific paths; generic adapter convergence remains open.
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

- [x] **C-01** Skill catalog progressive-disclosure regression tests, including bounded metadata search and metadata-only catalog telemetry.
- [x] **C-02** Reference pack integrity/path/symlink/tamper tests.
- [x] **C-03** Candidate create/patch/supersede contract and production supersession tests.
- [~] **C-04** Replay/self-reinforcement resistance tests. Replay/duplicate receipts and immutable identities are covered; dedicated independent re-grounding tests remain open.
- [~] **C-05** Held-out evaluation tests. Deterministic Phase 4K evaluation exists; dedicated held-out benchmark remains open.
- [x] **C-06** Promotion/materialization/supersession atomicity and rollback tests.
- [~] **C-07** Generic capability registry duplicate/override tests. Duplicate/malformed metadata tests exist; generalized override policy remains open.
- [~] **C-08** Authority intersection tests. Micro-tool selection and existing execution authority have coverage; universal adapter invocation convergence remains open.
- [ ] **C-09** Unknown external tool fail-closed tests.
- [ ] **C-10** MCP schema drift/quarantine tests.
- [ ] **C-11** Tool-result bounding/error-redaction tests.
- [~] **C-12** Observation/evidence lineage tests. Adaptive reuse/outcome lineage is tested; exact stale-skill freshness/rollback tenure behavior is also covered, while generic tool Observation normalization remains open.
- [~] **C-13** Python 3.11 and 3.12 full regression for the final integrated milestone. Current Skill lifecycle slices pass both versions, but the overall Tool lifecycle is not final.
- [~] **C-14** Installer/deployment regression for the final integrated milestone. Current slices pass installer and portable deployment CI; final Tool lifecycle remains open.
- [~] **C-15** Windows/Linux platform-specific smoke for the final integrated milestone where a runner is available. Current slices pass Windows runtime smoke and Ubuntu 22.04/24.04 portable deployment; final Tool lifecycle remains open.

## Current execution slice

### Skill lifecycle — core convergence achieved

The core chain is now implemented and merged:

`verified evidence -> candidate -> validation -> human/domain approval -> production materialization -> runtime retrieval/reuse -> exact reuse receipt -> authoritative effectiveness signal -> bounded maintenance recommendation -> reviewed revision -> deterministic Phase 4K evaluation -> authenticated activation -> immutable production supersession -> operator rollback mirror`

Progressive disclosure is also converged through approved catalog list/view, reviewed references, bounded metadata-only search, and metadata-only list/view/selected telemetry. Recommendation-only stale active-skill review is now bound to authenticated exact-version state and current-tenure reuse freshness.

This does **not** mean self-evolution is finished. Remaining Skill-side gaps are deliberately narrower:

1. **E-03 / E-05** — contradiction-triggered and vendor/version-drift maintenance inputs;
2. **E-07 / P-01 / P-03** — held-out benchmark and pre-publication regression comparison;
3. **E-08 / E-09** — safer/narrower preference and explicit self-reinforcement resistance;
4. **M-03..M-07** — normalized rates, resource correlation, last-verified/vendor applicability statistics, and quarantine recommendations.

### Tool lifecycle — next major convergence area

Micro-Tool Registry v0.2 is already the canonical starting point. Do not create another registry. Continue by extending it toward the remaining requirements:

1. runtime-wide capability descriptor/fingerprint without granting authority;
2. named Windows/Linux/network/camera/security toolsets built from small capabilities;
3. universal authority-bound adapter invocation + bounded Observation/evidence receipts;
4. external/plugin/MCP quarantine and schema-drift handling;
5. domain migrations as small read-only tools, not one giant diagnostic workflow.

### Merge discipline

For every next slice:

1. re-check live `main` before branch/write;
2. reuse canonical modules before adding new ones;
3. keep one narrow responsibility per PR;
4. run exact-head Python 3.11/3.12 + security + deployment gates that apply;
5. merge only with exact expected head SHA;
6. re-check live `main` after merge.
