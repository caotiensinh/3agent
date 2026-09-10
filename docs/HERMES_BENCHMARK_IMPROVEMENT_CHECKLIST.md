# Hermes Benchmark Improvement Checklist

Status: active comparative improvement backlog for WorkSpace.

Audit date: 2026-09-08

WorkSpace snapshot used for this audit: `fab35f5abd595073e098cc4b46be07810822902a`

Hermes snapshot used for this audit: `866332bfb52c46e543143b2620a9aeee8bce9c77`

Canonical WorkSpace implementation checklist:
`docs/WORKSPACE_SKILL_TOOL_SELF_EVOLUTION_CHECKLIST.md`

This document is a benchmark and gap register, not permission to copy Hermes trust assumptions or create parallel WorkSpace subsystems. Existing canonical WorkSpace runtime, authority, evidence, learning, checkpoint, skill, and micro-tool sources remain authoritative.

## 1. Comparison rule

Hermes is the historical reference point that helped motivate the WorkSpace agent direction. We use it to answer three different questions:

1. What product/runtime behavior is already stronger in WorkSpace and must not regress?
2. What mature Hermes behavior should WorkSpace learn from?
3. What WorkSpace controls should deliberately exceed Hermes because the target environment includes enterprise network, security, diagnostics, camera, and infrastructure operations?

A feature is not counted as complete because a similarly named class exists. Completion requires a real consumer path, negative/fail-closed tests, exact-head CI, and evidence that the feature does not create a second authority or execution source.

## 2. Areas WorkSpace should preserve as stronger design constraints

- [x] **H-BETTER-01 — Authority is a separate canonical object.** Skill/tool metadata, planner output, observations, checkpoints, and model text do not mint execution authority.
- [x] **H-BETTER-02 — Delegated authority can only narrow.** Child task/node authority is derived from the parent and cannot regain removed capability, write, network, or sensitivity scope.
- [x] **H-BETTER-03 — Execution plans are non-authorizing.** `ExecutionPlan` / `ExecutionNode` describe a deterministic DAG but do not become executable credentials.
- [x] **H-BETTER-04 — Admission and dispatch responsibilities are separated.** Pure deterministic readiness evaluation and stateful dispatch coordination remain separate canonical responsibilities.
- [x] **H-BETTER-05 — Execution outcomes bind exact task/plan/node/authority identity.** Canonical observations cannot silently satisfy a different node or wider authority.
- [x] **H-BETTER-06 — Evidence/provenance remains domain-native.** Security/DFIR evidence and custody are adapted into runtime identity rather than replaced by generic model output.
- [x] **H-BETTER-07 — Recovery is non-executing and ambiguity is explicit.** Checkpoint recovery never infers success for ambiguous in-flight work and requires manual reconciliation where exact outcome is unknown.
- [x] **H-BETTER-08 — Skill production activation is reviewed and immutable.** Candidate creation, validation, authenticated approval, materialization, supersession, and rollback are distinct controlled boundaries.
- [x] **H-BETTER-09 — Diagnostic micro-tools default to minimum sufficient evidence.** Current Office IT probes are small, bounded, read-oriented, and internal-network constrained instead of defaulting to one giant privileged workflow.
- [x] **H-BETTER-10 — Production self-modification remains prohibited.** Learning can propose and stage candidate knowledge, but cannot directly grant capabilities or rewrite production authority.

These controls are non-negotiable regression guards while adopting Hermes-like usability or breadth.

## 3. Areas WorkSpace should learn from Hermes

### Runtime/product maturity

- [ ] **H-LEARN-01 — Unified tool/toolset discovery UX.** Make reviewed capabilities easy to list, filter, inspect, and explain without exposing implementation or secrets.
- [ ] **H-LEARN-02 — Dynamic availability checks.** Detect whether a capability backend is actually usable before planning it, with bounded probes and correctly scoped cache identity.
- [ ] **H-LEARN-03 — Multiple execution backends/adapters.** Normalize local, container, SSH/remote, sandbox, provider, and specialist-agent backends behind reviewed adapters rather than embedding backend decisions in model text.
- [ ] **H-LEARN-04 — Subagent/parallel workstreams.** Add runtime-wide delegation contracts and deterministic fan-in while preserving child-authority narrowing, budgets, cancellation, and evidence binding.
- [ ] **H-LEARN-05 — Tool RPC / low-context pipelines.** Permit bounded programmatic composition of already-authorized operations without repeatedly injecting large tool schemas into model context.
- [ ] **H-LEARN-06 — Scheduled automations.** Add durable scheduling/delivery around the existing task/authority model rather than creating a privileged cron bypass.
- [ ] **H-LEARN-07 — Persistent memory/session search.** Improve cross-session retrieval, compression, and provenance-aware recall while filtering by security scope before semantic relevance.
- [ ] **H-LEARN-08 — Multi-interface continuity.** Improve CLI/TUI/web/messaging continuity without weakening recipient/destination authorization or data minimization.
- [ ] **H-LEARN-09 — Cross-platform setup/doctor UX.** One-command setup, deterministic environment inspection, repair guidance, and platform-specific health diagnostics should become first-class product surfaces.
- [ ] **H-LEARN-10 — Provider/backend portability.** Model/provider switching should not require changes to core runtime authority, evidence, or scheduling logic.

### Security engineering lessons from current Hermes development

The Hermes snapshot audited on 2026-09-08 contains a large relay egress-authorization hardening workstream. The useful lesson is structural: a caller can correctly classify a refusal yet a downstream fallback can still re-send the same content through another operation. WorkSpace should test the complete caller -> adapter -> result/egress path, not only helper functions.

- [ ] **H-LEARN-11 — Destination/target authorization must match the resolved target actually used by dispatch.**
- [ ] **H-LEARN-12 — Authorization refusal must remain distinguishable from transport failure/ambiguity.**
- [ ] **H-LEARN-13 — A refusal must not be laundered into a fallback send/edit/draft path.**
- [ ] **H-LEARN-14 — Absence and fault must be separate states.** Unknown routing/config/adapter state must not silently become authorization.
- [ ] **H-LEARN-15 — Mutation/negative tests must drive real production callers.** A callee test does not prove the caller forwards the security-critical field or reacts correctly to the result.

## 4. WorkSpace targets that must deliberately exceed the benchmark

- [ ] **H-EXCEED-01 — One canonical runtime capability descriptor with immutable fingerprint/provenance.** No second registry or hidden model-created descriptor source.
- [ ] **H-EXCEED-02 — External/plugin/MCP capabilities are quarantined before model/runtime exposure.** Unknown effect, schema drift, or provenance failure is fail-closed.
- [ ] **H-EXCEED-03 — External identity is not WorkSpace authority.** OAuth/provider/plugin authentication proves remote identity only; it never expands task capability authority.
- [ ] **H-EXCEED-04 — Result/egress boundary is mandatory.** Tool output is bounded, disclosure-aware, normalized, and auditable before entering model/UI/runtime observations.
- [ ] **H-EXCEED-05 — Every executable adapter revalidates exact authority immediately before invocation.** Registry membership, toolset membership, availability, plan membership, and prior approval do not substitute for this check.
- [ ] **H-EXCEED-06 — Every accepted tool outcome becomes canonical Observation + evidence identity.** Free-form provider output alone cannot unlock dependencies.
- [ ] **H-EXCEED-07 — Revocation/cancellation remains effective during long-running adapters.** New work must stop and partial/ambiguous outcomes remain explicit.
- [ ] **H-EXCEED-08 — Recovery never auto-replays ambiguous side effects.** Idempotency/safe-retry must be an explicit adapter property, not a generic scheduler assumption.
- [ ] **H-EXCEED-09 — Secrets stay outside model-visible capability descriptors and audit projections.** Environment variable names/credential classes may be declared; values may not.
- [ ] **H-EXCEED-10 — Security tests cover caller/callee/choke-point behavior and over-refusal controls.** Fail-closed changes must also prove legitimate traffic/tasks remain usable.

## 5. Canonical incomplete WorkSpace tasks

This section mirrors the current canonical self-evolution checklist so future sessions do not lose unfinished work.

### P0 — universal invocation, result, evidence, and external capability boundary

- [ ] **T-43** Adapter invocation contract; no raw model-selected shell command path.
- [~] **T-44** Bound tool result size and error disclosure. **Started 2026-09-08:** `tool_result_boundary.py` plus first Office IT local-collector integration is under implementation.
- [ ] **T-45** Normalize invocation output to canonical runtime `Observation`.
- [ ] **T-46** Bind Observation to content-addressed evidence.
- [ ] **T-47** Emit audit-safe capability decision and invocation receipt.
- [ ] **T-48** Preserve revocation/cancellation behavior across long-running adapters.
- [ ] **C-09** Unknown external tool fail-closed tests.
- [ ] **C-10** MCP schema drift/quarantine tests.
- [ ] **C-11** Tool-result bounding/error-redaction tests. **Started with T-44.**
- [~] **C-12** Generic Observation/evidence lineage tests.
- [ ] **X-01..X-10** External/MCP discovery, quarantine, identity separation, secret isolation, schema-drift review, override prevention, and provenance/audit.

### P1 — generic descriptor/registry/toolsets/availability

- [~] **T-01** Runtime-wide immutable `CapabilityDescriptor` view over canonical sources.
- [ ] **T-02** Descriptor kinds: `tool`, `program`, `gateway`, `agent`, `provider`, `adapter`.
- [~] **T-03** Runtime-wide effect taxonomy convergence.
- [~] **T-04** Unknown/external effects fail closed until reviewed.
- [ ] **T-05** Required environment variable names only; never secret values.
- [ ] **T-06** Descriptor result-size limit and evidence requirement.
- [ ] **T-08** Stable descriptor fingerprint/provenance/version.
- [~] **T-10** Extend the canonical Micro-Tool Registry toward reviewed runtime-wide capability projection; do not create a second registry.
- [~] **T-11** General reviewed override policy.
- [ ] **T-12** Adapter/plugin/provider namespaces.
- [ ] **T-13** Immutable effective registry fingerprint.
- [~] **T-14** Compact authority-aware agent/task capability listing.
- [~] **T-16** Preserve domain registries as adapters during convergence.
- [ ] **T-21** `windows_diagnostics` toolset.
- [ ] **T-22** `linux_diagnostics` toolset.
- [ ] **T-23** `network_diagnostics` toolset.
- [ ] **T-24** `camera_diagnostics` toolset.
- [ ] **T-25** `security_forensics_readonly` toolset.
- [ ] **T-26** `repository_coding` toolset.
- [~] **T-27** Full platform/profile/task filtering.
- [ ] **T-28** Bounded availability probes.
- [ ] **T-29** Correctly scoped TTL cache.

### P1 — remaining skill-quality/self-learning gaps

- [ ] **E-03** Revision trigger from verified contradiction.
- [ ] **E-05** Revision trigger from vendor/version drift.
- [~] **E-07 / P-01 / P-03** Held-out benchmark and pre-publication regression comparison.
- [ ] **E-08** Prefer safer/narrower candidates when quality is non-inferior.
- [~] **E-09** Explicit self-reinforcement resistance and independent re-grounding.
- [~] **E-10** Complete contradiction/resolution lineage.
- [~] **E-11** Explicit quarantine state/recommendation.
- [ ] **P-04** Independent-source/evidence-diversity policy.
- [~] **M-03** Normalized effectiveness rates.
- [ ] **M-04** Tool-call/latency/resource delta.
- [~] **M-05** Last-verified projection.
- [ ] **M-06** Vendor/version applicability statistics.
- [~] **M-07** Quarantine recommendation.
- [ ] **M-08** Stale-skill review policy.

### P2 — domain capability breadth

Windows:
- [~] **D-WIN-01** Event Viewer read/evidence: narrow System/Application/Security collectors exist; generic evidence normalization and broader event coverage remain.
- [ ] **D-WIN-02** System/hardware inventory.
- [ ] **D-WIN-03** Driver/GPU inventory.
- [ ] **D-WIN-04** Storage health/read-only metadata.
- [ ] **D-WIN-05** Service/process status read.
- [ ] **D-WIN-06** Network/interface/status read.
- [ ] **D-WIN-07** Crash-dump metadata/read-only collector.

Linux:
- [ ] **D-LNX-01** Journal read/evidence.
- [ ] **D-LNX-02** dmesg/kernel read.
- [ ] **D-LNX-03** PCI/GPU inventory.
- [ ] **D-LNX-04** Storage health/read-only metadata.
- [ ] **D-LNX-05** Service/process status read.
- [ ] **D-LNX-06** Network/interface/status read.

Network/Camera:
- [ ] **D-NET-01** ARP/neighbor evidence read.
- [~] **D-NET-02** SNMPv3 reviewed read: domain security capability exists; generic domain tool integration remains.
- [~] **D-NET-03** Passive flow/telemetry adapters: domain primitives exist; generic capability integration remains.
- [ ] **D-CAM-01** ONVIF discovery/identity.
- [ ] **D-CAM-02** RTSP health probe.
- [ ] **D-CAM-03** Camera manufacturer/model identity.
- [ ] **D-CAM-04** PoE/status read where supported.
- [ ] **D-CAM-05** Vendor reviewed runbook skills/reference packs.

### P2 — operator/product surface

- [ ] **U-01** Explain available/matched skills.
- [ ] **U-02** Show selected toolset and effective authorized subset.
- [ ] **U-03** Candidate skill creation/revision status.
- [ ] **U-04** Promotion evidence/evaluation summary.
- [ ] **U-05** Exact production skill version/hash/rollback lineage.
- [ ] **U-06** Quarantine/retirement recommendations.
- [ ] **U-07** Operator approve/reject with reason codes.
- [ ] **U-08** Browser projections never expose credentials or unnecessary sensitive evidence.
- [ ] **H-LEARN-04/06/07/08/09** Delegation, automation, memory/search, interface continuity, and doctor/install maturity.

## 6. Implementation order from today

1. **Result boundary (T-44/C-11)** — close unbounded local collector `stdout`/`stderr`; preserve raw digest/size metadata without returning unbounded text.
2. **Generic CapabilityDescriptor (T-01/T-02/T-05/T-06/T-08)** — extend canonical Micro-Tool Registry projection, no second registry.
3. **Registry fingerprint + namespaces (T-10..T-16)** — incorporate existing security/domain registries by adapters.
4. **Universal invocation contract (T-43/T-41/T-42)** — authority revalidation at the actual adapter boundary.
5. **Observation/Evidence receipts (T-45..T-47/C-12)**.
6. **Cancellation/revocation/safe retry (T-48)**.
7. **External/MCP quarantine (X-01..X-10/C-09/C-10)**.
8. **Availability + named toolsets (T-21..T-29)**.
9. **Domain migrations** — Windows -> Linux -> Network -> Camera, always as small read/evidence capabilities.
10. **Skill-quality gaps** — held-out comparison, contradiction/vendor drift, self-reinforcement resistance, stale/quarantine policy.
11. **Runtime-wide subagent delegation, automation, memory/search, and operator UI** after the authority/evidence adapter boundary is canonical.

## 7. Definition of done for every checklist item

An item may move to `[x]` only when all applicable requirements are true:

1. canonical source is reused or explicitly adapted;
2. no parallel authority/registry/evidence/runtime source is introduced;
3. model input cannot widen permission;
4. malformed/unknown/security-critical ambiguity fails closed;
5. over-refusal control proves legitimate use still works;
6. test drives the real caller/consumer path, not only a helper double;
7. output/evidence is bounded and disclosure-aware;
8. deterministic fingerprint/provenance exists where identity matters;
9. exact-head CI passes;
10. merge uses exact expected head and post-merge state is verified.
