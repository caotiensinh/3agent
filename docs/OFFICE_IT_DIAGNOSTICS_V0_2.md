# Office IT Diagnostics V0.2 — Security and Admission Review

## Scope

This review admits the project-owned streaming PC diagnostic doctrine into the existing approved `office-it-diagnostics` skill. It does not create a second production skill registry and does not admit the candidate collector scripts as autonomous execution capabilities.

Reviewed candidate baseline: `9e7c4f4103260d4c8bc97423173c9fa85b806067`, `skill_candidates/pc-diagnostic-streaming/`.

## Retained concepts

- streaming diagnosis instead of questionnaire-first support;
- preserve raw customer wording separately from technical interpretation;
- normalize layperson symptoms before technical routing;
- keep customer causal claims as hypotheses, never facts;
- ask 1–3 high-information questions and cancel obsolete questions;
- correlate user answers with logs/events/tool evidence continuously;
- maintain a bounded differential diagnosis and preserve contradictions;
- micro-tools first, deep collection only when justified;
- repair requires separate authority and post-repair verification.

## Runtime integration

`src/three_agent/diagnostics/complaint_semantics.py` performs deterministic local semantic normalization. `adaptive_diagnostic_router.py` augments routing with neutral evidence/subsystem terms and reuses the canonical `diagnostics.runtime_registry` for cross-platform read-only selection.

No second runtime registry, tool executor, credential path, network policy, or remediation authority is introduced. Existing Office selector behavior remains available for compatibility.

## Security boundary

The approved skill remains instruction-only. Semantic normalization does not execute commands. Tool selection does not grant execution authority. Execution remains subject to `TaskCapabilityAuthority`, bounded tool-result handling, redaction, and the advisory diagnostic observation envelope.

This change does not authorize log clearing, service/registry/firewall changes, driver changes, network reset, process termination, package installation, firmware work, forced crashes, destructive storage actions, scanning, brute force, or credential use.

Customer statements such as `GPU hỏng`, `RAM hỏng`, `Windows Update làm hỏng máy`, or `bị virus` are represented only as customer hypotheses until independently corroborated.

## Provenance

Project-owned clean-room synthesis derived from the WorkSpace diagnostic design and the project candidate package. No external code is vendored and no external skill text is promoted.

## Admission conditions

1. `skills/office-it-diagnostics/SKILL.md` stays within the 3,072-byte registry budget.
2. Registry SHA-256 must match the exact approved skill bytes.
3. Semantic and router tests must pass on the exact branch head.
4. Existing capability consistency, authority, registry and security tests must remain green.
5. Any future state-changing repair capability requires a separate admission and explicit authority review.
