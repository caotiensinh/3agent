---
name: skill-registry-admission
description: Admit WorkSpace-native skills into the approved registry only after deterministic integrity, policy, provenance, and regression gates pass.
license: Project-internal
---

# Skill Registry Admission

Registry admission is a release gate, not a writing task.

1. Require a project-owned `SKILL.md`, valid front matter, unique name, approved agent scope, review record, provenance, and exact SHA-256.
2. Enforce enterprise baseline fields: instruction-only, no network, no credentials, no persistence, no external vendored code, and advisory model authority unless a stricter reviewed profile says otherwise.
3. Reject oversized skills or load combinations that exceed registry resource limits.
4. Recompute the skill hash from canonical bytes; never trust a submitted digest.
5. Reject missing review documents, unknown agent IDs, duplicate names, path/name mismatch, or mutable/ambiguous provenance.
6. Run skill-loader, registry, security, and full regression tests on the exact candidate commit.
7. Do not mark a skill enabled until every mandatory gate is green; failed candidates remain quarantined and do not enter the approved load path.
8. Record the exact candidate commit and CI evidence used for promotion.
