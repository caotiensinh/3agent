# Skill Candidate Quarantine

`skill_candidates/` is an untrusted staging area for WorkSpace-native skill candidates.

Candidates in this tree are **not approved skills** and are intentionally outside `skills/`, the fail-closed root audited by `ApprovedSkillLoader`.

Promotion requires a separate admission change that:

1. passes candidate security/provenance/integrity tests on an exact commit;
2. rechecks the candidate against current `main` policy;
3. copies the reviewed `SKILL.md` into `skills/<name>/`;
4. adds the exact canonical SHA-256, review path, provenance, agent scope, and deny-by-default authority fields to `skills/registry.json`;
5. runs full exact-head regression CI before merge.

Never weaken `ApprovedSkillLoader.audit_registry()` to accommodate a candidate. A candidate that is not admitted must remain outside the approved root.
