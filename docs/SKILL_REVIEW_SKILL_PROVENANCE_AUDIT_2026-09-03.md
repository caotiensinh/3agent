# Skill Security Review — skill-provenance-audit

Date: 2026-09-03
Lane: 9
Status: candidate-ready-for-CI

## Purpose

Create a deterministic pre-admission audit skill so upstream popularity or permissive licensing can never substitute for provenance, capability review, or clean-room adaptation.

## Reviewed upstream ideas

- `getsentry/skills@0b8707d25edf588a1c6e9911feecf743fde931c5`
  - retained concepts previously reviewed by WorkSpace: scoped reusable skill instructions and explicit task guidance.
- `vercel-labs/agent-browser@fbd3441e38efe5823284aeb9a3d536f58c33819a`
  - retained concepts previously reviewed by WorkSpace: capability-focused agent tooling patterns and the need for explicit boundaries.
- Existing WorkSpace registry/review records remain the authoritative admission policy.

## Clean-room boundary

No upstream skill text, source code, browser implementation, package, prompt, or dependency is vendored. The candidate is project-owned governance wording.

## Quarantine boundary

The candidate lives under `skill_candidates/`, outside the approved loader root. It cannot approve itself or modify registry state.

## Removed / denied capabilities

- popularity-based trust
- license-only approval
- hidden network/credential/process capability
- auto-install or auto-update
- content-driven policy override
- concealed logging or exfiltration
- persistent self-modification

## Safety invariants

- exact upstream revision is recorded
- retained concepts are explicit
- copied text/code is distinguished from concept adaptation
- capabilities default to denied
- removed risky behavior remains auditable
- deterministic schema/hash/scope/provenance checks precede approval

## Admission gates

1. Candidate itself passes size/front matter/hash checks.
2. Candidate grants no execution capability.
3. Existing registry governance remains authoritative.
4. Exact-head CI and regression suite pass before registry admission.
