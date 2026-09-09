# RCA / Hard-Case Knowledge Base

This directory preserves difficult engineering incidents as reusable operational knowledge.

## When a case MUST be recorded

Record a case when one or more of the following is true:

- the root cause was not obvious from the first failure;
- the failure reproduced differently across operating systems, Python/runtime versions, CI lanes, or deployment modes;
- a misleading symptom or false lead could plausibly waste future investigation time;
- the fix required new diagnostics, stronger logging, a new regression test, or a new CI gate;
- the issue affected release readiness, clean installation, upgrade safety, security boundaries, persistence, concurrency, or exact-SHA verification;
- the issue required multiple RCA iterations before the real cause was proven.

## Required structure

Every hard-case record should contain:

1. **Context** — affected component, branch/PR, environment, exact relevant SHA when known.
2. **Symptom** — what failed and where it was observed.
3. **Evidence** — exact logs, traceback, failing test, workflow/job, platform/runtime matrix.
4. **False leads / rejected hypotheses** — what looked plausible but was disproven.
5. **Root cause** — the smallest evidence-backed technical explanation.
6. **Fix** — exact change made and why it addresses the root cause.
7. **Regression protection** — tests, CI gates, diagnostics, or invariants added to prevent recurrence.
8. **Verification** — exact-head and post-merge proof, including cross-platform lanes where relevant.
9. **Reusable lesson** — rules that should influence future debugging or design.
10. **Closure criteria** — what had to be true before the case was considered 100% complete.

## Operating rules

- Do not write an RCA from memory when live evidence can still be fetched.
- Do not label a failure as flaky, infrastructure-only, or platform-specific without evidence.
- Do not weaken a security, correctness, or regression assertion merely to make CI green.
- Do not count planning, reading, waiting for CI, or empty branch activity as progress.
- Prefer exact failing logs over inference. If logs are insufficient, add targeted diagnostics and rerun.
- Keep production changes minimal and isolate test-fixture fixes from production behavior changes when possible.
- Preserve exact-SHA lineage for release and deployment verification.
- A difficult case is not closed at "the PR is green" if the failure originally occurred only after merge, install, upgrade, restart, or another downstream lifecycle step.

## Naming convention

Use:

`YYYY-MM-DD-<short-case-name>.md`

The title should describe the technical failure, not only the PR number.

## Current cases

- [2026-09-10 — Windows Wave-3 diagnostics fixture portability](./2026-09-10-windows-wave3-diagnostics-fixture-portability.md)
