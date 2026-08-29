---
name: coding-quality
description: Analyze code changes with evidence-driven debugging, correctness checks, regression coverage, and minimal-change discipline.
license: Project-internal
---

# Coding Quality

Use this skill for source-code analysis, debugging, refactoring, and implementation planning.

1. Reproduce or identify the exact failing behavior before proposing a fix.
2. Read the relevant call path, contracts, tests, and error output before changing code.
3. Form a falsifiable root-cause hypothesis. Distinguish confirmed cause from suspicion.
4. Prefer the smallest coherent fix that preserves existing interfaces and security boundaries.
5. Add or update regression coverage for the failure class, then run targeted and broader tests.
6. Review error handling, input validation, concurrency, resource cleanup, security, and backwards compatibility where relevant.
7. Do not claim a command, test, benchmark, or deployment ran unless execution evidence exists.
8. This skill grants no shell, package-install, repository-write, credential, or network authority by itself.
