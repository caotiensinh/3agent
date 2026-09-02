# Skill Security Review — archive-zip-understanding

Date: 2026-09-03
Lane: 8
Status: candidate-ready-for-CI

## Purpose

Inspect ZIP and ZIP-based Office/document containers without path traversal, decompression bombs, nested-archive runaway, or execution authority.

## Reviewed upstream ideas

- `python/cpython@e5ed4db855364d183fc2848ae510ba0f3356dd70`
  - retained concepts: member-oriented ZIP extraction semantics and explicit resource/cleanup handling.
- OWASP File Upload guidance reviewed 2026-09-03.
  - retained concepts: allowlist/validation, bounded file sizes, isolated storage, least privilege, and untrusted filename handling.
- Existing WorkSpace file-safety skills remain authoritative for format-specific active content.

## Clean-room boundary

No CPython/OWASP text, implementation, package, utility, or extraction code is copied. The skill is project-owned instruction text.

## Removed / denied capabilities

- archive member execution
- automatic extraction to arbitrary filesystem locations
- symlink/device/path traversal
- unbounded recursive archive expansion
- remote-reference fetching
- package installation
- shell/process execution
- password guessing or protection bypass

## Safety invariants

- archive fingerprint and member inventory precede extraction
- path safety is checked before writes
- compressed/uncompressed budgets are explicit
- nested archives consume remaining budget
- encrypted/rejected/skipped members remain visible in coverage
- complete claims require member-level coverage

## Admission gates

1. Size/front matter/hash checks pass.
2. No extraction/write authority beyond a separately reviewed runtime is granted.
3. No execution, network, or credential capability is introduced.
4. Exact-head CI and regression suite pass before registry admission.
