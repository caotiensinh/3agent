# Skill Security Review — pptx-understanding

Date: 2026-09-03
Lane: 6
Status: candidate-ready-for-CI

## Purpose

Add slide-deck understanding above `file-pptx-safety`, with slide-level provenance and explicit handling of notes, hidden slides, charts, and unsupported objects.

## Reviewed upstream ideas

- `scanny/python-pptx@278b08bdfa1b0a9aa6e5c9173dc893ead892cfe5`
  - retained concepts: slide/shape/chart/table/relationship-aware presentation parsing.
- `microsoft/markitdown@83ce26def9f54b02dfb9d683c7cb47fee17ce4bc`
  - retained concepts: deterministic presentation normalization for downstream analysis.
- Existing WorkSpace `file-pptx-safety` remains authoritative.

## Clean-room boundary

No upstream code, prompt, package, plugin, embedded-workbook handler, or dependency is vendored. This is project-owned instruction text.

## Quarantine boundary

The candidate is stored under `skill_candidates/`, outside the approved loader root. Promotion requires a separate exact-head registry-admission change.

## Removed / denied capabilities

- macro/OLE/embedded package execution
- external media/link fetching
- remote templates
- package/plugin installation
- shell/process execution
- credential access

## Safety invariants

- every slide and note page is inventoried
- hidden slides are surfaced
- visual-layout interpretation is labeled
- charts retain embedded-data provenance when safely available
- OCR/inference remains separate from visible facts
- full-deck claims require slide-level coverage

## Admission gates

1. Size/front matter/hash checks pass.
2. Existing PPTX safety boundary remains authoritative.
3. No execution, external media fetch, or credential capability is introduced.
4. Exact-head CI and regression suite pass before registry admission.
