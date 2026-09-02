# Skill Security Review — xlsx-understanding

Date: 2026-09-03
Lane: 5
Status: candidate-ready-for-CI

## Purpose

Add workbook understanding above `file-xlsx-safety`, preserving formula/value provenance and sheet-level coverage without recalculation or active content.

## Reviewed upstream ideas

- `microsoft/markitdown@83ce26def9f54b02dfb9d683c7cb47fee17ce4bc`
  - retained concepts: structured spreadsheet normalization for downstream text analysis.
- Existing WorkSpace `file-xlsx-safety` remains authoritative for workbook active-content restrictions.

## Clean-room boundary

No upstream converter code, parser package, prompt, plugin, macro engine, or dependency is vendored. The skill is project-owned instruction text.

## Quarantine boundary

The candidate is stored under `skill_candidates/`, outside the approved loader root. Promotion is a separate registry-admission change after exact-head CI.

## Removed / denied capabilities

- VBA/Office Scripts/add-ins/DDE execution
- formula recalculation with external effects
- data connections or refreshes
- external-link fetching
- package/plugin installation
- shell/process execution
- protection bypass

## Safety invariants

- all sheet visibility states inventoried
- formula text and cached value remain distinguishable
- hidden rows/columns and errors affect interpretation
- charts retain source-cell provenance where available
- expansion and cell/formula counts are bounded
- complete-workbook claims require sheet coverage

## Admission gates

1. Size/front matter/hash checks pass.
2. Existing XLSX safety remains authoritative.
3. No recalculation, execution, network, or credential capability is granted.
4. Exact-head CI and regression suite pass before registry admission.
