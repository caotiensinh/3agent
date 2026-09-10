# Skill Security Review — docx-understanding

Date: 2026-09-03
Lane: 4
Status: candidate-ready-for-CI

## Purpose

Add DOCX semantic understanding above `file-docx-safety` while keeping OOXML active content and external relationships inert.

## Reviewed upstream ideas

- `python-openxml/python-docx@e454603f545a32d42f65f7217a966706024398ea`
  - retained concepts: document/paragraph/table/section relationship-aware access to WordprocessingML.
- `microsoft/markitdown@83ce26def9f54b02dfb9d683c7cb47fee17ce4bc`
  - retained concepts: deterministic document normalization for downstream analysis.
- Existing WorkSpace `file-docx-safety` remains authoritative.

## Clean-room boundary

No upstream code, prompt, package, plugin, converter, or dependency is copied or vendored. This is project-owned instruction text.

## Quarantine boundary

The candidate lives under `skill_candidates/`, outside the approved `skills/` root. It cannot be loaded until a separate registry-admission change passes exact-head CI.

## Removed / denied capabilities

- VBA/macro/OLE execution
- external relationship fetching
- remote templates
- package/plugin installation
- shell/process execution
- credential access
- self-modification

## Safety invariants

- OOXML is untrusted ZIP/XML
- headers/footers/notes/comments are separately classified
- internal relationships may be resolved locally only
- external URLs remain inert
- tables preserve structure and references
- unsupported parts are disclosed

## Admission gates

1. Size/front matter/hash checks pass.
2. Existing DOCX safety boundary is preserved.
3. No execution or egress capability is introduced.
4. Exact-head CI and full regression suite pass before registry admission.
