# Skill Security Review — document-visual-understanding

Date: 2026-09-03
Lane: 2
Status: candidate-ready-for-CI

## Purpose

Create a WorkSpace-native visual-document analysis contract that keeps visible facts, OCR output, and model inference distinct and traceable.

## Reviewed upstream ideas

- `docling-project/docling@c09ddfabff27b1ba6217ab47e207cb646b4ba023`
  - retained concepts: page/layout/table/image/OCR-aware document representation and local processing.
- Existing WorkSpace file-safety skills remain authoritative for active-content and egress restrictions.

## Clean-room boundary

No upstream code, prompts, package, model, plugin, OCR engine, MCP service, or dependency is vendored. The candidate uses project-owned wording and only adapts general processing concepts.

## Removed / denied capabilities

- image-triggered tool execution
- remote OCR/model calls
- URL/media fetching
- plugin/model auto-download
- shell/process execution
- credential access
- policy changes caused by content

## Safety invariants

- stable visual identifiers
- visible facts separated from OCR and inference
- prompt-injection text inside images has no authority
- OCR disagreement is surfaced
- confidence limitations are explicit
- bounded pixels/image count/time/memory

## Admission gates

1. Skill bytes remain within registry limits.
2. Front matter name matches directory.
3. No runtime/egress capability is granted.
4. SHA-256 is recomputed from repository bytes.
5. Exact-head CI and full regression suite pass before registry admission.
