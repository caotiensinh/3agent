# Skill Security Review — pdf-understanding

Date: 2026-09-03
Lane: 3
Status: candidate-ready-for-CI

## Purpose

Add traceable PDF understanding above the existing `file-pdf-safety` boundary without activating PDF content.

## Reviewed upstream ideas

- `py-pdf/pypdf@939aecc7598e33c6c4e886d95655a47dfbf1f6f5`
  - retained concepts: page/text/object-aware PDF parsing and explicit handling of parser limitations.
- `docling-project/docling@c09ddfabff27b1ba6217ab47e207cb646b4ba023`
  - retained concepts: page/layout/table/image/OCR-aware document processing.
- Existing WorkSpace `file-pdf-safety` remains authoritative for active-content and egress restrictions.

## Clean-room boundary

No upstream code, prompts, parser package, plugin, model, or dependency is vendored. This skill is project-owned instruction text derived from general document-processing concepts.

## Removed / denied capabilities

- JavaScript/action execution
- attachment execution
- remote link dereference
- package/plugin installation
- shell/process execution
- credentials or secret access
- automatic external OCR/model calls

## Safety invariants

- every physical page is inventoried
- OCR is explicitly labeled
- reading-order uncertainty is surfaced
- annotations/forms/attachments remain inert evidence
- empty extraction routes to visual review
- complete-PDF claims require explicit page coverage

## Admission gates

1. Skill size/front matter/hash pass deterministic checks.
2. Existing PDF safety contract remains unchanged.
3. No runtime or network authority is introduced.
4. Exact-head CI plus regression suite must pass before registry promotion.
