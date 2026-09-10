# Skill Security Review — document-full-ingestion

Date: 2026-09-03
Lane: 1
Status: candidate-ready-for-CI

## Purpose

Create a WorkSpace-native instruction skill that forces complete, traceable document ingestion before summarization or analysis.

## Reviewed upstream ideas

- `docling-project/docling@c09ddfabff27b1ba6217ab47e207cb646b4ba023`
  - retained concepts: unified document representation, page/layout/table/image/OCR awareness, local processing.
- `microsoft/markitdown@83ce26def9f54b02dfb9d683c7cb47fee17ce4bc`
  - retained concepts: broad format normalization, stream-oriented conversion, deterministic text-oriented downstream consumption.
- Existing WorkSpace file safety skills remain authoritative for PDF/DOCX/XLSX/PPTX active-content and egress restrictions.

## Clean-room boundary

No upstream source code, prompt text, package, plugin, MCP server, converter implementation, model, or dependency is vendored. The candidate is project-owned wording that adapts general processing concepts only.

## Quarantine boundary

The candidate lives under `skill_candidates/`, outside the fail-closed approved `skills/` root. It cannot be loaded by `ApprovedSkillLoader` and must not be copied to `skills/` until a separate registry-admission change passes exact-head CI.

## Removed / denied capabilities

- remote URL conversion and remote resource fetching
- plugin discovery or dynamic converter loading
- package installation
- shell/process execution
- macro/script/OLE/embedded-binary execution
- credential access
- persistent self-modification
- automatic external model/service calls

## Safety invariants

- original bytes preserved
- inventory before summary
- unit-level coverage ledger
- bounded expansion/time/memory
- OCR and inference labeled separately
- no “complete” claim with unexplained gaps
- confidential content remains local

## Admission gates

1. Skill file <= registry `max_skill_bytes`.
2. Front matter name matches directory.
3. No URL-fetch/install/exec instructions are present.
4. SHA-256 is recomputed from repository bytes.
5. Existing harness + installer + portable + Windows CI remain green on exact candidate head.
6. Registry admission is a separate change that copies the already-reviewed bytes into `skills/` and records the exact hash/provenance/scope.
