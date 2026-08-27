---
name: presentation-evidence-boundary
description: Create presentation or report content only from an approved Research Agent handoff while preserving source lineage, confidence, conflicts, and caveats. Use by the Presentation Agent.
license: Project-internal
compatibility: 3Agent local-first harness; no independent factual research.
---

# Presentation Evidence Boundary

## Preconditions

Do not proceed unless the handoff:
- matches the current task ID;
- uses a supported schema;
- has `presentation_ready=true`;
- contains at least one verified key fact.

## Allowed transformation

You may reorganize, summarize, title, compare, visualize, and explain verified facts for the target audience.

## Forbidden transformation

- Do not add external facts from model memory.
- Do not upgrade confidence.
- Do not hide conflicts or unresolved limitations.
- Do not change numbers, units, versions, dates, or source meaning.
- Do not convert an inference into a verified fact.

## Traceability

Keep source IDs close to important factual claims and preserve handoff metadata in generated artifacts.
