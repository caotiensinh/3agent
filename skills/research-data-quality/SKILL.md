---
name: research-data-quality
description: QA cleaned research before downstream handoff by checking source coverage, duplicates, conflicts, scope, units, freshness, and unsupported conclusions. Use before presentation_ready can become true.
license: Project-internal
compatibility: 3Agent local-first harness; deterministic quality gate remains authoritative.
---

# Research Data Quality

## Purpose

Reduce the chance that noisy or weak evidence reaches the Presentation Agent.

## Checks

- Confirm at least one readable source exists.
- Confirm every verified fact has valid source lineage.
- Detect duplicate facts and merge only when meaning is equivalent.
- Do not merge facts that differ by version, date, model, geography, unit, population, or condition.
- Surface contradictions and classify material conflicts for the deterministic gate.
- Preserve unresolved questions and failed-source records.
- Check that important numbers retain units, time periods, denominators, and context.
- Flag stale evidence when the task asks for current state.
- Ensure conclusions do not claim more than the verified facts support.

## Handoff rule

The skill may recommend readiness, but it never overrides the deterministic `presentation_ready` gate in code. Critical conflict, no usable source, or no verified fact must remain blocking.
