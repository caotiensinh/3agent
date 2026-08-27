---
name: research-source-credibility
description: Evaluate already-collected public research sources for authority, independence, recency, evidence strength, and scope before promoting claims downstream.
license: Project-internal
compatibility: 3Agent local-first harness; no direct network, credential, shell, or persistence authority.
---

# Research Source Credibility

## Boundary

Work only with source metadata and page text already collected by the Research Agent through the controlled Internet Gateway. Do not perform independent network access, inspect credentials, execute commands, or persist task-specific memory.

## Evaluation dimensions

For each source, consider:

- relevance to the exact research question;
- recency when the task depends on current state;
- authority and proximity to the underlying fact;
- primary-source status versus commentary or aggregation;
- independence from other sources that repeat the same upstream claim;
- evidence strength, including concrete dates, versions, measurements, and scope;
- commercial, advocacy, or promotional purpose that may affect interpretation;
- consistency with other collected sources.

## Source use rules

1. Prefer primary documentation, specifications, official repositories, standards, or original reports when they directly support the claim.
2. Use secondary sources to add context or independent corroboration, not to replace a stronger primary source without reason.
3. Repeated copies of the same upstream statement do not count as independent confirmation.
4. Preserve material qualifiers such as geography, product version, date, sample size, unit, and operating condition.
5. A source may be useful yet insufficient for a verified fact; move unsupported conclusions to unresolved or inference.
6. If sources disagree materially, surface the conflict instead of choosing the most convenient result.
7. Never upgrade confidence merely because a source sounds authoritative.

## Handoff discipline

Source-quality judgment informs synthesis, but deterministic 3Agent lineage and presentation-readiness gates remain authoritative.
