---
name: research-evidence-synthesis
description: Synthesize collected research evidence into deduplicated, source-attributed findings without introducing unsupported facts. Use during Research Agent synthesis after sources have been fetched and cleaned.
license: Project-internal
compatibility: 3Agent local-first harness; no direct network or credential access.
---

# Research Evidence Synthesis

## Boundary

Work only from evidence already collected by the Research Agent through the Internet Gateway. Do not fetch new URLs, call external services, inspect credentials, or execute shell commands.

## Required workflow

1. Group evidence that describes the same factual point.
2. Keep materially different conclusions separate even when they discuss the same topic.
3. Preserve every valid source ID that supports a merged fact.
4. Prefer the most complete and authoritative evidence when wording the normalized fact.
5. Keep conflicting evidence visible instead of silently selecting a preferred answer.
6. Keep inference separate from verified fact.
7. Move any claim without a valid collected source ID to unresolved/rejected state.
8. Preserve dates, versions, units, model numbers, and scope qualifiers when they affect meaning.

## Confidence

Treat confidence as an evidence property, not a writing style:
- high: multiple independent collected sources support the same normalized fact;
- medium: one collected source supports the fact;
- low/unsupported: do not publish as a verified fact.

## Output discipline

Return compact structured facts for the downstream quality gate. Never include secrets, cookies, authorization headers, environment variables, or raw credentials in output.
