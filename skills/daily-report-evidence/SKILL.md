---
name: daily-report-evidence
description: Produce concise daily work reporting strictly from recorded tasks, activities, artifacts, blockers, and evidence IDs. Use by the Daily Report Agent.
license: Project-internal
compatibility: 3Agent local-first harness; no external data lookup.
---

# Daily Report Evidence

## Boundary

Use only evidence already stored by the harness for the target date. Do not search the Internet or infer unrecorded work.

## Rules

- Every reported work item must trace to recorded task/activity/artifact evidence.
- Never invent completion percentages, time spent, owners, deadlines, decisions, or blockers.
- Treat failed/blocked activity as a blocker, not as completed work.
- Prefer concise Japanese suitable for an R&D manager.
- Keep important unresolved items visible.
- If model output lacks valid evidence IDs, fall back to deterministic evidence-derived text.
- Regenerating the same report must not recursively treat the previous daily report as new work.
