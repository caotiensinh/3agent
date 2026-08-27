# Agent 3 — Daily Report / 日報作成AI Specification

Version: 1.0  
Status: Implemented baseline

## 1. Purpose

Agent 3 converts the actual operational history of the 3Agent system into a Japanese R&D daily report. It is an observer/reconstructor, not the end of a simple Agent1 → Agent2 chain.

It observes recorded work from the whole day and answers:

- What work was actually performed?
- Which tasks changed?
- What artifacts/results were produced?
- What is blocked or waiting?
- What should logically continue next?
- Which items require manager attention?

## 2. Source of truth

Agent 3 reads three SQLite domains:

1. `tasks`
2. `activities`
3. `artifacts`

A task is in scope when it was created/updated on the requested date or is referenced by an activity on that date.

Agent 3 excludes its own previous daily-report activities/artifacts from source evidence. This prevents recursive self-reporting when a report is regenerated.

## 3. Evidence registry

Each report generation assigns auditable evidence IDs:

```text
T1..Tn = Task evidence
A1..An = Activity evidence
F1..Fn = Artifact evidence
```

A canonical evidence snapshot is hashed with SHA-256 and stored as `evidence_digest`.

The digest allows an operator to determine whether two report generations used the same source state even if natural-language phrasing differs.

## 4. Task snapshot model

For each task Agent 3 derives:

- task ID
- title/request
- exact workflow status
- actions recorded during the day
- agents involved
- artifact count/types
- blocker evidence
- deterministic next-action suggestion
- full evidence-ID lineage

Agent 3 does not invent a numeric completion percentage.

## 5. Blocker rules

A task is surfaced as a blocker/concern when at least one of the following is recorded:

- task status = `FAILED`
- task status = `WAITING_HUMAN`
- activity status is not a normal success state (`ok`, `success`, `pass`, `passed`, `completed`, `done`)

The exact source evidence IDs are attached to the blocker entry.

## 6. Live-model contract

With `daily-report --live`, the local Ollama model may improve Japanese phrasing and prioritization, but it does not become the source of truth.

The model must return structured JSON arrays for:

- `summary_points`
- `work_items`
- `achievements`
- `blockers`
- `tomorrow_plan`
- `manager_attention`

Every item must include valid `evidence_ids`. Task-specific items must include a valid exact `task_id`.

Unknown evidence/task references are rejected and listed in `rejected_model_items`.

If a model section is empty/invalid while deterministic evidence exists, the deterministic section is used.

If the model call fails entirely, Agent 3 creates the report using deterministic evidence and sets:

```text
status = deterministic_fallback_after_model_error
```

## 7. Deterministic mode

Without `--live`, Agent 3 still creates a complete auditable report.

Statuses:

- `deterministic_from_evidence`
- `no_activity`

This makes 日報 generation independent of model availability.

## 8. Output schema

The JSON report includes:

```text
schema_version
date
agent_id
status
activity_count
evidence_digest
source_counts
task_snapshots
sections
rejected_model_items
evidence
generated_at
```

The Markdown report contains the six manager-facing sections plus the evidence appendix.

## 9. Re-generation stability

Agent 3's own `daily_report_generation_started`, `daily_report_created` and daily-report artifacts do not enter the next evidence snapshot.

Therefore, when no other work evidence changes:

```text
first evidence_digest == regenerated evidence_digest
```

## 10. Acceptance tests

Agent 3 is accepted when tests confirm:

1. tasks, activity and artifacts are collected together;
2. blocker evidence is retained;
3. re-generation does not recursively change the evidence digest;
4. unknown model evidence IDs are rejected;
5. unknown model task IDs are rejected;
6. empty/invalid live sections fall back to deterministic evidence;
7. total LLM failure falls back to deterministic report generation;
8. an empty date produces an auditable `no_activity` report;
9. legacy `activity_count` remains available for harness compatibility.

## 11. Usage

```bash
3agent daily-report
3agent daily-report --live
3agent daily-report --date 2026-08-27 --live
```

Artifacts:

```text
~/3agent/data/daily_reports/YYYY-MM-DD.json
~/3agent/data/daily_reports/YYYY-MM-DD.md
```
