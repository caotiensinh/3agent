# Project Harness

## Purpose

The harness is the deterministic control layer around non-deterministic AI behavior. It owns task IDs, state, persistence, artifact paths, activity records, capability configuration and model/gateway adapters.

## State model

```text
NEW
 |
 v
RESEARCHING -> RESEARCH_COMPLETED
                    |
                    v
          PRESENTATION_CREATING
                    |
                    v
         PRESENTATION_COMPLETED
                    |
                    v
                   DONE

Any stage -> FAILED
Any stage -> WAITING_HUMAN
```

Daily reports are cross-task artifacts and do not need to block a task from reaching DONE.

## CLI contract

- `three-agent init`
- `three-agent smoke`
- `three-agent task-create --title ... --request ...`
- `three-agent task-list`
- `three-agent status TASK_ID`
- `three-agent research TASK_ID [--live]`
- `three-agent presentation TASK_ID [--live]`
- `three-agent daily-report [--date YYYY-MM-DD] [--live]`

Without `--live`, agent commands produce a deterministic non-AI scaffold and do not pretend that research/model execution occurred.

## Artifact conventions

```text
data/
  research/YYYY-MM-DD/TASK-ID.{json,md}
  presentations/YYYY-MM-DD/TASK-ID.{json,md}
  daily_reports/YYYY-MM-DD.{json,md}
  activity/*.jsonl
  tasks.db
```

## Test harness requirements

Tests must cover:

- database initialization
- unique task IDs
- valid state persistence
- artifact creation
- dry-run behavior
- activity recording
- daily report reconstruction
