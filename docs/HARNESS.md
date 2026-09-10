# Project Harness

## Purpose

The harness is the deterministic control layer around non-deterministic AI behavior. It owns task IDs, state, persistence, artifact paths, activity records, capability configuration, model/gateway adapters and presentation validation/rendering.

## State model

```text
NEW
 |
 v
RESEARCHING -> RESEARCH_COMPLETED
                    |
                    v
          PRESENTATION_CREATING
               |            |
               |            +--> WAITING_HUMAN (insufficient evidence)
               |
               +--> FAILED (invalid plan/render failure)
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
- `three-agent presentation TASK_ID [--live] [--audience ...] [--purpose ...] [--language ja|en|vi] [--slides N] [--format source|pptx|pdf|all]`
- `three-agent daily-report [--date YYYY-MM-DD] [--live]`

Without `--live`, agent commands produce deterministic non-AI scaffolds and do not pretend that external research/model work occurred.

## Presentation harness contract

Live Agent 2:

1. resolves the latest research JSON across date directories;
2. applies the research evidence gate;
3. stores source SHA-256;
4. builds an evidence catalog;
5. asks the model for claim-ID-based deck planning;
6. validates plan deterministically;
7. generates source/limitation appendices;
8. optionally renders PPTX/PDF;
9. records QA and artifacts;
10. only then sets `PRESENTATION_COMPLETED`.

## Artifact conventions

```text
data/
  research/YYYY-MM-DD/TASK-ID.{json,md}
  presentations/YYYY-MM-DD/TASK-ID.{json,md,pptx,pdf?}
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
- cross-day artifact lookup
- dry-run behavior
- activity recording
- daily report reconstruction
- presentation evidence catalog
- presentation invalid claim rejection
- unique slide titles
- source/limitation appendices
- PPTX generation/openability
- source lineage preservation
