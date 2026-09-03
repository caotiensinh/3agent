# 3Agent Product Specification

Version: 0.2
Status: Agent 1 research V1 + Agent 2 presentation V1 implementation baseline

## 1. Purpose

Build a local-first multi-agent system for R&D work that can research a subject, transform evidence into presentation/report artifacts, and reconstruct the day's work into a Japanese-style daily report.

The primary execution environment is a test workstation with two RTX 5090 GPUs, 32 GB system RAM and an Intel Core Ultra 7 CPU.

## 2. Primary goals

1. Use local GPU compute instead of requiring a paid cloud LLM API.
2. Keep three logical roles with explicit responsibilities and handoff contracts.
3. Centralize outbound Internet access behind one application gateway.
4. Preserve task/evidence lineage.
5. Store runtime state in SQLite and auditable results in JSON/Markdown.
6. Use GitHub as the versioned repository for source and curated results.
7. Support broad authority on the designated test machine while keeping an upgrade path to least-privilege production deployment.
8. Keep presentation facts evidence-bounded to Agent 1 rather than allowing slide-generation prompts to create a second truth source.

## 3. Non-goals for current V1

- production-grade sandboxing
- enterprise identity/RBAC
- multi-user web application
- distributed worker cluster
- mandatory cloud LLM usage
- autonomous production-system modification
- claim of pixel-perfect visual QA
- fully automatic arbitrary company-template adaptation

## 4. Functional requirements

### FR-001 Task creation

The system shall create a unique task ID and persist title, request, status and timestamps.

### FR-002 Research role

The system shall execute or scaffold a Research Agent task and create structured research artifacts.

### FR-003 Research truth state

Research output shall explicitly represent verified facts, inference, unresolved information and source references rather than flattening all statements into one certainty level.

### FR-004 Presentation role

Presentation Agent shall:

- locate the latest research artifact for the task even when it was generated on a previous day;
- preserve source research path, status and SHA-256;
- create stable presentation evidence claim IDs for Agent 1 verified facts/inferences;
- use the local LLM for narrative planning/claim selection rather than as a new factual source;
- reject unknown evidence claim IDs;
- preserve verified-fact vs inference distinction;
- classify new recommendations as proposals rather than facts;
- generate deterministic source and limitation appendices;
- generate JSON/Markdown and optionally PPTX/PDF artifacts;
- persist QA metadata and generated artifact paths.

### FR-005 Daily report role

The Daily Report Agent shall summarize stored task/activity evidence for a calendar day.

### FR-006 Local inference

The system shall support an Ollama-compatible local inference endpoint without requiring a cloud API key.

### FR-007 Internet gateway

Agent-owned outbound HTTP access shall use the Internet Gateway abstraction.

### FR-008 Full-access test mode

The configuration shall support a test mode in which all agent capabilities can be enabled.

### FR-009 Audit

Gateway requests, execution requests and major agent lifecycle events shall support timestamped audit records.

### FR-010 GitHub storage

The repository shall ignore runtime SQLite/secrets while allowing selected JSON, Markdown and generated report artifacts to be versioned.

### FR-011 Presentation accessibility baseline

Generated PPTX shall target unique slide titles, deterministic object order, body fonts at or above 20 pt, visible source IDs and no meaning conveyed by color alone.

## 5. Agent contracts

### Research Agent input

- task ID
- task title/request
- constraints/context

### Research Agent output

- task ID
- status
- objective/search queries
- source inventory
- verified facts with source IDs
- inferences with source IDs
- unresolved items
- conclusion
- recommended next actions
- timestamp/artifact metadata

### Presentation Agent input

- task ID
- latest source research artifact
- audience
- purpose
- language
- slide budget
- output format
- optional explicit incomplete-research override

### Presentation Agent output

- `presentation-artifact/v1` JSON
- presentation Markdown
- source research path/status/SHA-256
- validated deck plan
- `presentation-qa/v1`
- optional PPTX
- optional PDF
- generated artifact paths

### Daily Report Agent input

- date
- tasks active/modified that day
- activity records
- artifact metadata

### Daily Report Agent output

- work completed
- results/progress
- blockers/problems
- next actions
- referenced task/artifact IDs

## 6. Permission model

V1 uses a capability policy with these conceptual capabilities:

- `filesystem_read`
- `filesystem_write`
- `shell_execute`
- `git_read`
- `git_write`
- `github_read`
- `github_write`
- `internet_outbound`
- `local_llm`

When `test_mode_full_access=true`, all are permitted by default to all three agents. Broad permission does not weaken evidence contracts: Presentation Agent must still not add unsourced external facts.

## 7. Reliability requirements

- A failed model call must not be recorded as successful research/presentation.
- A presentation must fingerprint and reference the exact research artifact it used.
- Unknown presentation claim references must hard-fail validation.
- A dry-run must be visibly labeled as dry-run.
- State transitions and artifact writes must be persisted before reporting success.
- Missing configuration/model name must yield a clear error for live runs.
- Insufficient research for Agent 2 moves the task to `WAITING_HUMAN` unless an explicit scaffold override is supplied.
- Rendering/conversion failures move the task to `FAILED`.

## 8. Storage model

SQLite tables:

- `tasks`
- `activities`
- `artifacts`

Artifact conventions:

```text
data/
  research/YYYY-MM-DD/TASK-ID.{json,md}
  presentations/YYYY-MM-DD/TASK-ID.{json,md,pptx,pdf?}
  daily_reports/YYYY-MM-DD.{json,md}
  activity/*.jsonl
  tasks.db
```

## 9. Hardware utilization strategy

The inference server remains an external local service. Model loading and GPU sharding are controlled by the inference runtime rather than Agent code.

Recommended current strategy:

- one capable primary local model shared by agents;
- deterministic Python code performs validation/rendering after LLM planning;
- add specialized model routing only when measured workloads justify it;
- keep host RAM usage conservative because 32 GB system RAM is smaller than total GPU VRAM.

## 10. Presentation renderer baseline

- implementation: `python-pptx` 1.x
- slide size: 16:9 widescreen
- title target: 30–36 pt
- body target: 20 pt
- source IDs in footer
- speaker notes contain evidence source IDs
- source and limitation appendices are deterministic
- PDF conversion uses LibreOffice/`soffice` when explicitly requested

Structural QA is not the same as pixel-level visual QA. A future renderer-review loop may render slides to images and perform image-level review.

## 11. GitHub workflow

- Source/spec/profile changes are committed normally.
- Runtime database is never committed.
- Curated task results may be committed after validation.
- Git credentials/tokens remain external to the repository.
- CI must install project dependencies before running Presentation Agent renderer tests.

## 12. Acceptance criteria

Core harness acceptance:

1. package installs/imports on Python 3.11+
2. database initializes
3. task can be created/listed/read
4. dry-run research does not pretend to research
5. daily report reconstructs recorded activity
6. unit tests pass without live network/model dependency

Presentation Agent V1 acceptance:

1. research evidence becomes stable `F*`/`I*` claim IDs
2. unknown claim refs and duplicate slide titles are rejected
3. latest cross-day research artifact can be located
4. visible factual slide text is materialized from Agent 1 evidence
5. sources/limitations are appended deterministically
6. source research SHA-256 is persisted
7. PPTX opens and title sequence matches validated plan
8. speaker notes can be generated
9. dry-run stays non-factual
10. legacy harness dry-run remains compatible

## 13. Implementation milestones

### M1 — Harness baseline — IMPLEMENTED
Task store, activity store, artifact manager, local LLM adapter, gateway abstractions, CLI, tests.

### M2 — Real research tool loop — V1 IMPLEMENTED
Search-provider adapter, page retrieval, source normalization, citation/evidence validation.

### M3 — Presentation renderer — V1 IMPLEMENTED
Evidence Gate, evidence-ID planning, deterministic validation, JSON/Markdown, PPTX renderer, optional PDF conversion and structural QA.

Remaining M3 advanced work: company template/theme adaptation, charts from structured numeric evidence and pixel-level visual QA.

### M4 — Automated daily operations
Scheduler, daily report generation, GitHub artifact commit/push gateway.

### M5 — Operator UI
Local web dashboard for tasks, approvals, agent status, logs, reports and GPU/model status.

### M6 — Hardening
OS-level egress policy, isolated workers, least privilege, credential broker, production configuration.
