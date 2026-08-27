# 3Agent Product Specification

Version: 0.1
Status: Initial implementation baseline

## 1. Purpose

Build a local-first multi-agent system for R&D work that can research a subject, transform research into presentation/report material, and automatically reconstruct the day's work into a Japanese-style daily report.

The primary execution environment is a test workstation with two RTX 5090 GPUs, 32 GB system RAM and an Intel Core Ultra 7 CPU.

## 2. Primary goals

1. Use local GPU compute instead of requiring a paid cloud LLM API.
2. Keep three logical roles with explicit responsibilities and handoff contracts.
3. Centralize outbound Internet access behind one application gateway.
4. Preserve task/evidence lineage.
5. Store runtime state in SQLite and auditable results in JSON/Markdown.
6. Use GitHub as the versioned repository for source and curated results.
7. Support broad authority on the designated test machine while keeping an upgrade path to least-privilege production deployment.

## 3. Non-goals for V1

- production-grade sandboxing
- enterprise identity/RBAC
- multi-user web application
- distributed worker cluster
- mandatory cloud LLM usage
- automatic PowerPoint visual design engine
- autonomous production-system modification

## 4. Functional requirements

### FR-001 Task creation

The system shall create a unique task ID and persist title, request, status and timestamps.

### FR-002 Research role

The system shall execute or scaffold a Research Agent task and create structured research artifacts.

### FR-003 Research truth state

Research output shall explicitly represent verified facts, inference, unresolved information and source references rather than flattening all statements into one certainty level.

### FR-004 Presentation role

The Presentation Agent shall read source research metadata and preserve source lineage in its output.

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

## 5. Agent contracts

### Research Agent input

- task ID
- task title/request
- constraints/context

### Research Agent output

- task ID
- status
- findings
- verified facts
- inference
- unresolved items
- sources
- conclusion
- next actions
- timestamp/artifact metadata

### Presentation Agent input

- task ID
- source research artifact
- audience/purpose/output constraints

### Presentation Agent output

- task ID
- source research artifact reference
- presentation/report content
- limitations
- artifact metadata

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

When `test_mode_full_access=true`, all are permitted by default to all three agents. Later production profiles can deny capabilities without changing agent identities or artifact contracts.

## 7. Reliability requirements

- A failed model call must not be recorded as successful research.
- A presentation must reference the research artifact it used.
- A dry-run must be visibly labeled as dry-run.
- State transitions and artifact writes must be persisted before reporting success.
- Missing configuration or model name must yield a clear error for live runs.

## 8. Storage model

SQLite tables:

- `tasks`
- `activities`
- `artifacts`

JSON/Markdown artifacts use task ID and date-based directories.

## 9. Hardware utilization strategy

V1 treats the inference server as an external local service. Model loading and GPU sharding are controlled by the inference runtime. This avoids coupling orchestration logic to one GPU runtime.

Recommended initial strategy:

- one capable primary local model rather than three duplicate models
- three agent profiles reuse that model
- add a second specialized model only when measured workload justifies it
- keep system RAM usage conservative because 32 GB host RAM is smaller than total GPU capacity

## 10. GitHub workflow

- Source/spec/profile changes are committed normally.
- Runtime database is never committed.
- Curated task results can be committed after validation.
- Git credentials/tokens remain external to the repository.

## 11. Acceptance criteria for initial harness

The initial harness is accepted when:

1. package installs/imports on Python 3.11+
2. database initializes
3. task can be created/listed/read
4. dry-run research artifact can be generated without pretending to research
5. dry-run presentation artifact preserves research lineage
6. daily report can be generated from recorded activity
7. unit tests pass without network/model dependency
8. live local-LLM path validates required model configuration

## 12. Next implementation milestones

### M1 — Harness baseline
Task store, activity store, artifact manager, local LLM adapter, gateway abstractions, CLI, tests.

### M2 — Real research tool loop
Search-provider adapter, page retrieval, source normalization, citation/evidence validation.

### M3 — Presentation renderer
PPTX/PDF generation, company template/theme support, visual QA.

### M4 — Automated daily operations
Scheduler, daily report generation, GitHub artifact commit/push gateway.

### M5 — Operator UI
Local web dashboard for tasks, approvals, agent status, logs, reports and GPU/model status.

### M6 — Hardening
OS-level egress policy, isolated workers, least privilege, credential broker, production configuration.
