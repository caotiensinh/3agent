# Architecture

## 1. Architectural goals

- Local-first inference on the test workstation.
- Three logical agent roles sharing one or more local models.
- One application-level Internet Gateway abstraction.
- SQLite for runtime state.
- JSON/Markdown for auditable interchange/evidence.
- GitHub for versioned source and selected generated artifacts.
- Capability policy that can be broad in test and restrictive in production.
- Presentation facts remain bound to Research Agent evidence.

## 2. Components

```text
CLI / future Web UI
        |
        v
   Orchestrator
        |
  +-----+------------------+
  |                        |
TaskStore              ActivityStore
(SQLite)                (SQLite/JSONL)
  |
  +-----------------------------------------+
  |                    |                    |
Research           Presentation        DailyReport
Agent                  Agent               Agent
  |                      |
  |                Evidence Gate
  |                      |
  |                Evidence Catalog
  |                      |
  |                  LLM Planner
  |                      |
  |            Deterministic Validator
  |                      |
  |                 PPTX Renderer
  |                      |
  +---------- Local LLM Adapter -----------+
  |
  +---------- Internet Gateway -----------> Internet
  +---------- Execution Gateway ----------> Local OS / Git
```

## 3. Single Internet Gate

The single-gate requirement is enforced at the application architecture level: agents receive an Internet Gateway interface rather than creating arbitrary HTTP clients in agent code.

`TEST_MODE_FULL_ACCESS=true` allows broad destinations through the gateway but still records requests. This is not yet an OS firewall guarantee.

Presentation Agent normally does not need Internet access to create factual content. New factual discovery belongs to Research Agent.

## 4. Local LLM

The first adapter targets an Ollama-compatible HTTP endpoint on `127.0.0.1:11434`.

The harness does not hard-code a model name. Multi-GPU placement is delegated to the inference runtime.

## 5. Data flow

### Research

`Task -> Research Agent -> search/fetch -> evidence JSON/Markdown -> TaskStore/ActivityStore`

### Presentation

```text
Task
 + latest research JSON
        |
        v
Evidence Gate (status + SHA-256)
        |
        v
F*/I* evidence catalog
        |
        v
LLM selects/order claim IDs
        |
        v
validator materializes exact claim text + source IDs
        |
        +--> presentation JSON/Markdown
        +--> PPTX
        +--> optional PDF
        |
        v
QA + ArtifactStore + ActivityStore
```

Presentation source lookup is cross-day: Agent 2 is not limited to research created on the same calendar day.

### Daily report

`TaskStore + activities + artifact metadata -> Daily Report Agent -> daily report`

## 6. Presentation truth boundary

- Agent 1 owns factual discovery/verification.
- Agent 2 owns selection, ordering, audience adaptation and rendering.
- Agent 2 LLM references claims by ID rather than supplying visible factual text.
- Deterministic code copies visible factual text from Agent 1 claims.
- Proposals are separately labeled and may be authored by Agent 2.
- Unresolved research becomes a deterministic limitation appendix.

## 7. Presentation rendering

The PPTX adapter uses `python-pptx` and creates a 16:9 presentation with deterministic object insertion order, unique titles, readable font targets, source-ID footers and speaker notes.

PDF conversion is optional and uses LibreOffice/`soffice` when installed.

Structural QA is deterministic. Pixel-level visual QA is a later extension and must not be claimed by the current implementation.

## 8. GitHub

GitHub stores:

- source code
- agent profiles
- specifications
- curated research JSON/Markdown
- curated presentation source/output
- daily reports

Runtime SQLite and secrets are not committed.
