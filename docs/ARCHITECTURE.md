# Architecture

## 1. Architectural goals

- Local-first inference on the test workstation.
- Three logical agent roles sharing one or more local models.
- One application-level Internet Gateway abstraction.
- SQLite for runtime state.
- JSON/Markdown for auditable interchange/evidence.
- GitHub for versioned source and selected generated artifacts.
- Capability policy that can be broad in test and restrictive in production.

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
  +-------------------------------+
  |               |               |
Research      Presentation    DailyReport
Agent             Agent           Agent
  |               |               |
  +------- Local LLM Adapter -----+
  |
  +------- Internet Gateway ------> Internet
  +------- Execution Gateway -----> Local OS / Git
```

## 3. Single Internet Gate

The initial single-gate requirement is enforced at the application architecture level: agents receive an Internet Gateway interface rather than creating arbitrary HTTP clients in agent code.

`TEST_MODE_FULL_ACCESS=true` allows all destinations through the gateway but still records requests.

Important: this is not yet an OS firewall guarantee. A future hardened deployment can enforce the same rule with container/network namespaces, proxy settings, nftables/iptables or host firewall policy.

## 4. Local LLM

The first adapter targets an Ollama-compatible HTTP endpoint on `127.0.0.1:11434`.

The harness does not hard-code a model name. This allows the operator to select a model appropriate for available VRAM and workload. Multi-GPU placement is delegated to the inference runtime in V1.

Future adapters may support vLLM or another local inference server without changing agent contracts.

## 5. Data flow

### Research

`Task -> Research Agent -> LLM/tools -> research JSON/Markdown -> TaskStore/ActivityStore`

### Presentation

`Task + research artifact -> Presentation Agent -> LLM -> presentation JSON/Markdown -> artifact record`

### Daily report

`TaskStore + activities + artifact metadata -> Daily Report Agent -> daily report`

## 6. GitHub

GitHub stores:

- source code
- agent profiles
- specifications
- curated research JSON/Markdown
- curated presentation source/output
- daily reports

Runtime SQLite and secrets are not committed.
