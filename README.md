# 3Agent

Local-first multi-agent work system for an R&D test workstation.

The project coordinates three AI roles around a shared task/evidence model:

1. **Research Agent / 調査・情報収集AI** — gathers, cleans, verifies and structures information.
2. **Presentation Agent / 資料作成・発表AI** — turns presentation-ready research handoff data into management-ready material.
3. **Daily Report Agent / 日報作成AI** — records work activity and generates a daily report.

The initial target is a test PC with **2× NVIDIA RTX 5090, 32 GB RAM, Intel Core Ultra 7**. AI inference is local-first. Cloud LLM APIs are not required.

## Preferred setup for the prepared RTX 5090 workstation

If NVIDIA driver 590+ is already installed and `nvidia-smi` sees both RTX 5090 GPUs, use the application-only setup path:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_ai_stack_ubuntu2404.sh | bash
```

This path intentionally does **not** install, remove, switch or reload the NVIDIA driver, does not upgrade the kernel, and does not reboot the PC. It installs the remaining AI application stack: Ollama, local model, Python environment, 3Agent harness, configuration and validation.

The default model is `qwen3:30b`. Qwen3 supports Ollama thinking mode; deterministic installer/structured-agent calls use non-thinking mode unless an agent explicitly requests reasoning output.

See `docs/AI_STACK_SETUP.md` and `docs/OLLAMA_QWEN3_VALIDATION_NOTE.md`.

## Research Agent V1

The first production-capable logical agent is **Research Agent / 調査・情報収集AI**. V1 is implemented as:

```text
Task
  -> local LLM search plan
  -> DuckDuckGo HTML search through Internet Gateway
  -> canonicalize/deduplicate source URLs
  -> source fetch through Internet Gateway
  -> strip script/style/navigation/footer/form boilerplate
  -> deduplicate extracted text fragments
  -> stable source IDs (S1, S2, ...)
  -> local LLM evidence-bounded synthesis
  -> reject claims without valid source IDs
  -> deduplicate facts and merge source lineage
  -> confidence + conflict processing
  -> presentation-ready quality gate
  -> full research JSON/Markdown
  -> compact TASK_handoff.json
```

A model claim without a valid collected source ID cannot enter `verified_facts` or `inferences`; it is rejected into unresolved state. Search/fetch failures are retained in the full artifact instead of being silently hidden.

Agent 2 does **not** normally consume raw page text. It consumes the compact `TASK_handoff.json` and refuses to run unless all of these pass:

- matching `task_id`;
- supported handoff schema;
- `presentation_ready=true`;
- at least one verified key fact.

Critical source conflicts block presentation generation.

The V1 contracts are in:

- `docs/RESEARCH_AGENT_IMPLEMENTATION_PLAN.md`
- `docs/RESEARCH_AGENT_V1_ACCEPTANCE.md`
- `docs/RESEARCH_HANDOFF_CONTRACT.md`

## Core design

```text
User / Supervisor
      |
      v
  Python Harness
      |
      +-------------------+--------------------+
      |                   |                    |
      v                   v                    v
Research Agent      Presentation Agent    Daily Report Agent
      |                   |                    |
      +-------------------+--------------------+
                          |
                     Local LLM
                   (Ollama-compatible)
                          |
                    RTX 5090 x2

All external access -> Application Internet Gateway -> Internet / GitHub
All state           -> SQLite (local runtime)
All auditable output-> JSON / Markdown / PPTX/PDF later -> GitHub
```

## Test-machine authority

The initial configuration intentionally supports **TEST_MODE_FULL_ACCESS=true**. In test mode, agents may be granted local filesystem, shell, Git, GitHub and outbound network capabilities. External access still flows through a single application gateway so requests can be logged and later restricted without redesigning the agents.

This is a **test-workstation policy only**. It is not production authorization.

## Manual quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp config/test.example.json config/local.json
three-agent init
three-agent smoke
```

Create a task:

```bash
three-agent task-create \
  --title "AI camera traffic analytics" \
  --request "Research AI-camera traffic analytics for an internal R&D review."
```

Run with the local model:

```bash
export THREE_AGENT_CONFIG=config/local.json
export LOCAL_LLM_MODEL=<installed-model-name>
three-agent task-list
three-agent research TASK-YYYYMMDD-0001 --live
three-agent presentation TASK-YYYYMMDD-0001 --live
three-agent daily-report --live
```

Research output is written under:

```text
data/research/YYYY-MM-DD/
  TASK-....json
  TASK-....md
  TASK-...._handoff.json
```

## CI

- `harness-ci` validates the Python harness.
- `installer-ci` checks Bash syntax, installer contracts, ShellCheck and regression tests on GitHub-hosted Ubuntu 24.04.
- `deploy-ubuntu-2404-rtx5090` can deploy to a registered self-hosted test PC labeled `rtx5090` after an explicit `DEPLOY` workflow-dispatch confirmation.

Hosted GitHub runners do not contain RTX 5090 GPUs; real GPU acceptance is therefore executed on the target PC.

## Repository policy

`data/tasks.db` and transient runtime files stay local and are ignored by Git. Human-readable evidence and generated artifacts are designed to be versioned in GitHub.

See:

- `AGENTS.md` — repository governance and agent operating rules.
- `profiles/` — role profiles, objectives, duties, capabilities and authority.
- `docs/SPEC.md` — detailed product specification.
- `docs/ARCHITECTURE.md` — technical architecture and data flow.
- `docs/HARNESS.md` — harness contracts and CLI lifecycle.
- `docs/TEST_MODE_SECURITY.md` — full-access test-mode boundary.
- `docs/AI_STACK_SETUP.md` — preferred setup when driver 590+ is already installed.
- `docs/RESEARCH_HANDOFF_CONTRACT.md` — Agent 1 cleaning/quality gate and Agent 2 handoff rules.
