# 3Agent

Local-first multi-agent work system for an R&D test workstation.

The project coordinates three AI roles around a shared task/evidence model:

1. **Research Agent / 調査・情報収集AI** — gathers and verifies information.
2. **Presentation Agent / 資料作成・発表AI** — turns verified research into management-ready material.
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

Research Agent V1 is implemented as:

```text
Task
  -> local LLM search plan
  -> DuckDuckGo HTML search through Internet Gateway
  -> source fetch/extraction through Internet Gateway
  -> stable source IDs (S1, S2, ...)
  -> local LLM evidence-bounded synthesis
  -> verified facts / inferences / unresolved separation
  -> research_result.json + research_result.md
```

A model claim without a valid collected source ID cannot enter `verified_facts` or `inferences`; it is rejected into unresolved state. Search/fetch failures are retained in the artifact instead of being silently hidden.

## Presentation Agent V1

Presentation Agent is now an evidence-bounded rendering pipeline rather than a free-form slide prompt:

```text
latest Agent 1 research JSON
        -> Evidence Gate + research SHA-256
        -> F1/F2/... verified-fact catalog
        -> I1/I2/... inference catalog
        -> local LLM chooses slide order + claim IDs
        -> deterministic validator
        -> exact Agent 1 claim text materialization
        -> deterministic source/limitation appendices
        -> JSON/Markdown + PPTX (+ optional PDF)
        -> presentation-qa/v1
```

The LLM does **not** supply visible factual body text. It selects evidence IDs; deterministic code retrieves the exact Agent 1 claim and source IDs. Recommendations created by Agent 2 remain visibly classified as proposals.

Example Japanese internal deck:

```bash
3agent presentation TASK-YYYYMMDD-0001   --live   --audience "部長・R&Dチーム"   --purpose "技術選定の判断"   --language ja   --slides 6   --format pptx
```

Outputs are written under:

```text
data/presentations/YYYY-MM-DD/
  TASK-ID.json
  TASK-ID.md
  TASK-ID.pptx
  TASK-ID.pdf   # only when PDF is requested and LibreOffice is available
```

See `docs/PRESENTATION_AGENT_SPEC.md` and `docs/PRESENTATION_AGENT_ACCEPTANCE.md`.

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
All auditable output-> JSON / Markdown / PPTX/PDF -> GitHub when curated
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

Create and execute a full task:

```bash
TASK_ID="$(three-agent task-create   --title "AI camera traffic analytics"   --request "Research AI-camera traffic analytics for an internal R&D review.")"

three-agent research "$TASK_ID" --live
three-agent presentation "$TASK_ID" --live --language ja --format pptx
three-agent daily-report --live
```

## CI

- `harness-ci` installs project dependencies and validates Python 3.11/3.12, including PPTX renderer tests.
- `installer-ci` checks Bash syntax, installer contracts, ShellCheck and the complete harness regression suite on GitHub-hosted Ubuntu 24.04.
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
- `docs/PRESENTATION_AGENT_SPEC.md` — Agent 2 evidence and rendering contract.
- `docs/TEST_MODE_SECURITY.md` — full-access test-mode boundary.
- `docs/AI_STACK_SETUP.md` — preferred setup when driver 590+ is already installed.
