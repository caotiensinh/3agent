# 3Agent

Local-first multi-agent work system for an R&D test workstation.

The project coordinates three AI roles around a shared task/evidence model:

1. **Research Agent / 調査・情報収集AI** — gathers, cleans, verifies and structures information.
2. **Presentation Agent / 資料作成・発表AI** — turns presentation-ready research handoff data into management-ready material.
3. **Daily Report Agent / 日報作成AI** — records work activity and generates a daily report.

The initial target is a test PC with **2× NVIDIA RTX 5090, 32 GB RAM, Intel Core Ultra 7**. AI inference is local-first. Cloud LLM APIs are not required.

## One-command portable deployment

On a supported Linux host, the application can be installed or updated directly from GitHub with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh | bash
```

The bootstrap clones/fetches the repository from GitHub, creates an isolated Python environment, installs project dependencies, preserves existing local config/data, installs `3agent` and `3agent-update` launchers, and runs compile/unit/smoke validation before reporting PASS.

This portable path deliberately does **not** install or modify NVIDIA drivers, the kernel, bootloader, or reboot policy. Live AI is optional; to install Ollama and pull a model in the same command:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh \
  | THREE_AGENT_INSTALL_OLLAMA=1 \
    THREE_AGENT_MODEL=qwen3:30b \
    THREE_AGENT_PULL_MODEL=1 \
    bash
```

Choose a model that fits the target PC. See `docs/PORTABLE_DEPLOY.md` for pinning a branch/tag/SHA, custom install paths, and CI acceptance.

## Preferred setup for the prepared RTX 5090 workstation

If NVIDIA driver 590+ is already installed and `nvidia-smi` sees both RTX 5090 GPUs, use the application-only setup path:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_ai_stack_ubuntu2404.sh | bash
```

This path intentionally does **not** install, remove, switch or reload the NVIDIA driver, does not upgrade the kernel, and does not reboot the PC. It installs the remaining AI application stack: Ollama, local model, Python environment, 3Agent harness, configuration and validation.

The default model is `qwen3:30b`. Qwen3 supports Ollama thinking mode; deterministic installer/structured-agent calls use non-thinking mode unless an agent explicitly requests reasoning output.

See `docs/AI_STACK_SETUP.md` and `docs/OLLAMA_QWEN3_VALIDATION_NOTE.md`.

## End-to-end workflow

The preferred operating path is now one workflow command rather than three manual agent commands:

```text
User request
   |
   v
Task created
   |
   v
Agent 1: Research
   |
   +--> web access only through InternetGateway
   +--> source collection / cleanup / deduplication
   +--> evidence synthesis
   +--> deterministic quality gate
   |
   | presentation_ready=false
   +-------------------------------> Agent 3 daily report -> BLOCKED
   |
   | presentation_ready=true
   v
Agent 2: Presentation
   |
   +--> consumes only validated research handoff
   +--> evidence-bound planning
   +--> PPTX/PDF/source output
   |
   v
Task status = DONE
   |
   v
Agent 3: Daily Report
   |
   +--> task/activity/artifact evidence
   +--> completed, blocked and failed work are all recorded
   |
   v
workflow_runs/YYYY-MM-DD/TASK-....json
```

Run the complete live pipeline:

```bash
three-agent workflow-run \
  --title "AI camera traffic analytics" \
  --request "Research AI-camera traffic analytics and prepare an internal R&D presentation." \
  --live \
  --audience "R&D internal" \
  --purpose "inform" \
  --language ja \
  --slides 6 \
  --format pptx
```

`--live` is intentionally explicit because it authorizes Agent 1 to use the configured Internet Gateway and enables local-model generation. Without `--live`, Agent 1 performs a dry run, the research quality gate blocks Agent 2, Agent 3 still records that blocked result, and `workflow-run` exits with code `2`.

Workflow exit codes:

- `0` — full workflow completed;
- `2` — research/presentation gate blocked the workflow without bypassing it;
- `1` — a hard workflow or daily-report failure occurred.

Every run produces an auditable workflow manifest under `data/workflow_runs/YYYY-MM-DD/`. The manifest contains stage outcome and artifact lineage but not raw research page text or credentials.

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

For normal use, prefer the one-command `workflow-run` shown above. The individual commands remain available for debugging or controlled stage-by-stage operation:

```bash
export THREE_AGENT_CONFIG=config/local.json
export LOCAL_LLM_MODEL=<installed-model-name>

three-agent task-create \
  --title "AI camera traffic analytics" \
  --request "Research AI-camera traffic analytics for an internal R&D review."

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
- `portable-deploy-ci` performs clean installs that fetch the source from GitHub, validates exact source lineage, re-runs deployment idempotently, and checks config preservation on Ubuntu 22.04/Python 3.11 and Ubuntu 24.04/Python 3.12.
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
- `docs/PORTABLE_DEPLOY.md` — one-command portable deployment from GitHub.
- `docs/RESEARCH_HANDOFF_CONTRACT.md` — Agent 1 cleaning/quality gate and Agent 2 handoff rules.
