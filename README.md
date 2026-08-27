# 3Agent

Local-first multi-agent work system for an R&D test workstation.

The project coordinates three AI roles around a shared task/evidence model:

1. **Research Agent / 調査・情報収集AI** — gathers and verifies information.
2. **Presentation Agent / 資料作成・発表AI** — turns verified research into management-ready material.
3. **Daily Report Agent / 日報作成AI** — records work activity and generates a daily report.

The initial target is a test PC with **2× NVIDIA RTX 5090, 32 GB RAM, Intel Core Ultra 7**. AI inference is local-first. Cloud LLM APIs are not required.

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

## Ubuntu 24.04.4 + dual RTX 5090: one-command deployment

On the target PC, run this as the normal sudo-capable user:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/install_ubuntu_2404_rtx5090.sh | bash
```

This checks Ubuntu 24.04.4, preserves a healthy NVIDIA driver, verifies at least two RTX 5090 GPUs, installs/configures Ollama, deploys the Python harness, pulls the configured model, installs the `3agent` command and runs a live verification.

Default model: `qwen3:30b`. Override it with:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/install_ubuntu_2404_rtx5090.sh \
  | THREE_AGENT_MODEL='<model>' bash
```

Full deployment documentation: `docs/DEPLOY_UBUNTU_2404_RTX5090.md`.

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

## CI

- `harness-ci` validates the Python harness.
- `installer-ci` checks Bash syntax, installer contracts, ShellCheck and regression tests on GitHub-hosted Ubuntu 24.04.
- `deploy-ubuntu-2404-rtx5090` can deploy to a registered self-hosted test PC labeled `rtx5090` after an explicit `DEPLOY` workflow-dispatch confirmation.

Hosted GitHub runners do not contain RTX 5090 GPUs; real GPU acceptance is therefore executed on the target PC by `scripts/verify_deployment.sh` or the self-hosted deployment workflow.

## Repository policy

`data/tasks.db` and transient runtime files stay local and are ignored by Git. Human-readable evidence and generated artifacts are designed to be versioned in GitHub.

See:

- `AGENTS.md` — repository governance and agent operating rules.
- `profiles/` — role profiles, objectives, duties, capabilities and authority.
- `docs/SPEC.md` — detailed product specification.
- `docs/ARCHITECTURE.md` — technical architecture and data flow.
- `docs/HARNESS.md` — harness contracts and CLI lifecycle.
- `docs/TEST_MODE_SECURITY.md` — full-access test-mode boundary.
- `docs/DEPLOY_UBUNTU_2404_RTX5090.md` — one-command GPU workstation deployment.
