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

## Recommended setup: NVIDIA driver already installed

For the designated Ubuntu 24.04.x test PC with a healthy **NVIDIA 590+ driver and 2× RTX 5090 already installed**, use the application-only installer:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_ai_stack_ubuntu2404.sh | bash
```

This installer **does not install, replace, remove, reload or upgrade the NVIDIA driver or kernel**. It verifies the existing GPU stack and then completes the application environment:

- base Python/Git/SQLite tooling
- Ollama installation/update
- dual-RTX5090 GPU allow-list using GPU UUIDs
- 64K Ollama context, Flash Attention and q8 K/V cache
- local model pull (`qwen3:30b` by default)
- repository clone/update
- Python virtual environment
- `three-agent` package installation
- `config/local.json`
- global `3agent` command
- regression tests, harness smoke and live GPU-backed model inference

Override the model without editing the script:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_ai_stack_ubuntu2404.sh \
  | THREE_AGENT_MODEL='<model>' bash
```

After it reports `FINAL PASS`, the normal entry points are:

```bash
3agent smoke
3agent task-create --title "Test task" --request "Research the requested topic."
3agent task-list
```

See `docs/AI_STACK_SETUP.md`.

## Full bootstrap when the NVIDIA driver is not prepared

The repository still contains the earlier full workstation bootstrap:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/install_ubuntu_2404_rtx5090.sh | bash
```

For the current designated test PC, prefer `setup_ai_stack_ubuntu2404.sh` because the NVIDIA 590 driver is already installed and should remain outside application deployment authority.

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
- `installer-ci` validates both deployment scripts with Bash contract tests and ShellCheck, then reruns the Python regression suite.
- `deploy-ubuntu-2404-rtx5090` deploys the application-only AI stack to a registered self-hosted PC labeled `rtx5090` after explicit `DEPLOY` confirmation.
- Real dual-GPU acceptance is performed on the target PC because GitHub-hosted runners do not contain RTX 5090 GPUs.

## Repository policy

`data/tasks.db` and transient runtime files stay local and are ignored by Git. Human-readable evidence and generated artifacts are designed to be versioned in GitHub.

See:

- `AGENTS.md` — repository governance and agent operating rules.
- `profiles/` — role profiles, objectives, duties, capabilities and authority.
- `docs/SPEC.md` — detailed product specification.
- `docs/ARCHITECTURE.md` — technical architecture and data flow.
- `docs/HARNESS.md` — harness contracts and CLI lifecycle.
- `docs/TEST_MODE_SECURITY.md` — full-access test-mode boundary.
- `docs/AI_STACK_SETUP.md` — application-only installation for a PC with a prepared NVIDIA stack.
- `docs/DEPLOY_UBUNTU_2404_RTX5090.md` — full workstation bootstrap.
