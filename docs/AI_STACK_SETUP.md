# Application-Only AI Stack Setup

## Target machine

This path is for a test workstation where the GPU driver is already prepared:

- Ubuntu 24.04.x
- x86_64
- 2× NVIDIA GeForce RTX 5090
- healthy NVIDIA driver branch 590 or newer
- sudo-capable normal user
- Internet access to Ubuntu repositories, GitHub and ollama.com

The script deliberately treats the NVIDIA driver and kernel as **preconditions**, not installation targets.

## One command

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_ai_stack_ubuntu2404.sh | bash
```

The default model is `qwen3:30b`.

To choose another Ollama model:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_ai_stack_ubuntu2404.sh \
  | THREE_AGENT_MODEL='<model>' bash
```

## What is installed

1. `ca-certificates`, `curl`, `git`, `jq`, Python 3, `python3-venv`, pip and SQLite CLI.
2. Current Ollama Linux runtime using the official installer.
3. A systemd override that exposes exactly the first two detected RTX 5090 GPU UUIDs to Ollama.
4. Ollama defaults optimized for agent workloads:
   - `OLLAMA_CONTEXT_LENGTH=65536`
   - `OLLAMA_FLASH_ATTENTION=1`
   - `OLLAMA_KV_CACHE_TYPE=q8_0`
   - `OLLAMA_MAX_LOADED_MODELS=2`
   - `OLLAMA_NUM_PARALLEL=1`
   - `OLLAMA_KEEP_ALIVE=20m`
5. The `3agent` repository at `~/3agent` by default.
6. `~/3agent/.venv`.
7. Editable installation of the local `three-agent` package.
8. `config/local.json` with local Ollama and `TEST_MODE_FULL_ACCESS=true`.
9. `/usr/local/bin/3agent`.
10. The configured Ollama model.

## What the script never does

The application-only path does not:

- install an NVIDIA driver
- remove an NVIDIA driver
- switch NVIDIA driver branches
- run `ubuntu-drivers`
- reload NVIDIA kernel modules
- reboot the PC
- upgrade the Linux kernel

If `nvidia-smi` is not healthy, driver branch 590+ is not detected, or fewer than two RTX 5090 GPUs are visible, the script fails before installing the AI application stack.

## Validation before FINAL PASS

The installer verifies:

- Ubuntu 24.04.x
- NVIDIA driver health and version
- at least two RTX 5090 GPUs
- Ollama API readiness
- repository deployment
- Python regression tests
- `3agent smoke`
- a real local Ollama generation request
- non-zero VRAM usage reported by Ollama after inference
- final `ollama ps`
- final `nvidia-smi`

Installation log:

```text
/var/log/3agent/ai-stack-setup.log
```

## GPU behavior

Both RTX 5090 UUIDs are made visible to Ollama. Ollama's scheduler chooses placement based on model and available VRAM. If a model fits completely on one GPU, Ollama may intentionally place it on one GPU because that can be faster than splitting inference over PCIe. Models that do not fit on one GPU can be spread across both visible GPUs.

The two-GPU machine is also useful for concurrent model loads as the project evolves toward separate model routing for Research and Presentation/Report workloads.

## Useful overrides

```bash
THREE_AGENT_MODEL='qwen3:30b'
THREE_AGENT_INSTALL_DIR="$HOME/3agent"
THREE_AGENT_MIN_DRIVER_MAJOR=590
THREE_AGENT_REQUIRED_RTX5090_COUNT=2
OLLAMA_CONTEXT_LENGTH=65536
OLLAMA_KEEP_ALIVE=20m
OLLAMA_MAX_LOADED_MODELS=2
OLLAMA_NUM_PARALLEL=1
```

## Daily use

```bash
3agent smoke

TASK_ID="$(3agent task-create \
  --title "AI camera research" \
  --request "Research the requested topic and preserve evidence.")"

3agent research "$TASK_ID" --live
3agent presentation "$TASK_ID" --live
3agent daily-report --live
```

## CI

`installer-ci` runs:

- Bash syntax checks
- the full-bootstrap contract
- the application-only AI-stack contract
- ShellCheck
- Python harness regression tests
- harness smoke

The self-hosted deployment workflow uses the application-only script and first requires a functioning `nvidia-smi` with at least two RTX 5090 devices.
