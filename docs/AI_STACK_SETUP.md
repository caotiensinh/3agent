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

The default routed model pool is:

- fast/presentation/report: `qwen3:14b`
- research: `qwen3:30b`
- deep escalation: `deepseek-r1:32b`

Models are stored on disk and may remain resident in VRAM when resources permit. There is **no fixed resident-model count limit**.

## Dynamic resource admission

Before 3Agent starts a model request, the runtime reads live resource state and calculates whether the candidate can be admitted safely.

Default limits:

- aggregate GPU VRAM budget: **90%**
- system RAM budget: **90%**
- pre-start GPU utilization guard: **95%**
- pre-start GPU power-ratio guard: **95% of the reported power limit**
- pre-start GPU temperature guard: **85°C**
- model VRAM estimate safety factor: **1.15×**
- host-RAM model overhead reservation: **15% of the estimated model footprint**
- generation serialization: enabled by default

A second, third, or later model is allowed to remain resident when the projected aggregate resource use stays within the configured budget. If adding another model would exceed the VRAM or RAM budget, 3Agent denies that activation before requesting the model from Ollama.

Cross-process reservation state prevents two requests from simultaneously passing the same stale free-memory check. By default, actual generation is serialized even when multiple models are resident, which reduces simultaneous GPU power and thermal spikes.

The utilization, power, and temperature checks are admission guards. They prevent new work from being started when the machine is already near the configured limits; they are not a replacement for a hardware/NVIDIA power-limit setting and therefore are not claimed to be a hard instantaneous power cap during a running inference.

## What is installed

1. `ca-certificates`, `curl`, `git`, `jq`, Python 3, `python3-venv`, pip and SQLite CLI.
2. Current Ollama Linux runtime using the official installer.
3. A systemd override that exposes the detected RTX 5090 GPU UUIDs used by the stack.
4. Ollama runtime defaults including 65k context, flash attention, q8 KV cache, keep-alive, and bounded parallel generation.
5. The `3agent` repository at `~/3agent` by default.
6. `~/3agent/.venv`.
7. Editable installation of the local `three-agent` package.
8. `config/local.json` with the routed model pool and dynamic resource-control policy.
9. `/usr/local/bin/3agent`.
10. The configured Ollama model pool.

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

## Admission calculation

Conceptually, a new model is accepted only when all relevant checks pass:

```text
projected VRAM
  = max(live GPU used VRAM, VRAM reported for resident Ollama models)
  + outstanding model reservations
  + estimated candidate model footprint

projected RAM
  = live host RAM used
  + reserved host-RAM loading/runtime overhead
  + candidate host-RAM loading/runtime overhead
```

The candidate model footprint is estimated from Ollama model metadata and multiplied by the configured safety factor. Host RAM does not assume a full duplicate copy of GPU-offloaded model weights; it reserves a configurable overhead fraction instead.

If either projection exceeds its budget, activation is denied. A resource denial on the primary model is **not** escalated to a larger deep model. If the deep model was preferred but cannot fit, the router may fall back to the smaller primary model when that primary model passes admission.

## Validation before FINAL PASS

The installer/upgrader verifies:

- Ubuntu 24.04.x
- NVIDIA driver health and version
- at least two RTX 5090 GPUs
- Ollama API readiness
- repository deployment
- Python regression tests
- `3agent smoke`
- dynamic resource-control configuration
- absence of a fixed loaded-model count cap
- real local Ollama generation
- resident VRAM remains within the configured budget during physical validation
- final `ollama ps`
- final `nvidia-smi`

Installation log:

```text
/var/log/3agent/ai-stack-setup.log
```

## Useful overrides

```bash
THREE_AGENT_FAST_MODEL='qwen3:14b'
THREE_AGENT_RESEARCH_MODEL='qwen3:30b'
THREE_AGENT_PRESENTATION_MODEL='qwen3:14b'
THREE_AGENT_REPORT_MODEL='qwen3:14b'
THREE_AGENT_DEEP_MODEL='deepseek-r1:32b'

THREE_AGENT_MAX_VRAM_PERCENT=90
THREE_AGENT_MAX_RAM_PERCENT=90
THREE_AGENT_MAX_GPU_UTIL_PERCENT=95
THREE_AGENT_MAX_GPU_POWER_PERCENT=95
THREE_AGENT_MAX_GPU_TEMP_C=85
THREE_AGENT_MODEL_SIZE_SAFETY_FACTOR=1.15
THREE_AGENT_MODEL_RAM_OVERHEAD_FACTOR=0.15
THREE_AGENT_SERIALIZE_GENERATION=true
```

The runtime clamps VRAM and RAM budgets to at most 95%, so a local configuration cannot silently turn the safety margin into 100% occupancy.

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

`harness-ci` and `installer-ci` validate the Python resource-admission logic, multi-model budget decisions, configuration compatibility, Bash contracts, ShellCheck, and existing agent regressions. Physical dual-RTX5090 validation is still required before declaring the target workstation itself PASS.
