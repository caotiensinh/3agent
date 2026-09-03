# Lean profile — dual RTX 5090 + 32GB system RAM

## Target host

- Ubuntu 24.04.4
- Intel Core Ultra 7 desktop CPU
- 2× NVIDIA GeForce RTX 5090 (32GB VRAM each, 64GB aggregate)
- **32GB system RAM**
- 1TB NVMe SSD

## What is actually scarce on this class of host

The default `install_ubuntu_2404_rtx5090.sh` / `setup_ai_stack_ubuntu2404.sh` path is
already the officially targeted configuration for a dual-RTX-5090 workstation, and GPU
VRAM (64GB aggregate) is generous relative to the default model pool. System RAM is not:
32GB is comparatively tight for a machine carrying two 32GB GPUs, several always-on
Python services (WorkSpace core, chat gateway, egress broker) and, historically, three
resident Ollama daemons at once once the GPU worker pool is enabled (`ollama.service`
plus `ollama-gpu0.service` and `ollama-gpu1.service`, see
`scripts/enable_gpu_worker_pool.sh`). Every change in this profile follows
`avoid > reuse > precompute > compact > parallelize > accelerate > scale hardware`
(`docs/WORKSPACE_DESIGN_PRINCIPLES.md`) applied specifically at the RAM axis: nothing
here reduces model size, context budget or answer quality.

## Change 1 — retire the redundant dual-GPU Ollama daemon (avoid duplicate work)

`OllamaWorkerPool` (`src/three_agent/worker_pool.py`) only calls the dual-GPU worker
(`ollama.service` on port 11434) as a fallback when a model does not fit either single
GPU's VRAM budget. With the default routed pool —

```text
fast/presentation/report: qwen3:14b   (~9GB on disk)
research:                 qwen3:30b   (~19GB on disk)
deep escalation:          deepseek-r1:32b or qwen3:30b (~19-20GB on disk)
```

— every model, even after the 1.15× safety factor, comfortably fits inside one RTX
5090's 88% VRAM budget (≈28GB). The dual-GPU fallback path is therefore never exercised
in normal operation, and the resident `ollama.service` process is pure duplicate
overhead: a third Ollama runtime plus its own model-metadata cache, on the one resource
(host RAM) that this machine has comparatively little of.

`scripts/enable_gpu_worker_pool.sh` now accepts an opt-in flag:

```bash
scripts/enable_gpu_worker_pool.sh --retire-dual-service
```

Before touching anything, it re-verifies the safety condition on the live machine: it
reads the configured model pool from `config/local.json`, queries the GPU0 worker for
each model's actual on-disk size, and checks every one against the live single-GPU VRAM
budget. Only if **all** configured models fit does it `systemctl disable --now
ollama.service`. If any model would not fit, it leaves `ollama.service` running and
prints exactly which model and why. This is purely additive: it never changes the
GPU0/GPU1 worker units that already passed `verify_affinity`, and it is fully reversible:

```bash
sudo systemctl enable --now ollama.service
```

If you later add a model larger than one RTX 5090's budget to the pool, re-enable
`ollama.service` first so the dual-GPU fallback is available again.

## Change 2 — align the installer's resource budget with the reviewed secure profile

`config/workspace.secure.json` (the canonical, already-reviewed Confidential Core
profile) has always shipped with `max_vram_percent: 88` / `max_ram_percent: 82`. The
one-command installers (`setup_ai_stack_ubuntu2404.sh`, `enable_model_pool.sh`) shipped
a separate, more permissive default of `90` / `90` that was never reconciled with the
canonical profile. That drift is fixed: the installer defaults now match the canonical
secure profile (88% VRAM / 82% RAM) out of the box, still overridable with
`THREE_AGENT_MAX_VRAM_PERCENT` / `THREE_AGENT_MAX_RAM_PERCENT`.

## Change 3 — a profile tuned specifically for 32GB hosts

`config/workspace.lean-dual5090-32gb.json` is `workspace.secure.json` unchanged except
for the resource-control block:

| Field | Secure default | Lean 32GB profile | Why |
| --- | --- | --- | --- |
| `max_ram_percent` | 82 | 78 | 32GB has less absolute headroom than a typical larger-RAM workstation; a wider margin protects against OS + multi-service + burst (e.g. large-file parsing) spikes without touching model choice or context size. |
| `model_ram_overhead_factor` | 0.15 | 0.20 | Slightly more conservative per-model host-RAM reservation given the tighter absolute budget. |
| `worker_pool` | not set | pre-wired to GPU0/GPU1 ports | Matches the two-single-GPU-worker topology this profile assumes. |

No context-length, model-size or citation/evidence behavior changes. Security posture
(confidential mode, strict egress, execution gateway) is identical to
`workspace.secure.json`.

Use it with:

```bash
export WORKSPACE_CONFIG=config/workspace.lean-dual5090-32gb.json
```

## Validating the claim on the real machine

This document was written without access to the physical workstation, so the RAM
savings from Change 1/2/3 are a reasoned estimate, not a measured result.
`docs/WORKSPACE_DESIGN_PRINCIPLES.md` Principle 10 and the D7 evidence discipline
(`docs/D7_RESOURCE_BENEFIT_MEASUREMENT.md`) both require an actual before/after
measurement before any optimization is accepted — that measurement can only happen on
the target hardware. `scripts/measure_ram_baseline.sh` is a read-only instrument for
exactly that:

```bash
scripts/measure_ram_baseline.sh before > /tmp/before.json
scripts/enable_gpu_worker_pool.sh --retire-dual-service
scripts/measure_ram_baseline.sh after > /tmp/after.json
diff /tmp/before.json /tmp/after.json
```

It reports aggregate RAM used/available, per-GPU VRAM/utilization/temperature, the
`active`/`inactive` state of the relevant systemd units, and how many models are
resident per worker — nothing else (no hostname, GPU UUID/serial, model name, or process
command line), consistent with the metadata-only discipline already used by
`evaluation/representative_hardware_closure_20260830.json`.

## What this profile deliberately does not do

- It does not shrink model size, context window, retry/escalation budgets, or any
  evidence/citation gate — those are quality and correctness controls, not RAM knobs.
- It does not weaken `internet_gateway`, `execution_gateway`, or confidentiality mode.
- It does not disable D5-02/D5-05 context-packing behavior or reopen the `NO-GO` decision
  recorded in `docs/research/06_REPRESENTATIVE_HARDWARE_CLOSURE_2026-08-30.md` — that
  closure is unrelated to host RAM and remains in force.
