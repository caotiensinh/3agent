# WorkSpace

**Local-first AI work runtime for confidential enterprise use.**

WorkSpace is the product identity of the project previously called `3Agent`. The repository and Python module keep legacy names temporarily for deployment compatibility, but the architecture is capability/harness-based and is no longer limited to three agents.

## Mission

WorkSpace helps employees research, analyze data, write, code, design presentations, process local business files and create work reports while keeping confidential business information under enterprise control.

The canonical posture is **local and confidential**:

- LLM inference runs on local Ollama/GPU workers;
- tasks, files, evidence, reports and caches stay on the workstation/server;
- cloud LLM APIs are not required or authorized by default;
- GitHub synchronization is an operator/deployment action, never autonomous runtime authority;
- Confidential Core has no Internet/LAN egress and no access to the public egress broker;
- public research, when required, runs in a separate OS/data zone that cannot read confidential WorkSpace data.

## Security architecture

```text
             CONFIDENTIAL ZONE

 Local files / internal tasks
            |
            v
   +--------------------+
   | WorkSpace Core     |  workspace-core
   | Harness / Evidence |
   | Skills / Context   |
   | Models / Artifacts |
   +---------+----------+
             |
             +---- localhost Ollama/GPU
             |
             X  NO broker membership
             X  NO LAN/Internet egress

             PUBLIC-ONLY ZONE

   +--------------------+
   | Public Research    |  workspace-public
   | separate DB/data   |
   +----+-----------+---+
        |           |
        |           +---- localhost Ollama/GPU
        |
        +---- AF_UNIX ----> Egress Broker (workspace-egress)
                                |
                                +---- DLP
                                +---- search allowlist
                                +---- one-time result URLs
                                +---- HTTPS GET only
                                +---- no confidential-data access
                                v
                             Internet
```

The high-assurance Linux boundary uses separate UIDs, filesystem permissions, Unix peer credentials, systemd hardening and nftables owner rules.

**DLP is defense-in-depth, not the primary confidentiality guarantee.** The primary guarantee is capability separation: the runtime that can read confidential data has no path to the egress broker, while the runtime that can request Internet research cannot read the confidential store.

See `docs/WORKSPACE_SECURITY_ARCHITECTURE.md` and `docs/WORKSPACE_PUBLIC_RESEARCH_ZONE.md`.

## PicoLM-inspired design philosophy

WorkSpace adopts the constraint-first engineering method demonstrated by PicoLM:

1. **Eliminate work before accelerating it.** Avoid > reuse > precompute > compact > parallelize > accelerate > add hardware.
2. **Harness intelligence over prompt size.** Deterministic policy, validation, routing and evidence lineage do not belong to probabilistic model output.
3. **Context is working memory, not storage.** Load only evidence and approved skills needed for the current stage.
4. **Mechanically constrain correctness.** Schema, citations, state transitions, file rules and security policy are enforced by code.
5. **Minimize data movement.** Workflow stages exchange compact handoffs rather than full files/pages.
6. **Cache deterministic work with provenance.** Hash inputs and invalidate caches on parser/policy/version changes.
7. **Use the smallest sufficient model/GPU footprint.** Prefer one RTX 5090 when the model fits; use the second for concurrent work and dual-GPU only when required.
8. **Measure every optimization claim.** Record model, config, tokens, latency, queue wait, VRAM/RAM, cache hits and quality outcome.

See `docs/WORKSPACE_DESIGN_PRINCIPLES.md`.

## Canonical configurations

### Confidential Core — default

`config/workspace.secure.json`

```json
{
  "confidentiality_mode": "confidential",
  "test_mode_full_access": false,
  "internet_gateway": {
    "mode": "strict",
    "public_search_enabled": false,
    "direct_egress": false
  }
}
```

### Public Research — separate trust zone

`config/workspace.public-research.json`

This uses `/var/lib/workspace-public`, disables the execution gateway, and enables only brokered public research. It is never a substitute for the confidential config.

### Lean profile — dual RTX 5090 + 32GB system RAM

`config/workspace.lean-dual5090-32gb.json`

Same security posture and model pool as Confidential Core; only the RAM/VRAM budget and worker-pool wiring are tuned for a host where GPU VRAM is abundant (2× RTX 5090) but system RAM is comparatively scarce (32GB). See `docs/WORKSPACE_LEAN_DUAL_5090_32GB_PROFILE.md` for the reasoning and `scripts/measure_ram_baseline.sh` to validate the effect on the real machine.

## CLI

Primary commands:

```bash
workspace smoke
workspace task-list
workspace workflow-run --title "..." --request "..."
```

Unified D3 metrics:

```bash
workspace metrics
workspace metrics --date 2026-08-29
workspace metrics --task-id TASK-20260829-0001 --task-id TASK-20260829-0002
```

The metrics snapshot uses one exact task scope across Verified Task Success, first-pass success, token/resource cost, Evidence Coverage and the Context Precision/Recall proxies. See `docs/D3_METRICS.md` for formulas and limitations.

High-assurance wrappers:

```bash
workspace-secure smoke
workspace-public task-create --title "Public research" --request "Public-only question..."
```

Temporary compatibility aliases remain: `three-agent`, `three-agent-chat`.

Configuration prefers:

```bash
export WORKSPACE_CONFIG=config/workspace.secure.json
```

## Secure Ubuntu deployment

For the dual-RTX5090 workstation with an existing healthy NVIDIA driver/local Ollama stack:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_workspace_secure.sh | bash
```

For enterprise rollout, pin `WORKSPACE_REPO_REF` to a reviewed exact commit SHA rather than trusting moving `main`.

If the package is already installed, install only the OS boundary:

```bash
sudo WORKSPACE_INSTALL_DIR=/opt/workspace bash scripts/install_workspace_secure_boundary.sh
```

## CI runner pool

`scripts/setup_runner_pool.sh` registers a pool of GitHub Actions self-hosted runner
instances on the workstation, split into a `general` lane (lightweight lint/test CI,
parallel-safe) and an exclusive `gpu` lane (live-Ollama/benchmark CI, always serialized).
See `docs/WORKSPACE_RUNNER_POOL.md`.

## Current capability model

WorkSpace grows by **capabilities and reviewed skills**, not by adding a fixed number of agents. Current areas include research/evidence synthesis, data quality, presentation/report generation, daily reporting, coding/software-development guidance, language quality, local file/Office/PDF safety, skill approval, model/resource routing, dual RTX 5090 scheduling and deterministic citation/evidence validation.

For the planned network/cybersecurity analyst subsystem, see `docs/SECURITY_ANALYST_HACKINGTOOL_DISTILLATION.md`. It defines the WorkSpace-native integration of closed security taxonomy, approved capability registry, curated-first runbooks, evidence-only analyst reasoning, continuous monitoring/correlation, bounded active diagnostics and tool promotion gates without vendoring a general offensive toolkit runtime.

## Repository transition

The repository is still hosted as `caotiensinh/3agent` so existing installation URLs keep working. **WorkSpace** is the product name from this release onward. Repository/module renaming should be a separate migration after deployment URLs/services are updated deliberately.
