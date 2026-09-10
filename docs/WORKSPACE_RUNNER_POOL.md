# Self-hosted runner pool — two lanes on one machine

## Problem this solves

The dual-RTX5090 workstation (`aiserver`) has historically run as a single GitHub
Actions self-hosted runner. Every self-hosted CI job — including lightweight ones like
shellcheck or `python -m unittest` that never touch a GPU — queued behind whatever else
was using that one runner, serializing development throughput.

## Design: general lane + gpu lane, not "8 identical runners"

Registering 8 identical runners and letting GitHub Actions schedule freely across all of
them would let up to 8 GPU-bound jobs (live Ollama generation, benchmark closures) run
at once. On this exact host — 2× RTX 5090, **32GB system RAM** — that is not a
parallelism win, it is a way to get out-of-memory failures and, worse, to silently
corrupt every benchmark's resource measurement (`docs/D3_METRICS.md`,
`docs/WORKSPACE_DESIGN_PRINCIPLES.md` Principle 10: GPU/RAM numbers are only meaningful
if nothing else was contending for the same hardware while they were captured).

So the pool is split into two lanes with different concurrency rules:

| Lane | Default count | Labels | What runs here | Concurrency |
| --- | --- | --- | --- | --- |
| `general` | 7 | `self-hosted,general` | shellcheck, `bash -n`, the `test_*_contract.sh` suite, `python -m unittest` (no live Ollama calls), lint/packaging checks | Unrestricted — safe to run in parallel |
| `gpu` | 1 | `self-hosted,gpu` | `deploy-rtx5090.yml`, benchmark/closure workflows that call `ollama generate` or read `nvidia-smi` for evidence | Serialized via a shared `concurrency: group: gpu-rtx5090-exclusive` on every gpu-lane workflow |

The `gpu-rtx5090-exclusive` concurrency group is what actually enforces exclusivity —
not the runner count. Even if a future change adds a second `gpu`-labeled runner (one
per physical card), GitHub Actions queues a second gpu-lane job rather than starting it
concurrently, because both workflows share the same concurrency group. Add more `gpu`
runners only for failover, never to get real GPU parallelism, unless a workflow is
proven not to need clean-measurement isolation.

Most existing CI (`installer-ci.yml`'s `shellcheck-and-contracts` / `harness-regression`
jobs) already runs on GitHub-hosted `ubuntu-24.04` runners and does not need to move —
only workflows that were already `runs-on: [self-hosted, ...]` benefit from this pool.

## Setting it up — paste a key, nothing else

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_runner_pool.sh | bash
```

That is the entire interaction. It prompts once, with a hidden (`read -s`) input so the
key never lands in shell history or `ps` output:

```text
GitHub PAT (repo admin, used once to mint a registration token, never stored):
```

Paste the PAT and press Enter. Everything else is automatic:

- the current linux-x64 runner release is resolved from GitHub's own public API at run
  time — never a version/URL hardcoded by this repo;
- a registration token is minted via the GitHub API from the pasted PAT (used once, over
  HTTPS, never written to disk);
- if this machine already has a runner registered at `~/actions-runner` (as `aiserver`
  did before this pool existed), it is detected automatically and folded into the
  general lane in place — pass `--no-adopt-existing` to skip that;
- 7 `general` + 1 `gpu` instance are registered under `~/actions-runner-pool/`, each as
  its own systemd service (survives terminal closes and reboots — unlike running
  `./run.sh` by hand in a foreground terminal, which is the most likely reason a
  manually-started runner stops responding to queued jobs after the SSH session closes).

Where to get the PAT: <https://github.com/settings/tokens> → classic token with `repo`
scope (or a fine-grained PAT with this repo's **Administration: read and write**
permission — that is what grants `actions/runners/registration-token`).

To skip the prompt entirely (e.g. scripting it), export `GH_PAT` first:
`GH_PAT='<your PAT>' curl -fsSL .../setup_runner_pool.sh | bash`. To change the split,
add args after `--`: `... | bash -s -- --general-count=6 --gpu-count=2`.

Prefer to audit every value before anything runs, or don't want to paste a PAT at all?
The fully manual path still works and never reads `GH_PAT`: pass `--token`,
`--tarball-url` and `--tarball-sha256`, copied from this repo's **Settings → Actions →
Runners → New self-hosted runner** page.

Verify: **Settings → Actions → Runners** should list `aiserver-general-1` .. `-7` and
`aiserver-gpu-1` (plus `aiserver-general-existing` if an existing runner was adopted),
all idle/online.

Point workflow files at the right lane:

```yaml
runs-on: [self-hosted, general]   # lint/test/shellcheck work
```

```yaml
runs-on: [self-hosted, gpu]
concurrency:
  group: gpu-rtx5090-exclusive
  cancel-in-progress: false       # never cancel a job mid-inference/mid-benchmark
```

`deploy-rtx5090.yml` in this repo already uses the `gpu` lane and the shared
concurrency group.

## Removing the pool

```bash
GH_PAT='<your PAT>' scripts/setup_runner_pool.sh --teardown
```

Mints its own removal token the same way, stops and uninstalls each instance's systemd
service, deregisters it from GitHub, and removes its directory. Safe to re-run
`setup_runner_pool.sh` (without `--teardown`) afterward to rebuild the pool —
registration is idempotent per instance. `--token '<REMOVE_TOKEN>'` still works if you
prefer to paste it from the Runners page instead of using a PAT.

## What this does not change

- No security boundary, model, or context-budget behavior changes.
- GPU-bound workflows still run exactly one at a time — the pool adds throughput for
  the CI work that was never the bottleneck's actual cause (lint/test queueing), it does
  not add GPU throughput, and it should not.
