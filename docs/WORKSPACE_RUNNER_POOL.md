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

## Setting it up — one command

The script resolves the current linux-x64 runner release from GitHub's own public API
at run time (never a version/URL hardcoded by this repo) and mints its own short-lived
registration token via the GitHub API from a Personal Access Token, instead of asking
you to open the Runners UI page and copy/paste three values by hand.

1. Create a classic PAT with `repo` scope (or a fine-grained PAT with this repo's
   **Administration: read and write** permission — that is what grants
   `actions/runners/registration-token`) at
   <https://github.com/settings/tokens>. It is used once, over HTTPS, only to mint a
   registration token; the script never writes it to disk.

2. On `aiserver`, from the repository checkout:

   ```bash
   GH_PAT='<your PAT>' scripts/setup_runner_pool.sh
   ```

   Leaving `GH_PAT` unset also works — the script prompts for it once with a hidden
   (`read -s`) input instead of taking it as a command-line argument, so it never ends up
   in shell history or `ps` output.

   Defaults to 7 `general` + 1 `gpu` instance under `~/actions-runner-pool/`. Override
   with `--general-count`/`--gpu-count` (or `RUNNER_POOL_GENERAL_COUNT`/
   `RUNNER_POOL_GPU_COUNT`). If this machine already has a runner registered at
   `~/actions-runner` (as `aiserver` did before this pool existed), fold it into the
   general lane instead of leaving it unlabeled:

   ```bash
   GH_PAT='<your PAT>' scripts/setup_runner_pool.sh --adopt-existing
   ```

   The runner tarball is downloaded once and reused for every instance (`avoid > reuse`,
   not 8 redundant downloads). Each instance becomes its own systemd service via the
   runner's own `svc.sh install`, so it survives terminal closes and reboots — unlike
   running `./run.sh` by hand in a foreground terminal (which is the most likely reason
   a manually-started runner stops responding to queued jobs after the terminal or SSH
   session closes).

   Prefer to audit every value before anything runs? The fully manual path still works
   and never reads `GH_PAT`: pass `--token`, `--tarball-url` and `--tarball-sha256`,
   copied from this repo's **Settings → Actions → Runners → New self-hosted runner**
   page.

3. Verify: **Settings → Actions → Runners** should list `aiserver-general-1` .. `-7` and
   `aiserver-gpu-1` (plus `aiserver-general-existing` if you used `--adopt-existing`),
   all idle/online.

4. Point workflow files at the right lane:

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
