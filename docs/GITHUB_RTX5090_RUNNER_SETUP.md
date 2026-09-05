# WorkSpace RTX5090 GitHub Runner — One-Time Setup

## Goal

Configure the Ubuntu 24.04 RTX5090 host once, then let GitHub Actions deliver benchmark jobs automatically through a persistent self-hosted runner service.

The operator should not run `./run.sh` manually after setup.

## Manual boundary

Only one GitHub UI action is intentionally manual when a new runner must be registered:

1. Open the `caotiensinh/3agent` repository.
2. Go to **Settings → Actions → Runners → New self-hosted runner**.
3. Copy the short-lived registration token.
4. Paste it into the script's hidden prompt.

Do not save the registration token in a file, shell script, issue, workflow variable, screenshot, or documentation.

## Automated setup

Download the script from the reviewed repository revision or use the checked-out repository copy:

```bash
sudo bash scripts/setup_github_rtx5090_runner.sh
```

If the configured benchmark model is missing and the operator explicitly wants the setup to pull it once:

```bash
sudo bash scripts/setup_github_rtx5090_runner.sh --pull-model
```

The script performs:

- Ubuntu/x86_64 preflight;
- RTX 5090 hardware verification;
- local Ollama API/model verification;
- creation/reuse of a dedicated `github-runner` user;
- `video`/`render` group membership when available;
- resolution of the latest official `actions/runner` Linux x64 release;
- verification using the SHA-256 digest published on the GitHub release asset;
- unattended runner registration using the one-time token;
- labels `rtx5090,workspace-benchmark`;
- persistent systemd service installation and enablement;
- runner-local service identity validation using `/opt/actions-runner/.service`;
- `needrestart` protection for running benchmark jobs;
- GPU and Ollama access checks under the runner OS identity.

The script does **not** install or modify:

- NVIDIA drivers;
- kernel packages;
- Docker;
- Redis/vector databases;
- WorkSpace production configuration;
- model servers other than optional `ollama pull MODEL` when `--pull-model` is explicitly used.

## Idempotency

Re-running the script preserves an already configured runner when the local registration identity matches the expected runner name/repository.

If `/opt/actions-runner` belongs to a different runner registration, setup fails closed instead of taking it over.

## Final browser check

After the script returns `READY`, open:

**Settings → Actions → Runners**

Expected state:

```text
workspace-rtx5090-01
Status: Idle
Labels: self-hosted, Linux, X64, rtx5090, workspace-benchmark
```

## Reboot check

Reboot the Ubuntu host once:

```bash
sudo reboot
```

Do not start `run.sh` after boot. The systemd service must reconnect automatically.

When the machine returns, the GitHub runner page should return to `Idle` without operator action.
