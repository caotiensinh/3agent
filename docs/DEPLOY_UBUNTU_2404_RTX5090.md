# Ubuntu 24.04.4 + 2× RTX 5090 One-Command Deployment

## Target

- Ubuntu 24.04.4 LTS
- x86_64
- at least 2× NVIDIA GeForce RTX 5090
- sudo-capable local user
- Internet access to Ubuntu repositories, GitHub and ollama.com
- test workstation policy (`TEST_MODE_FULL_ACCESS=true`)

## One command

Run as the normal user that should own the 3Agent checkout:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/install_ubuntu_2404_rtx5090.sh | bash
```

The default model is `qwen3:30b`. Override it without editing the script:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/install_ubuntu_2404_rtx5090.sh | THREE_AGENT_MODEL='<model>' bash
```

## What the installer does

1. Requires Ubuntu 24.04.4 by default.
2. Installs base packages.
3. Preserves an already healthy NVIDIA driver.
4. If no healthy NVIDIA driver exists, installs the newest available Ubuntu `nvidia-driver-*-open` package at or above branch 570.
5. If a new driver needs a reboot, installs a one-shot systemd resume unit and continues automatically after reboot.
6. Requires at least two visible RTX 5090 GPUs after driver setup.
7. Installs and enables Ollama.
8. Pins Ollama to the two RTX 5090 GPU UUIDs with `CUDA_VISIBLE_DEVICES`.
9. Clones or fast-forwards `caotiensinh/3agent` into `~/3agent`.
10. Creates `.venv`, installs `three-agent`, and writes `config/local.json`.
11. Pulls the selected local model.
12. Installs `/usr/local/bin/3agent`.
13. Runs harness smoke tests and a live Ollama generation request.

## Important safety behavior

The installer does not replace a working NVIDIA driver merely because a newer one exists. This prevents an ordinary application deployment from unnecessarily mutating a known-good GPU stack.

If Secure Boot is enabled and the NVIDIA driver is not already working, unattended deployment stops rather than trying to bypass Secure Boot or MOK enrollment.

The full-access setting applies only to the designated test workstation.

## Useful overrides

```bash
THREE_AGENT_MODEL='qwen3:30b'
THREE_AGENT_INSTALL_DIR="$HOME/3agent"
THREE_AGENT_AUTO_REBOOT=1
THREE_AGENT_STRICT_POINT_RELEASE=1
THREE_AGENT_MIN_DRIVER_MAJOR=570
THREE_AGENT_REQUIRED_RTX5090_COUNT=2
OLLAMA_CONTEXT_LENGTH=32768
```

To allow another Ubuntu 24.04.x point release:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/install_ubuntu_2404_rtx5090.sh \
  | THREE_AGENT_STRICT_POINT_RELEASE=0 bash
```

## After installation

```bash
3agent smoke
3agent task-list
nvidia-smi
systemctl status ollama --no-pager
```

Runtime installation log:

```text
/var/lib/3agent-bootstrap/install.log
```

## GitHub Actions deployment

The repository also contains `.github/workflows/deploy-rtx5090.yml`.

A deployment runner must be registered on the test PC with these labels:

```text
self-hosted
Linux
X64
rtx5090
```

The runner account must be allowed to run the installer-required `sudo` commands non-interactively. The workflow is manually dispatched and requires the input `confirm=DEPLOY`.

Note: if the workflow itself installs a missing GPU driver and reboots the runner host, the initial Actions job will be interrupted by that reboot. The machine-level systemd resume service still completes the one-command bootstrap, but a new workflow run is needed if GitHub itself must record a final post-reboot deployment PASS. For the cleanest CI deployment, preinstall a working NVIDIA driver on the self-hosted runner PC.

## CI scope

Hosted GitHub runners do not have two RTX 5090 GPUs, so `installer-ci` validates:

- Bash syntax
- ShellCheck
- installer contract/self-test
- existing Python harness tests
- harness smoke

Actual dual-GPU verification is performed on the target PC by `scripts/verify_deployment.sh` or by the self-hosted deployment workflow.
