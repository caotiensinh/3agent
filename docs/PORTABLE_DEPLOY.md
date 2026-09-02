# Portable one-command deployment

WorkSpace provides two deployment layers:

- `scripts/deploy_ubuntu_pc.sh` is the preferred user-facing one-command entrypoint for validated Ubuntu PCs.
- `scripts/bootstrap.sh` remains the canonical portable deployment primitive used by the Ubuntu entrypoint and by generic Linux deployment.

Neither path changes the NVIDIA driver, kernel, bootloader, or reboot policy.

## Ubuntu PC: preferred one-command deployment

Run this command as the normal Ubuntu user. Do not prefix it with `sudo`; the underlying bootstrap requests sudo only when normal system packages must be installed.

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh | bash
```

Validated Ubuntu releases:

- Ubuntu 22.04
- Ubuntu 24.04

Default installation path:

```text
~/3agent
```

The Ubuntu entrypoint validates the host, delegates installation to the canonical bootstrap, verifies the installed command and configuration, runs a final smoke check, and reports the exact installed Git commit when available.

## What the canonical bootstrap does

The delegated `scripts/bootstrap.sh` performs the following actions:

1. installs basic prerequisites when `apt`, `dnf`, or `yum` is available;
2. verifies Linux and Python >=3.11;
3. clones or updates `https://github.com/caotiensinh/3agent.git`;
4. resolves the requested Git ref and checks out the exact fetched commit;
5. creates an isolated `.venv`;
6. installs the project and dependencies;
7. creates `config/local.json` when missing and preserves an existing config;
8. installs user launchers `~/.local/bin/3agent` and `~/.local/bin/3agent-update`;
9. runs compile, unit-test, and smoke validation before reporting PASS.

## Full local-AI bootstrap

The default Ubuntu deployment does not download a large model. To also install Ollama and pull a selected model:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh \
  | THREE_AGENT_INSTALL_OLLAMA=1 \
    THREE_AGENT_MODEL=qwen3:30b \
    THREE_AGENT_PULL_MODEL=1 \
    bash
```

Choose a model appropriate for the host. `qwen3:30b` is intended for a capable AI workstation and should not be assumed to fit every PC.

## Update

After installation:

```bash
~/.local/bin/3agent-update
```

The updater fetches the configured repository/ref again and re-runs the same idempotent deployment path. Existing `config/local.json` and `data/` are preserved.

## Pin a reviewed branch, tag, or commit

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh \
  | THREE_AGENT_REPO_REF=<branch-tag-or-sha> bash
```

For repeated fleet deployment, pin a reviewed tag or commit rather than relying on a moving branch.

## Custom user-writable installation path

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh \
  | THREE_AGENT_INSTALL_DIR="$HOME/workspace-3agent" \
    THREE_AGENT_BIN_DIR="$HOME/.local/bin" \
    bash
```

The target directory must be writable by the deploying user.

## Generic Linux fallback

For a non-Ubuntu Linux host, use the canonical portable bootstrap directly:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh | bash
```

The generic bootstrap supports Linux with Python >=3.11 and can install normal prerequisites through `apt`, `dnf`, or `yum`.

## GPU/runtime boundary

The portable Ubuntu entrypoint deliberately does not install or change NVIDIA drivers, kernel packages, bootloader settings, or reboot policy.

For a dedicated Ubuntu 24.04 + dual RTX 5090 workstation where GPU/runtime configuration is also required, use the separately reviewed `scripts/setup_ai_stack_ubuntu2404.sh` workflow.

## CI acceptance

`.github/workflows/portable-deploy-ci.yml` validates:

- Bash syntax;
- ShellCheck;
- bootstrap and Ubuntu-entrypoint contract checks;
- the exact `deploy_ubuntu_pc.sh` file downloaded from raw GitHub by commit SHA;
- a clean deployment from GitHub;
- exact installed-source commit lineage;
- installed `3agent smoke`;
- a second idempotent deployment;
- preservation of existing configuration;
- Ubuntu 22.04 with Python 3.11;
- Ubuntu 24.04 with Python 3.12.
