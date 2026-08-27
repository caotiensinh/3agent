# Portable one-command deployment

The portable deployment path installs the 3Agent application directly from GitHub on a supported Linux host without touching the NVIDIA driver, kernel, bootloader, or reboot policy.

## One command

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh | bash
```

The bootstrap performs the following actions:

1. installs basic prerequisites when `apt`, `dnf`, or `yum` is available;
2. verifies Linux and Python >=3.11;
3. clones or updates `https://github.com/caotiensinh/3agent.git`;
4. resolves the requested Git ref and checks out the exact fetched commit;
5. creates an isolated `.venv`;
6. installs the project and dependencies;
7. creates `config/local.json` when missing and preserves an existing config;
8. installs user launchers `~/.local/bin/3agent` and `~/.local/bin/3agent-update`;
9. runs compile, unit-test, and smoke validation before reporting PASS.

Default installation path:

```text
~/3agent
```

## Full local-AI bootstrap

The portable installer does not download a large model unless explicitly requested. To also install Ollama and pull a model:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh \
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

## Pin a branch, tag, or commit

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh \
  | THREE_AGENT_REPO_REF=<branch-tag-or-sha> bash
```

For repeated fleet deployment, pin a reviewed tag or commit rather than relying on a moving branch.

## Custom installation path

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh \
  | THREE_AGENT_INSTALL_DIR=/opt/3agent \
    THREE_AGENT_BIN_DIR=$HOME/.local/bin \
    bash
```

The target directory must be writable by the deploying user.

## Supported host contract

Portable bootstrap currently supports Linux. The application requires Python >=3.11. The script can install normal prerequisites through `apt`, `dnf`, or `yum`, but it deliberately does not install or change NVIDIA drivers.

For the dedicated Ubuntu 24.04 + dual RTX 5090 workstation, use `scripts/setup_ai_stack_ubuntu2404.sh` when GPU/runtime configuration is also required.

## CI acceptance

`.github/workflows/portable-deploy-ci.yml` validates:

- Bash syntax;
- ShellCheck;
- bootstrap contract checks;
- a clean deployment that fetches source from GitHub;
- exact source commit lineage;
- installed `3agent smoke`;
- a second idempotent deployment;
- preservation of existing configuration;
- Ubuntu 22.04 with Python 3.11 and Ubuntu 24.04 with Python 3.12.
