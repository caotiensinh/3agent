# Portable one-command deployment

WorkSpace provides three deployment/update layers:

- `scripts/deploy_ubuntu_pc.sh` is the preferred user-facing one-command entrypoint for validated Ubuntu PCs.
- `scripts/update_workspace_ubuntu.sh` is the preferred user-facing updater for an already installed real Ubuntu PC.
- `scripts/bootstrap.sh` and `scripts/update_code_safe.sh` are the canonical deployment/update primitives used underneath those entrypoints.

None of these paths changes the NVIDIA driver, kernel, bootloader, or reboot policy.

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

## Update an existing real Ubuntu PC

Preferred command:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/update_workspace_ubuntu.sh | bash
```

Run it as the normal Ubuntu user, not with `sudo`.

The real-PC updater:

1. accepts only validated Ubuntu 22.04/24.04 hosts;
2. verifies an existing WorkSpace installation before changing anything;
3. resolves the configured ref (`main` by default) to an exact Git commit;
4. downloads `update_code_safe.sh` from that exact commit rather than executing a moving-branch copy;
5. creates a new immutable release checkout and isolated virtual environment;
6. preserves `config/local.json`, the legacy install, prior releases, and append-only activation history;
7. compiles and smoke-tests the new release before activation;
8. verifies the active release SHA after activation;
9. resolves the remote ref again and retries safely when the ref moved during the update;
10. reports FINAL PASS only when the updater source SHA, active release SHA, and current target SHA are the same stable commit.

The updater does not use `git pull`, `git reset --hard`, `git clean`, `rsync --delete`, or destructive release cleanup.

For a deeper local verification before activation:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/update_workspace_ubuntu.sh \
  | THREE_AGENT_UPDATE_VERIFY=full bash
```

The installed convenience launcher remains available after deployment/update:

```bash
~/.local/bin/3agent-update
```

That launcher delegates to the same non-destructive immutable-release updater on its configured repository ref.

## Pin a reviewed branch, tag, or commit

Deployment:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh \
  | THREE_AGENT_REPO_REF=<branch-tag-or-sha> bash
```

Update:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/update_workspace_ubuntu.sh \
  | THREE_AGENT_REPO_REF=<branch-tag-or-sha> bash
```

For repeated fleet deployment, pin a reviewed tag or commit rather than relying on a moving branch.

## Custom user-writable installation path

Deployment:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh \
  | THREE_AGENT_INSTALL_DIR="$HOME/workspace-3agent" \
    THREE_AGENT_BIN_DIR="$HOME/.local/bin" \
    bash
```

Use the same path variables for later updates.

The target directory must be writable by the deploying user.

## Generic Linux fallback

For a non-Ubuntu Linux host, use the canonical portable bootstrap directly:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh | bash
```

The generic bootstrap supports Linux with Python >=3.11 and can install normal prerequisites through `apt`, `dnf`, or `yum`.

## GPU/runtime boundary

The portable Ubuntu deployment and update entrypoints deliberately do not install or change NVIDIA drivers, kernel packages, bootloader settings, or reboot policy.

For a dedicated Ubuntu 24.04 + dual RTX 5090 workstation where GPU/runtime configuration is also required, use the separately reviewed `scripts/setup_ai_stack_ubuntu2404.sh` workflow.

## CI acceptance

`.github/workflows/portable-deploy-ci.yml` validates:

- Bash syntax;
- ShellCheck;
- bootstrap, Ubuntu deployment, safe updater, and real-Ubuntu updater contract checks;
- the exact `deploy_ubuntu_pc.sh` file downloaded from raw GitHub by commit SHA;
- a clean deployment from GitHub;
- exact installed-source commit lineage;
- installed `3agent smoke`;
- a second idempotent deployment;
- preservation of existing configuration and operator-local sentinels;
- Ubuntu 22.04 with Python 3.11;
- Ubuntu 24.04 with Python 3.12.

The updater itself also performs post-activation source-lineage checks on the real PC before reporting FINAL PASS.
