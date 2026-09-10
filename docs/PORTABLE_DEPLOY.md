# Portable one-command deployment

WorkSpace provides three deployment/update layers:

- `scripts/deploy_ubuntu_pc.sh` is the preferred user-facing one-command entrypoint for validated Ubuntu PCs.
- `scripts/update_workspace_ubuntu.sh` is the reviewed Ubuntu update coordinator for an already installed real Ubuntu PC.
- `scripts/bootstrap.sh` and `scripts/update_code_safe.sh` are the canonical deployment/update primitives used underneath those entrypoints.

None of these paths changes the NVIDIA driver, kernel, bootloader, or reboot policy.

## Ubuntu PC: preferred one-command deployment

Run this command as the normal Ubuntu user. Do not prefix it with `sudo`; the underlying bootstrap requests sudo only when normal system packages must be installed.

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh | bash
```

This convenience command treats the initial download from mutable `main` as an explicit bootstrap trust decision. For a reviewed/high-assurance installation, download the deployment entrypoint and bootstrap from the same reviewed tag or exact commit SHA instead of mutable `main`.

Validated Ubuntu releases:

- Ubuntu 22.04
- Ubuntu 24.04

Default installation path:

```text
~/3agent
```

The Ubuntu entrypoint validates the host, delegates installation to the canonical bootstrap, verifies the installed command and configuration, runs a final smoke check, and reports the exact installed Git commit when available. After bootstrap verification succeeds, it replaces the bootstrap convenience updater with a trusted local Ubuntu update payload copied from that exact installed checkout.

## What the canonical bootstrap does

The delegated `scripts/bootstrap.sh` performs the following actions:

1. installs basic prerequisites when `apt`, `dnf`, or `yum` is available;
2. verifies Linux and Python >=3.11;
3. clones or updates `https://github.com/caotiensinh/3agent.git`;
4. resolves the requested Git ref and checks out the exact fetched commit;
5. creates an isolated `.venv`;
6. installs the project and dependencies;
7. creates `config/local.json` when missing and preserves an existing config;
8. installs user launchers under `~/.local/bin`;
9. runs compile, unit-test, and smoke validation before reporting PASS.

For the validated Ubuntu PC entrypoint, the final `3agent-update` launcher is installed only after that bootstrap has returned successfully and is rebound to the trusted local `3agent-update.sh` copied from the exact installed checkout.

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

Preferred enterprise update command after a successful installation:

```bash
~/.local/bin/3agent-update
```

Run it as the normal Ubuntu user, not with `sudo`.

### Trusted installed update boundary

The installed `3agent-update` launcher does **not** download a script from `main`, another branch, or a tag before execution. It invokes the local `~/.local/bin/3agent-update.sh` payload. That payload was copied from an exact checkout that already passed deployment/update verification.

The configured tracking ref (`main` by default, or an operator-selected branch/tag/SHA) remains data used by that already-trusted local coordinator. For each update attempt the coordinator:

1. resolves the tracking ref to an exact `expected` SHA;
2. downloads `update_code_safe.sh` from that exact SHA;
3. invokes the inner updater with `THREE_AGENT_REPO_REF=expected`, never the moving tracking ref;
4. permits that attempt to create/verify/activate only `expected`;
5. resolves the tracking ref again after activation;
6. starts a new outer attempt if the ref moved; and
7. reports FINAL PASS only when the exact attempted SHA, active SHA, and current tracking-ref SHA converge.

This means a ref move A -> B cannot cause B to become active inside the attempt that was pinned to A. B can be considered only by a subsequent outer attempt.

Each verified immutable release refreshes the trusted local updater payload from that exact release before the installed launcher is rewritten. The launcher preserves the configured tracking ref but contains no `curl`, remote URL, pipe-to-shell, or mutable bootstrap execution primitive.

The update path also preserves `config/local.json`, the legacy install, prior releases, and append-only activation history. It does not use `git pull`, `git reset --hard`, `git clean`, `rsync --delete`, or destructive release cleanup.

For deeper local verification before activation:

```bash
THREE_AGENT_UPDATE_VERIFY=full ~/.local/bin/3agent-update
```

### Recovery or reviewed direct invocation

If the installed trusted updater is missing or damaged, do not recover by executing mutable `main` directly in a high-assurance environment. Pin a reviewed exact commit SHA and execute that reviewed file explicitly:

```bash
Ref='<reviewed-commit-sha>'
Updater="$HOME/.cache/3agent-update-$Ref.sh"
mkdir -p "$(dirname "$Updater")"
curl -fsSL "https://raw.githubusercontent.com/caotiensinh/3agent/$Ref/scripts/update_workspace_ubuntu.sh" -o "$Updater"
bash -n "$Updater"
THREE_AGENT_REPO_REF="$Ref" bash "$Updater"
```

The exact-SHA recovery command is a separate operator trust decision. Routine updates should use the installed trusted updater.

## Pin a reviewed branch, tag, or commit

Deployment:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh \
  | THREE_AGENT_REPO_REF=<branch-tag-or-sha> bash
```

For high-assurance deployment, pin the **downloaded deployment entrypoint itself** to the same reviewed tag/SHA instead of leaving the first URL on `main`.

After deployment, routine update remains:

```bash
~/.local/bin/3agent-update
```

The installed launcher preserves the configured branch/tag/SHA as its tracking ref while entering only through trusted local code.

For repeated fleet deployment, pin a reviewed tag or commit rather than relying on a moving branch.

## Custom user-writable installation path

Deployment:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/deploy_ubuntu_pc.sh \
  | THREE_AGENT_INSTALL_DIR="$HOME/workspace-3agent" \
    THREE_AGENT_BIN_DIR="$HOME/.local/bin" \
    bash
```

Use the same path variables for later updates. The generated trusted updater launcher retains the configured install, bin, configuration, release, state, and activation-log paths.

The target directory must be writable by the deploying user.

## Generic Linux fallback

For a non-Ubuntu Linux host, use the canonical portable bootstrap directly:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh | bash
```

The generic bootstrap supports Linux with Python >=3.11 and can install normal prerequisites through `apt`, `dnf`, or `yum`. The stricter trusted-installed-updater guarantees in this document are acceptance-tested for the validated Ubuntu PC path.

## GPU/runtime boundary

The portable Ubuntu deployment and update entrypoints deliberately do not install or change NVIDIA drivers, kernel packages, bootloader settings, or reboot policy.

For a dedicated Ubuntu 24.04 + dual RTX 5090 workstation where GPU/runtime configuration is also required, use the separately reviewed `scripts/setup_ai_stack_ubuntu2404.sh` workflow.

## CI acceptance

`.github/workflows/portable-deploy-ci.yml` validates:

- Bash syntax and ShellCheck;
- bootstrap, Ubuntu deployment, safe updater, and real-Ubuntu updater contract checks;
- deterministic moving-ref A -> B regression proving B cannot activate inside the A attempt;
- the exact `deploy_ubuntu_pc.sh` file downloaded from raw GitHub by commit SHA;
- a clean deployment from GitHub;
- exact installed-source commit lineage;
- installed `3agent smoke`;
- identity of local `3agent-update.sh` against the exact installed checkout;
- absence of URL/`curl`/pipe-to-shell primitives in the installed `3agent-update` launcher;
- execution of the installed trusted updater itself, including configuration preservation and activation-lineage verification;
- trusted-updater refresh after update;
- a second idempotent deployment without restoring a mutable remote updater entrypoint;
- preservation of existing configuration and operator-local sentinels;
- Ubuntu 22.04 with Python 3.11; and
- Ubuntu 24.04 with Python 3.12.

The updater itself also performs post-activation source-lineage checks on the real PC before reporting FINAL PASS.
