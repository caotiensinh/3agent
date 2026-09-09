# Portable one-command deployment

WorkSpace provides four deployment/update layers:

- root `install.sh` is the canonical user-facing one-command trust shim for validated Ubuntu PCs;
- `scripts/deploy_ubuntu_pc.sh` is the canonical Ubuntu deployment coordinator used by that shim;
- `scripts/update_workspace_ubuntu.sh` is the reviewed Ubuntu update coordinator for an already installed real Ubuntu PC; and
- `scripts/bootstrap.sh` plus `scripts/update_code_safe.sh` are the canonical deployment/update primitives used underneath those entrypoints.

The root `install.sh` intentionally contains no clone, package-install, virtualenv, or application-install implementation. It selects and validates a reviewed source ref, optionally verifies the downloaded deployment coordinator by SHA-256, and delegates to the existing canonical Ubuntu path.

None of these paths changes the NVIDIA driver, kernel, bootloader, or reboot policy.

## Ubuntu PC: preferred one-command deployment

Run this command as the normal Ubuntu user. Do not prefix it with `sudo`; the underlying bootstrap requests sudo only when normal system packages must be installed.

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/install.sh | bash
```

This convenience command treats the initial download from mutable `main` as an explicit bootstrap trust decision.

Validated Ubuntu releases:

- Ubuntu 22.04
- Ubuntu 24.04

Default installation path:

```text
~/3agent
```

The root installer downloads `scripts/deploy_ubuntu_pc.sh` from `WORKSPACE_SOURCE_REF` (defaulting to the configured tracking ref, normally `main`), validates Bash syntax, optionally verifies an operator-supplied SHA-256, and delegates deployment. The Ubuntu coordinator then validates the host, delegates installation to the canonical bootstrap, verifies the installed command and configuration, runs a final smoke check, and reports the exact installed Git commit when available. After bootstrap verification succeeds, it replaces the bootstrap convenience updater with a trusted local Ubuntu update payload copied from that exact installed checkout.

## Reviewed or exact-SHA bootstrap

For high-assurance installation, pin both the downloaded root installer and the repository target to the same reviewed commit SHA:

```bash
Ref='<reviewed-commit-sha>'
curl -fsSL "https://raw.githubusercontent.com/caotiensinh/3agent/$Ref/install.sh" \
  | WORKSPACE_SOURCE_REF="$Ref" THREE_AGENT_REPO_REF="$Ref" bash
```

If an operator has separately reviewed the SHA-256 of `scripts/deploy_ubuntu_pc.sh` at that source ref, it can be enforced with:

```bash
WORKSPACE_INSTALLER_SHA256='<sha256-of-scripts-deploy-ubuntu-pc-sh>'
```

`WORKSPACE_SOURCE_REF` controls the reviewed code used for the initial root delegation. `THREE_AGENT_REPO_REF` remains the branch, tag, or exact SHA the installation tracks. For immutable enterprise deployment, pin both to the same exact reviewed SHA.

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
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/install.sh \
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

## Track a reviewed branch or tag

A reviewed branch or tag can remain the update tracking ref while the initial root installer is pinned to a reviewed immutable source:

```bash
SourceRef='<reviewed-installer-commit-sha>'
TrackingRef='<branch-or-tag>'
curl -fsSL "https://raw.githubusercontent.com/caotiensinh/3agent/$SourceRef/install.sh" \
  | WORKSPACE_SOURCE_REF="$SourceRef" THREE_AGENT_REPO_REF="$TrackingRef" bash
```

For repeated fleet deployment, prefer an exact reviewed commit or release artifact when deterministic rollout matters more than automatically tracking a moving branch.

## Custom user-writable installation path

Deployment:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/install.sh \
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

The generic bootstrap supports Linux with Python >=3.11 and can install normal prerequisites through `apt`, `dnf`, or `yum`. The stricter root-entrypoint and trusted-installed-updater guarantees in this document are acceptance-tested for the validated Ubuntu PC path.

## GPU/runtime boundary

The portable Ubuntu deployment and update entrypoints deliberately do not install or change NVIDIA drivers, kernel packages, bootloader settings, or reboot policy.

For a dedicated Ubuntu 24.04 + dual RTX 5090 workstation where GPU/runtime configuration is also required, use the separately reviewed `scripts/setup_ai_stack_ubuntu2404.sh` workflow.

## CI acceptance

`.github/workflows/portable-deploy-ci.yml` validates:

- Bash syntax and ShellCheck for the root `install.sh` and canonical Ubuntu deployment files;
- the thin-entrypoint contract that rejects duplicate clone/package/venv installer logic in the root shim;
- bootstrap, Ubuntu deployment, safe updater, and real-Ubuntu updater contract checks;
- deterministic moving-ref A -> B regression proving B cannot activate inside the A attempt;
- the exact root `install.sh` file downloaded from raw GitHub by candidate commit SHA;
- delegation from that root entrypoint to `scripts/deploy_ubuntu_pc.sh` and the exact candidate `scripts/bootstrap.sh`;
- clean deployment from GitHub on Ubuntu 22.04/Python 3.11 and Ubuntu 24.04/Python 3.12;
- exact installed-source commit lineage;
- installed `3agent smoke`;
- identity of local `3agent-update.sh` against the exact installed checkout;
- absence of URL/`curl`/pipe-to-shell primitives in the installed `3agent-update` launcher;
- execution of the installed trusted updater itself, including configuration preservation and activation-lineage verification;
- trusted-updater refresh after update;
- ten repeated installed-updater executions with same-SHA idempotency checks; and
- a second root one-command deployment without restoring a mutable remote updater entrypoint while preserving existing configuration and operator-local sentinels.

This CI proves portable application installation and the installed updater trust boundary through the same root one-command entrypoint offered to users. Automatic WorkSpace Chat/UI startup and `/ready`/`/version` product checks remain separate acceptance gates and are not implied by this deployment proof.
