# Windows 10/11 One-Command Deployment

## Supported scope

The Windows installer installs or updates the WorkSpace/3Agent application directly from GitHub while delegating platform installation logic to the canonical `scripts/bootstrap.ps1` implementation.

Supported baseline:

- Windows 10 or Windows 11 x64;
- Windows PowerShell 5.1 or PowerShell 7;
- Internet access to GitHub and Python package indexes;
- WinGet when Git or Python must be installed automatically.

Python 3.11 or newer is required. When Python is missing, the bootstrap installs `Python.Python.3.12` through WinGet. When Git is missing, it installs `Git.Git`.

The portable Windows path never installs, removes, upgrades, disables, or reloads NVIDIA drivers. It also never changes boot configuration and never reboots or shuts down the PC.

## Initial bootstrap

The root `install.ps1` file is the canonical user-facing trust shim. It downloads the reviewed platform bootstrap for the selected source ref and then delegates all installation work to `scripts/bootstrap.ps1`. The root file intentionally contains no clone, package-install, virtualenv, or application-install implementation of its own.

Convenience command for the current `main` head:

```powershell
irm https://raw.githubusercontent.com/caotiensinh/3agent/main/install.ps1 | iex
```

Equivalent command from `cmd.exe` or Run:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/caotiensinh/3agent/main/install.ps1' | iex"
```

This convenience command treats the initial download from mutable `main` as an explicit trust decision.

For a reviewed/high-assurance installation, pin both the root installer source and repository target to the same reviewed commit SHA:

```powershell
$Ref='<reviewed-commit-sha>'
$env:WORKSPACE_SOURCE_REF=$Ref
$env:THREE_AGENT_REPO_REF=$Ref
$Installer="$env:TEMP\workspace-install-$Ref.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/caotiensinh/3agent/$Ref/install.ps1" -OutFile $Installer
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

Optional bootstrap-payload checksum verification is available when an operator has a separately reviewed SHA-256 value:

```powershell
$env:WORKSPACE_INSTALLER_SHA256='<sha256-of-scripts-bootstrap-ps1-at-the-selected-source-ref>'
```

The root installer then fetches the canonical platform bootstrap from the selected `WORKSPACE_SOURCE_REF`. The bootstrap fetches the application repository directly from:

```text
https://github.com/caotiensinh/3agent.git
```

The fetched Git ref is resolved to an exact commit SHA and checked out detached before installation and validation.

## What the bootstrap does

1. Confirms Windows.
2. Detects Git and Python >=3.11.
3. Uses WinGet to install missing Git/Python when permitted.
4. Clones or fetches `caotiensinh/3agent` from GitHub.
5. Checks out the exact fetched commit.
6. Preserves `config/local.json` and `data/` across updates.
7. Creates `~/3agent/.venv`.
8. Installs the project and dependencies into the venv.
9. Creates `config/local.json` on first install.
10. Installs `3agent.cmd`, `3agent-update.cmd`, and the trusted local `3agent-update.ps1` under `%LOCALAPPDATA%\3agent\bin`.
11. Copies `3agent-update.ps1` from `scripts/bootstrap.ps1` in the exact detached checkout that was just installed.
12. Adds the bin directory to the current and user PATH.
13. Runs Python compile checks, the full unit suite, and `3agent smoke`.
14. Reports `FINAL PASS` only after validation succeeds.

## Daily commands

```powershell
3agent smoke
3agent task-list
```

Update the installation from the same configured GitHub ref:

```powershell
3agent-update
```

### Trusted installed update path

`3agent-update` does **not** download and execute `scripts/bootstrap.ps1` from mutable `main` as its entrypoint. The installed command invokes the local `%LOCALAPPDATA%\3agent\bin\3agent-update.ps1` with PowerShell `-File`. That local updater payload was copied from the exact detached checkout that passed installation validation.

The trusted local updater then performs the normal Git fetch/resolve/checkout flow for the configured `THREE_AGENT_REPO_REF`. After a successful deployment, the local updater payload is refreshed from the newly installed exact checkout. This keeps the entrypoint inside the previously installed trust boundary while preserving the configured target ref.

The update path is idempotent and preserves local configuration and runtime data. If the configured ref is an exact commit SHA, routine updates remain pinned to that SHA until the operator explicitly changes the ref.

## Optional Ollama and local model

Ollama is not installed by default on every Windows machine. To install Ollama and pull a model during an initial convenience bootstrap:

```powershell
$env:THREE_AGENT_INSTALL_OLLAMA='1'; $env:THREE_AGENT_MODEL='qwen3:30b'; $env:THREE_AGENT_PULL_MODEL='1'; irm https://raw.githubusercontent.com/caotiensinh/3agent/main/install.ps1 | iex
```

Choose a model that fits the target machine. The bootstrap uses Ollama's official Windows PowerShell installer when Ollama installation is explicitly requested. For a reviewed/high-assurance installation, combine the same model environment variables with the exact-SHA root-installer procedure above.

## Overrides

```powershell
$env:WORKSPACE_SOURCE_REF='main'
$env:THREE_AGENT_REPO_REF='main'
$env:THREE_AGENT_INSTALL_DIR="$HOME\3agent"
$env:THREE_AGENT_BIN_DIR="$env:LOCALAPPDATA\3agent\bin"
$env:THREE_AGENT_CONFIG_PATH="$HOME\3agent\config\local.json"
$env:THREE_AGENT_SKIP_SYSTEM_PACKAGES='0'
```

A branch, tag, or exact SHA may be used as `THREE_AGENT_REPO_REF`. `WORKSPACE_SOURCE_REF` selects the root installer's reviewed bootstrap source independently. In high-assurance deployment, pin both to the same exact reviewed SHA.

## Existing installation safety

If the repository contains tracked local modifications, deployment stops instead of overwriting them.

The bootstrap intentionally cleans generated/untracked repository files while excluding:

```text
config/local.json
data/
```

This keeps the application source reproducible while preserving local state.

## CI acceptance

`.github/workflows/windows-deploy-ci.yml` validates the Windows path on GitHub-hosted Windows runners.

The CI matrix tests Python 3.11 and 3.12 and performs:

- Windows PowerShell 5.1 root-installer and bootstrap contract checks;
- PowerShell 7 root-installer and bootstrap contract checks;
- download of the root `install.ps1` from `raw.githubusercontent.com` using the exact candidate SHA;
- delegation from that root entrypoint to the exact candidate `scripts/bootstrap.ps1`;
- GitHub repository fetch by the delegated bootstrap;
- exact installed source SHA verification;
- verification that `3agent-update.cmd` contains no remote-download/`iex` entrypoint and invokes the local trusted updater with `-File`;
- verification that installed `3agent-update.ps1` is byte-equivalent by SHA-256 to `scripts/bootstrap.ps1` from the exact installed checkout;
- venv/dependency installation;
- full unit tests;
- `3agent smoke`;
- second deployment through the installed `3agent-update.cmd` trusted path;
- exact installed SHA verification after the updater re-run;
- configuration SHA preservation across the updater re-run; and
- verification that the trusted local updater is refreshed from the resulting exact checkout.

This CI proves portable application installation and the installed updater trust boundary through the same root one-command entrypoint offered to users. Automatic WorkSpace Chat/UI startup and product readiness checks are separate acceptance gates and are not implied by this installer proof. Physical GPU/Ollama acceptance remains a target-machine responsibility when local AI is enabled.
