# Windows 10/11 One-Command Deployment

## Supported scope

The Windows bootstrap installs or updates the 3Agent application directly from GitHub.

Supported baseline:

- Windows 10 or Windows 11 x64;
- Windows PowerShell 5.1 or PowerShell 7;
- Internet access to GitHub and Python package indexes;
- WinGet when Git or Python must be installed automatically.

Python 3.11 or newer is required. When Python is missing, the bootstrap installs `Python.Python.3.12` through WinGet. When Git is missing, it installs `Git.Git`.

The portable Windows bootstrap never installs, removes, upgrades, disables, or reloads NVIDIA drivers. It also never changes boot configuration and never reboots or shuts down the PC.

## Initial bootstrap

The first bootstrap is a separate trust boundary from routine installed updates. The convenience command below downloads the current `main` bootstrap and therefore should only be used when the operator intends to trust the repository's current `main` head:

```powershell
irm https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.ps1 | iex
```

Equivalent command from `cmd.exe` or Run:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.ps1' | iex"
```

For a reviewed/high-assurance installation, pin both the bootstrap source and repository target to the same reviewed commit SHA instead of a mutable branch:

```powershell
$Ref='<reviewed-commit-sha>'
$env:THREE_AGENT_REPO_REF=$Ref
$Bootstrap="$env:TEMP\3agent-bootstrap-$Ref.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/caotiensinh/3agent/$Ref/scripts/bootstrap.ps1" -OutFile $Bootstrap
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Bootstrap
```

The bootstrap then fetches the application repository directly from:

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
$env:THREE_AGENT_INSTALL_OLLAMA='1'; $env:THREE_AGENT_MODEL='qwen3:30b'; $env:THREE_AGENT_PULL_MODEL='1'; irm https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.ps1 | iex
```

Choose a model that fits the target machine. The bootstrap uses Ollama's official Windows PowerShell installer when Ollama installation is explicitly requested. For a reviewed/high-assurance installation, combine the same model environment variables with the exact-SHA bootstrap procedure above.

## Overrides

```powershell
$env:THREE_AGENT_REPO_REF='main'
$env:THREE_AGENT_INSTALL_DIR="$HOME\3agent"
$env:THREE_AGENT_BIN_DIR="$env:LOCALAPPDATA\3agent\bin"
$env:THREE_AGENT_CONFIG_PATH="$HOME\3agent\config\local.json"
$env:THREE_AGENT_SKIP_SYSTEM_PACKAGES='0'
```

A branch, tag, or exact SHA may be used as `THREE_AGENT_REPO_REF`. Use an exact reviewed SHA when the deployment requires immutable source selection.

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

- Windows PowerShell 5.1 parsing/contract checks;
- PowerShell 7 parsing/contract checks;
- download of the initial `bootstrap.ps1` from `raw.githubusercontent.com` using the exact candidate SHA;
- GitHub repository fetch by the downloaded bootstrap;
- exact installed source SHA verification;
- verification that `3agent-update.cmd` contains no remote-download/`iex` entrypoint and invokes the local trusted updater with `-File`;
- verification that installed `3agent-update.ps1` is byte-equivalent by SHA-256 to `scripts/bootstrap.ps1` from the exact installed checkout;
- venv/dependency installation;
- full unit tests;
- `3agent smoke`;
- second deployment through the installed `3agent-update.cmd` trusted path;
- exact installed SHA verification after the updater re-run;
- configuration SHA preservation across the updater re-run;
- verification that the trusted local updater is refreshed from the resulting exact checkout.

This CI tests portable application installation and the installed updater trust boundary. Physical GPU/Ollama acceptance remains a target-machine responsibility when local AI is enabled.
