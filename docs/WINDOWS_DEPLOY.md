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

## One command

From PowerShell:

```powershell
irm https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.ps1 | iex
```

Equivalent command from `cmd.exe` or Run:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.ps1' | iex"
```

The bootstrap itself then fetches the application repository directly from:

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
10. Installs `3agent.cmd` and `3agent-update.cmd` under `%LOCALAPPDATA%\3agent\bin`.
11. Adds that bin directory to the current and user PATH.
12. Runs Python compile checks, the full unit suite, and `3agent smoke`.
13. Reports `FINAL PASS` only after validation succeeds.

## Daily commands

```powershell
3agent smoke
3agent task-list
```

Update the installation from the same configured GitHub ref:

```powershell
3agent-update
```

The update path is idempotent and preserves local configuration and runtime data.

## Optional Ollama and local model

Ollama is not installed by default on every Windows machine. To install Ollama and pull a model in the same PowerShell command:

```powershell
$env:THREE_AGENT_INSTALL_OLLAMA='1'; $env:THREE_AGENT_MODEL='qwen3:30b'; $env:THREE_AGENT_PULL_MODEL='1'; irm https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.ps1 | iex
```

Choose a model that fits the target machine. The bootstrap uses Ollama's official Windows PowerShell installer when Ollama installation is explicitly requested.

## Overrides

```powershell
$env:THREE_AGENT_REPO_REF='main'
$env:THREE_AGENT_INSTALL_DIR="$HOME\3agent"
$env:THREE_AGENT_BIN_DIR="$env:LOCALAPPDATA\3agent\bin"
$env:THREE_AGENT_CONFIG_PATH="$HOME\3agent\config\local.json"
$env:THREE_AGENT_SKIP_SYSTEM_PACKAGES='0'
```

A branch, tag, or exact SHA may be used as `THREE_AGENT_REPO_REF`.

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
- download of `bootstrap.ps1` from `raw.githubusercontent.com` using the exact candidate SHA;
- GitHub repository fetch by the downloaded bootstrap;
- exact installed source SHA verification;
- venv/dependency installation;
- full unit tests;
- `3agent smoke`;
- second deployment from GitHub;
- configuration SHA preservation across the second deployment.

This CI tests portable application installation. Physical GPU/Ollama acceptance remains a target-machine responsibility when local AI is enabled.
