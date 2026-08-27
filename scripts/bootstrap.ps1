param(
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EnvOrDefault {
    param([string]$Name, [string]$Default)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Test-True {
    param([string]$Value)
    if ($null -eq $Value) { return $false }
    return @('1','true','yes','on') -contains $Value.ToLowerInvariant()
}

function Write-Log { param([string]$Message) Write-Host "[3Agent] $Message" }
function Write-Warn { param([string]$Message) Write-Warning "[3Agent] $Message" }
function Stop-Deploy { param([string]$Message) throw "[3Agent][ERROR] $Message" }

$RepoUrl = Get-EnvOrDefault 'THREE_AGENT_REPO_URL' 'https://github.com/caotiensinh/3agent.git'
$RepoRef = Get-EnvOrDefault 'THREE_AGENT_REPO_REF' 'main'
$InstallDir = Get-EnvOrDefault 'THREE_AGENT_INSTALL_DIR' (Join-Path $HOME '3agent')
$BinDir = Get-EnvOrDefault 'THREE_AGENT_BIN_DIR' (Join-Path $env:LOCALAPPDATA '3agent\bin')
$ConfigPath = Get-EnvOrDefault 'THREE_AGENT_CONFIG_PATH' (Join-Path $InstallDir 'config\local.json')
$Model = Get-EnvOrDefault 'THREE_AGENT_MODEL' ''
$InstallOllama = Test-True (Get-EnvOrDefault 'THREE_AGENT_INSTALL_OLLAMA' '0')
$PullModel = Test-True (Get-EnvOrDefault 'THREE_AGENT_PULL_MODEL' '0')
$SkipSystemPackages = Test-True (Get-EnvOrDefault 'THREE_AGENT_SKIP_SYSTEM_PACKAGES' '0')
$BootstrapUrl = 'https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.ps1'

if ($SelfTest) {
    if ([string]::IsNullOrWhiteSpace($RepoUrl)) { Stop-Deploy 'Repository URL is empty' }
    if ([string]::IsNullOrWhiteSpace($RepoRef)) { Stop-Deploy 'Repository ref is empty' }
    if ([string]::IsNullOrWhiteSpace($InstallDir)) { Stop-Deploy 'Install directory is empty' }
    if ([string]::IsNullOrWhiteSpace($BinDir)) { Stop-Deploy 'Binary directory is empty' }
    Write-Log 'Windows bootstrap self-test PASS'
    exit 0
}

if ($env:OS -ne 'Windows_NT') {
    Stop-Deploy 'This bootstrap is for Windows 10/11 only'
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory=$true)][string]$File,
        [string[]]$Arguments = @(),
        [string]$Description = $File
    )
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Deploy "$Description failed with exit code $LASTEXITCODE"
    }
}

function Resolve-Git {
    $cmd = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd\git.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

function Test-PythonVersion {
    param([string]$PythonExe)
    if ([string]::IsNullOrWhiteSpace($PythonExe) -or -not (Test-Path $PythonExe)) { return $false }
    & $PythonExe -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Resolve-Python {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -ne $python -and (Test-PythonVersion $python.Source)) { return $python.Source }

    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        foreach ($selector in @('-3.12','-3.11')) {
            $resolved = & $py.Source $selector -c 'import sys; print(sys.executable)' 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($resolved)) {
                $candidate = ($resolved | Select-Object -First 1).Trim()
                if (Test-PythonVersion $candidate) { return $candidate }
            }
        }
    }

    $roots = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python'),
        $env:ProgramFiles
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $candidates = Get-ChildItem -Path $root -Filter python.exe -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'Python3(11|12|13)' } |
            Sort-Object FullName -Descending
        foreach ($candidate in $candidates) {
            if (Test-PythonVersion $candidate.FullName) { return $candidate.FullName }
        }
    }
    return $null
}

function Resolve-Winget {
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    return $null
}

function Install-WingetPackage {
    param([string]$Id)
    $winget = Resolve-Winget
    if ([string]::IsNullOrWhiteSpace($winget)) {
        Stop-Deploy "WinGet is required to install missing dependency '$Id'. Install Microsoft App Installer or install the dependency manually."
    }
    Write-Log "Installing missing dependency with WinGet: $Id"
    Invoke-NativeChecked -File $winget -Arguments @(
        'install','--id',$Id,'-e','--source','winget','--silent',
        '--accept-package-agreements','--accept-source-agreements'
    ) -Description "winget install $Id"
}

function Install-SystemPrerequisites {
    $git = Resolve-Git
    $python = Resolve-Python

    if ($SkipSystemPackages) {
        Write-Log 'Skipping system package installation by request'
    } else {
        if ([string]::IsNullOrWhiteSpace($git)) { Install-WingetPackage 'Git.Git' }
        if ([string]::IsNullOrWhiteSpace($python)) { Install-WingetPackage 'Python.Python.3.12' }
    }

    $script:GitExe = Resolve-Git
    $script:PythonExe = Resolve-Python
    if ([string]::IsNullOrWhiteSpace($script:GitExe)) { Stop-Deploy 'Git >= 2.x was not found after prerequisite setup' }
    if ([string]::IsNullOrWhiteSpace($script:PythonExe)) { Stop-Deploy 'Python >= 3.11 was not found after prerequisite setup' }

    $version = & $script:PythonExe -c 'import sys; print(sys.version.split()[0])'
    Write-Log "Git: $(& $script:GitExe --version)"
    Write-Log "Python: $version"
}

function Resolve-Ollama {
    $cmd = Get-Command ollama.exe -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'),
        (Join-Path $env:LOCALAPPDATA 'Ollama\ollama.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

function Install-OllamaIfRequested {
    if (-not $InstallOllama) { return }
    $ollama = Resolve-Ollama
    if (-not [string]::IsNullOrWhiteSpace($ollama)) {
        Write-Log "Ollama already installed: $(& $ollama --version 2>&1 | Select-Object -First 1)"
        $script:OllamaExe = $ollama
        return
    }

    Write-Log 'Installing Ollama from the official Windows installer script'
    $tempScript = Join-Path ([IO.Path]::GetTempPath()) ("ollama-install-{0}.ps1" -f [Guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -UseBasicParsing -Uri 'https://ollama.com/install.ps1' -OutFile $tempScript
        $hostPowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
        Invoke-NativeChecked -File $hostPowerShell -Arguments @('-NoProfile','-ExecutionPolicy','Bypass','-File',$tempScript) -Description 'Ollama installer'
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $tempScript
    }
    $script:OllamaExe = Resolve-Ollama
    if ([string]::IsNullOrWhiteSpace($script:OllamaExe)) { Stop-Deploy 'Ollama installation completed but ollama.exe was not found' }
}

function Test-RepositoryClean {
    if (-not (Test-Path (Join-Path $InstallDir '.git'))) { return $true }
    & $script:GitExe -C $InstallDir diff --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $script:GitExe -C $InstallDir diff --cached --quiet
    return ($LASTEXITCODE -eq 0)
}

function Deploy-Repository {
    Write-Log "Deploying GitHub ref '$RepoRef' into $InstallDir"
    $parent = Split-Path -Parent $InstallDir
    if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }

    if (Test-Path (Join-Path $InstallDir '.git')) {
        if (-not (Test-RepositoryClean)) { Stop-Deploy "Existing checkout has tracked local changes: $InstallDir" }
        Invoke-NativeChecked -File $script:GitExe -Arguments @('-C',$InstallDir,'remote','set-url','origin',$RepoUrl) -Description 'git remote set-url'
    } elseif (Test-Path $InstallDir) {
        Stop-Deploy "Install path exists but is not a Git checkout: $InstallDir"
    } else {
        Invoke-NativeChecked -File $script:GitExe -Arguments @('clone','--no-checkout',$RepoUrl,$InstallDir) -Description 'git clone'
    }

    Invoke-NativeChecked -File $script:GitExe -Arguments @('-C',$InstallDir,'fetch','--prune','origin',$RepoRef) -Description 'git fetch'
    $resolvedOutput = & $script:GitExe -C $InstallDir rev-parse FETCH_HEAD
    $revParseExit = $LASTEXITCODE
    if ($revParseExit -ne 0) { Stop-Deploy "git rev-parse FETCH_HEAD failed with exit code $revParseExit" }
    $resolved = [string]($resolvedOutput | Select-Object -First 1)
    $resolved = $resolved.Trim()
    if ([string]::IsNullOrWhiteSpace($resolved)) { Stop-Deploy 'Unable to resolve fetched Git commit' }
    Invoke-NativeChecked -File $script:GitExe -Arguments @('-C',$InstallDir,'checkout','--detach',$resolved) -Description 'git checkout'
    Invoke-NativeChecked -File $script:GitExe -Arguments @('-C',$InstallDir,'clean','-fdx','-e','config/local.json','-e','data/') -Description 'git clean'
    Write-Log "Repository deployed at commit $resolved"
}

function Install-PythonEnvironment {
    Write-Log 'Creating/updating isolated Python environment'
    $venv = Join-Path $InstallDir '.venv'
    Invoke-NativeChecked -File $script:PythonExe -Arguments @('-m','venv',$venv) -Description 'python -m venv'
    $venvPython = Join-Path $venv 'Scripts\python.exe'
    if (-not (Test-Path $venvPython)) { Stop-Deploy 'Virtual environment python.exe was not created' }
    $script:VenvPython = $venvPython
    Invoke-NativeChecked -File $venvPython -Arguments @('-m','pip','install','--upgrade','pip','setuptools','wheel') -Description 'pip bootstrap'
    Invoke-NativeChecked -File $venvPython -Arguments @('-m','pip','install','-e',$InstallDir) -Description 'pip install project'
}

function Write-ConfigIfMissing {
    if (Test-Path $ConfigPath) {
        Write-Log "Preserving existing configuration: $ConfigPath"
        return
    }
    $configDir = Split-Path -Parent $ConfigPath
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    Copy-Item -Force (Join-Path $InstallDir 'config\test.example.json') $ConfigPath
    if (-not [string]::IsNullOrWhiteSpace($Model)) {
        $code = @'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
model = sys.argv[2]
data = json.loads(path.read_text(encoding="utf-8"))
data.setdefault("llm", {})["model"] = model
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
'@
        Invoke-NativeChecked -File $script:VenvPython -Arguments @('-c',$code,$ConfigPath,$Model) -Description 'configure model'
    }
    Write-Log "Created configuration: $ConfigPath"
}

function Add-UserPath {
    param([string]$Directory)
    $userPath = [Environment]::GetEnvironmentVariable('Path','User')
    $parts = @()
    if (-not [string]::IsNullOrWhiteSpace($userPath)) { $parts = $userPath -split ';' }
    if ($parts -notcontains $Directory) {
        $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $Directory } else { "$userPath;$Directory" }
        [Environment]::SetEnvironmentVariable('Path',$newPath,'User')
    }
    if (($env:Path -split ';') -notcontains $Directory) { $env:Path = "$Directory;$env:Path" }
}

function Escape-CmdValue {
    param([string]$Value)
    return $Value.Replace('%','%%').Replace('"','""')
}

function Install-Launchers {
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    $venvAgent = Join-Path $InstallDir '.venv\Scripts\three-agent.exe'
    if (-not (Test-Path $venvAgent)) { Stop-Deploy 'three-agent.exe entry point is missing from the virtual environment' }

    $agentCmd = @"
@echo off
setlocal
set "THREE_AGENT_CONFIG=$(Escape-CmdValue $ConfigPath)"
cd /d "$(Escape-CmdValue $InstallDir)"
"$(Escape-CmdValue $venvAgent)" %*
"@
    Set-Content -Encoding ASCII -Path (Join-Path $BinDir '3agent.cmd') -Value $agentCmd

    $updateCmd = @"
@echo off
setlocal
set "THREE_AGENT_REPO_URL=$(Escape-CmdValue $RepoUrl)"
set "THREE_AGENT_REPO_REF=$(Escape-CmdValue $RepoRef)"
set "THREE_AGENT_INSTALL_DIR=$(Escape-CmdValue $InstallDir)"
set "THREE_AGENT_BIN_DIR=$(Escape-CmdValue $BinDir)"
set "THREE_AGENT_CONFIG_PATH=$(Escape-CmdValue $ConfigPath)"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm '$BootstrapUrl' | iex"
"@
    Set-Content -Encoding ASCII -Path (Join-Path $BinDir '3agent-update.cmd') -Value $updateCmd
    Add-UserPath $BinDir
    Write-Log "Installed launchers in $BinDir"
}

function Pull-ModelIfRequested {
    if (-not $PullModel) { return }
    if ([string]::IsNullOrWhiteSpace($Model)) { Stop-Deploy 'THREE_AGENT_PULL_MODEL=1 requires THREE_AGENT_MODEL' }
    $ollama = Resolve-Ollama
    if ([string]::IsNullOrWhiteSpace($ollama)) { Stop-Deploy "Ollama is required to pull model '$Model'" }
    Write-Log "Pulling Ollama model: $Model"
    Invoke-NativeChecked -File $ollama -Arguments @('pull',$Model) -Description 'ollama pull'
}

function Verify-Install {
    Write-Log 'Running compile and unit tests'
    Invoke-NativeChecked -File $script:VenvPython -Arguments @('-m','compileall','-q',(Join-Path $InstallDir 'src'),(Join-Path $InstallDir 'tests')) -Description 'compileall'

    Push-Location $InstallDir
    try {
        Invoke-NativeChecked -File $script:VenvPython -Arguments @('-m','unittest','discover','-s','tests','-v') -Description 'unit tests'
    } finally {
        Pop-Location
    }

    Write-Log 'Running application smoke check'
    $oldConfig = $env:THREE_AGENT_CONFIG
    try {
        $env:THREE_AGENT_CONFIG = $ConfigPath
        $agentExe = Join-Path $InstallDir '.venv\Scripts\three-agent.exe'
        Invoke-NativeChecked -File $agentExe -Arguments @('smoke') -Description '3agent smoke'
    } finally {
        $env:THREE_AGENT_CONFIG = $oldConfig
    }

    $commitOutput = & $script:GitExe -C $InstallDir rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { Stop-Deploy 'Unable to read installed Git commit' }
    $commit = [string]($commitOutput | Select-Object -First 1)
    $commit = $commit.Trim()
    Write-Log 'FINAL PASS: Windows 3Agent deployment is ready'
    Write-Log "Commit: $commit"
    Write-Log "Install: $InstallDir"
    Write-Log "Command: 3agent"
    Write-Log "Update: 3agent-update"
    if ([string]::IsNullOrWhiteSpace($Model)) {
        Write-Warn 'No local LLM model configured. CLI/smoke is ready; live agents require Ollama plus a configured model.'
    }
}

Install-SystemPrerequisites
Install-OllamaIfRequested
Deploy-Repository
Install-PythonEnvironment
Write-ConfigIfMissing
Install-Launchers
Pull-ModelIfRequested
Verify-Install
