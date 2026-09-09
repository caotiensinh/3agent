param(
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CanonicalRepository = 'caotiensinh/3agent'

function Get-EnvOrDefault {
    param([string]$Name, [string]$Default)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Write-Log { param([string]$Message) Write-Host "[WorkSpace Installer] $Message" }
function Stop-Install { param([string]$Message) throw "[WorkSpace Installer][ERROR] $Message" }

$TrackingRef = Get-EnvOrDefault 'THREE_AGENT_REPO_REF' 'main'
$SourceRef = Get-EnvOrDefault 'WORKSPACE_SOURCE_REF' $TrackingRef
$ExpectedSha256 = Get-EnvOrDefault 'WORKSPACE_INSTALLER_SHA256' ''
$TempEntrypoint = $null

function Test-SafeRef {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -notmatch '^[A-Za-z0-9._/-]+$') { return $false }
    if ($Value.StartsWith('/') -or $Value.Contains('..')) { return $false }
    return $true
}

if (-not (Test-SafeRef $SourceRef)) { Stop-Install "Unsafe WORKSPACE_SOURCE_REF: $SourceRef" }
if (-not (Test-SafeRef $TrackingRef)) { Stop-Install "Unsafe THREE_AGENT_REPO_REF: $TrackingRef" }
if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    Stop-Install 'WORKSPACE_INSTALLER_SHA256 must be a 64-character SHA-256 value'
}

if ($SelfTest) {
    Write-Log 'One-command Windows entrypoint self-test PASS'
    Write-Log "Repository: $CanonicalRepository"
    Write-Log "Source ref: $SourceRef"
    Write-Log "Tracking ref: $TrackingRef"
    exit 0
}

$PowerShellHost = Get-Command powershell.exe -ErrorAction SilentlyContinue
if ($null -eq $PowerShellHost) {
    Stop-Install 'Windows PowerShell 5.1 (powershell.exe) is required for the canonical bootstrap'
}

$EntrypointUrl = "https://raw.githubusercontent.com/$CanonicalRepository/$SourceRef/scripts/bootstrap.ps1"
$TempEntrypoint = Join-Path ([IO.Path]::GetTempPath()) ("workspace-bootstrap-{0}.ps1" -f [Guid]::NewGuid().ToString('N'))

try {
    Write-Log "Downloading reviewed WorkSpace deployment entrypoint from $SourceRef"
    Invoke-WebRequest -UseBasicParsing -Uri $EntrypointUrl -OutFile $TempEntrypoint

    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $TempEntrypoint).Hash
        if (-not $ActualSha256.Equals($ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Install 'Deployment entrypoint checksum mismatch'
        }
        Write-Log 'Deployment entrypoint SHA-256 verification PASS'
    }

    [Environment]::SetEnvironmentVariable('THREE_AGENT_REPO_URL', "https://github.com/$CanonicalRepository.git", 'Process')
    [Environment]::SetEnvironmentVariable('THREE_AGENT_REPO_REF', $TrackingRef, 'Process')

    & $PowerShellHost.Source -NoProfile -ExecutionPolicy Bypass -File $TempEntrypoint
    if ($LASTEXITCODE -ne 0) {
        Stop-Install "Windows bootstrap failed with exit code $LASTEXITCODE"
    }
} finally {
    if ($null -ne $TempEntrypoint -and (Test-Path -LiteralPath $TempEntrypoint)) {
        Remove-Item -Force -LiteralPath $TempEntrypoint -ErrorAction SilentlyContinue
    }
}
