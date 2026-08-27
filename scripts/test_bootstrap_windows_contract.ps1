Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Bootstrap = Join-Path $Root 'scripts\bootstrap.ps1'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "[windows-bootstrap-contract][FAIL] $Message" }
}

Assert-True (Test-Path $Bootstrap) 'bootstrap.ps1 is missing'

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($Bootstrap, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) ("PowerShell syntax errors: " + (($parseErrors | ForEach-Object Message) -join '; '))

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Bootstrap -SelfTest
Assert-True ($LASTEXITCODE -eq 0) 'bootstrap self-test failed'

$content = Get-Content -Raw -Path $Bootstrap
Assert-True ($content.Contains('https://github.com/caotiensinh/3agent.git')) 'default GitHub repository missing'
Assert-True ($content.Contains("'fetch','--prune','origin',`$RepoRef")) 'GitHub ref fetch contract missing'
Assert-True ($content.Contains("'-m','pip','install','-e',`$InstallDir")) 'project install contract missing'
Assert-True ($content.Contains("@('smoke')")) 'post-deploy smoke contract missing'
Assert-True ($content.Contains('3agent-update.cmd')) 'update launcher missing'
Assert-True ($content.Contains('Python.Python.3.12')) 'Python WinGet fallback missing'
Assert-True ($content.Contains('Git.Git')) 'Git WinGet fallback missing'

$banned = @(
    'nvidia-driver',
    'pnputil',
    'bcdedit',
    'Restart-Computer',
    'Stop-Computer',
    'shutdown.exe'
)
foreach ($term in $banned) {
    Assert-True (-not $content.Contains($term)) "bootstrap must not mutate driver/boot/reboot state: $term"
}

Write-Host '[windows-bootstrap-contract][PASS] Windows portable bootstrap contract'
