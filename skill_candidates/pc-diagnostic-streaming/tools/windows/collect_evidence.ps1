# Candidate deep collector: broad S0 evidence; do not run by default.
param(
  [int]$Days = 7,
  [string]$Out = "$env:USERPROFILE\Desktop\PC_DIAG_EVIDENCE"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $Out | Out-Null
$start = (Get-Date).AddDays(-[math]::Abs($Days))

function Save-Text($Name, $Script) {
  try { & $Script 2>&1 | Out-File -Width 4096 -Encoding utf8 (Join-Path $Out $Name) }
  catch { $_ | Out-File -Encoding utf8 (Join-Path $Out ($Name + '.error.txt')) }
}

Save-Text 'systeminfo.txt' { systeminfo }
Save-Text 'computer_info.txt' { Get-ComputerInfo }
Save-Text 'pnp_devices.txt' { Get-PnpDevice | Sort-Object Class,Status,FriendlyName | Format-Table -AutoSize }
Save-Text 'drivers.txt' { pnputil /enum-drivers }
Save-Text 'processes.txt' { Get-Process | Sort-Object CPU -Descending | Select-Object -First 100 }
Save-Text 'network.txt' { Get-NetAdapter; Get-NetIPConfiguration; Get-NetRoute; Get-NetTCPConnection }
Save-Text 'disks.txt' { Get-PhysicalDisk; Get-Disk; Get-Volume }
Save-Text 'memory_dumps.txt' {
  Get-Item "$env:SystemRoot\MEMORY.DMP" -ErrorAction SilentlyContinue
  Get-ChildItem "$env:SystemRoot\Minidump\*.dmp" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
}

$ids = 7,19,41,51,55,129,153,157,161,162,4101,6008,1001,1074,7045
try {
  Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start} -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in $ids -or $_.ProviderName -match 'WHEA|nvlddmkm|Display|Disk|Ntfs|storahci|stornvme|BugCheck|volmgr' } |
    Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message |
    Export-Csv -NoTypeInformation -Encoding utf8 (Join-Path $Out 'system_events.csv')
} catch { $_ | Out-File (Join-Path $Out 'system_events.error.txt') }

try {
  Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start} -ErrorAction SilentlyContinue |
    Where-Object { $_.LevelDisplayName -in 'Error','Critical' } |
    Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message |
    Export-Csv -NoTypeInformation -Encoding utf8 (Join-Path $Out 'application_errors.csv')
} catch { $_ | Out-File (Join-Path $Out 'application_events.error.txt') }

@{
  collected_at = (Get-Date).ToString('o')
  days = $Days
  note = 'Evidence collection only. No repair commands were executed.'
} | ConvertTo-Json | Out-File -Encoding utf8 (Join-Path $Out 'manifest.json')

Write-Host "Evidence saved to: $Out"
