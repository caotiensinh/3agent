param(
  [int]$Hours = 24,
  [int]$MaxEvents = 300
)
$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-[math]::Abs($Hours))
$ids = 41,1001,6008,1074,161,162,19,7,51,55,129,153,157,4101
Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$start } -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Id -in $ids -or
    $_.ProviderName -match 'WHEA|BugCheck|Display|nvlddmkm|Disk|Ntfs|storahci|stornvme|volmgr'
  } |
  Sort-Object TimeCreated -Descending |
  Select-Object -First ([math]::Abs($MaxEvents)) TimeCreated,Id,ProviderName,LevelDisplayName,Message
