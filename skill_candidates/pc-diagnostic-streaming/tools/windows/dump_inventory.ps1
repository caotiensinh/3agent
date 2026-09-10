$ErrorActionPreference = 'SilentlyContinue'
$items = @()
$items += Get-Item "$env:SystemRoot\MEMORY.DMP"
$items += Get-ChildItem "$env:SystemRoot\Minidump\*.dmp"
$items | Where-Object { $_ } |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName,Length,CreationTime,LastWriteTime
