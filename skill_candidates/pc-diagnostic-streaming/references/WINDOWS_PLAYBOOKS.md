# Windows Diagnostic Playbooks

## Core evidence set (S0)
- `systeminfo`
- `Get-ComputerInfo`
- `Get-WinEvent` filtered around incident time
- `Get-PnpDevice`
- `pnputil /enum-drivers`
- `Get-CimInstance Win32_OperatingSystem, Win32_ComputerSystem, Win32_BIOS`
- `Get-Process | Sort-Object CPU -Descending`
- `Get-Counter` targeted counters
- `perfmon /rel`, `perfmon /report`
- dump inventory: `%SystemRoot%\MEMORY.DMP`, `%SystemRoot%\Minidump`

## Random reboot / freeze evidence priorities
Correlate System log around incident:
- 41 Kernel-Power: unclean restart evidence, not root cause.
- 6008: previous shutdown unexpected.
- 1001 WER-SystemErrorReporting: bugcheck and dump path when present.
- 1074 User32: planned/process/user initiated shutdown/restart.
- WHEA-Logger: hardware error architecture evidence.
- Display/GPU provider events.
- Disk/Ntfs/storahci/stornvme events such as timeout/reset/media/filesystem signals.
- Service/driver install/change events near first-known-bad time.

## Crash dump path
If a bugcheck exists:
1. Preserve dump.
2. Verify dump if needed.
3. Analyze with WinDbg and `!analyze -v`.
4. Look for recurring faulting module/stack across multiple dumps.
5. Do not blame the last module in stack automatically; correlate with driver version/change and hardware evidence.

## System file corruption
Diagnosis first. If supported by symptoms/evidence:
- S2: `DISM.exe /Online /Cleanup-Image /RestoreHealth`
- S2: `sfc /scannow`
Microsoft recommends DISM before SFC for component-store-backed repair.

## Startup / service isolation
Use clean boot/selective startup only if third-party service/startup interference is plausible.
Use binary search over non-Microsoft services instead of disabling arbitrary system services.

## Driver diagnosis
S0:
- `Get-PnpDevice`
- `pnputil /enum-drivers`
- collect driver versions and recent changes
S4:
- Driver Verifier only for targeted suspected drivers and only after user approval; it can deliberately crash the system.

## Performance
- `perfmon /res`
- `perfmon /report`
- `perfmon /rel`
- Windows Performance Recorder / Analyzer for advanced CPU, I/O, DPC/ISR, boot, power traces.

## Network
S0/S1 sequence:
1. `Get-NetAdapter`
2. `Get-NetIPConfiguration`
3. `Get-NetRoute`
4. `Get-NetTCPConnection`
5. `Test-NetConnection <host> -Port <port>`
6. DNS checks
7. `pktmon` filtered capture for local drops
8. ETW/netsh trace only if packet-level evidence is insufficient
Do not jump straight to Winsock/IP reset.

## Power / sleep / battery
- `powercfg /lastwake`
- `powercfg /waketimers`
- `powercfg /requests`
- `powercfg /energy`
- `powercfg /batteryreport`
- `powercfg /sleepstudy` where supported

## Update/upgrade failures
Use SetupDiag to analyze Windows Setup logs for failed upgrades before generic repair/reinstall.
