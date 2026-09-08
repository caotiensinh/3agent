# Source Registry

Authoritative sources used to seed this skill. Community sources are used only to discover symptom patterns and practical evidence ideas, never as sole proof.

## Microsoft / Windows
- Event ID 41 unexpected restart: https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart
- Stop code / dump troubleshooting: https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/stop-code-error-troubleshooting
- Analyze kernel dump with WinDbg: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/analyzing-a-kernel-mode-dump-file-with-windbg
- Get-WinEvent: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
- Process Monitor: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- Perfmon: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/perfmon
- Driver Verifier: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier
- WHEA hardware errors: https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/hardware-errors-and-error-sources
- Bugcheck 0x124: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x124---whea-uncorrectable-error
- Powercfg: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
- SetupDiag: https://learn.microsoft.com/en-us/windows/deployment/upgrade/setupdiag
- Pktmon: https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon
- Packet loss diagnosis: https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/diagnose-packet-loss
- PnPUtil: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax
- DISM/SFC: https://support.microsoft.com/en-us/windows/experience/backup-recovery/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files

## Linux / upstream
- Linux kernel pstore/ramoops: https://docs.kernel.org/admin-guide/ramoops.html
- Linux kernel pstore block: https://docs.kernel.org/admin-guide/pstore-blk.html
- Linux shutdown hang debugging with pstore: https://docs.kernel.org/power/shutdown-debugging.html
- Linux kernel tainted state: https://docs.kernel.org/admin-guide/tainted-kernels.html
- Linux Magic SysRq: https://docs.kernel.org/admin-guide/sysrq.html
- Red Hat core dump debugging: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/developer_guide/debugging-crashed-application

## Community pattern sources
Examples reviewed include LinuxQuestions/Reddit discussions of random freezes and the practical distinction between GUI-only hangs and full system hangs. These are hypothesis-generating only and must be corroborated with logs/dumps/vendor docs.
