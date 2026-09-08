# Linux Diagnostic Playbooks

## Core evidence set (S0)
- `uname -a`
- `/etc/os-release`
- `uptime`
- `journalctl --list-boots`
- `journalctl -b -1 -p warning..alert --no-pager`
- `journalctl -k -b -1 --no-pager`
- `dmesg -T`
- `systemctl --failed`
- `lspci -nnk`
- `lsusb`
- `lsblk -o NAME,MODEL,SERIAL,SIZE,TYPE,FSTYPE,MOUNTPOINTS`
- `free -h`
- `vmstat 1 5`
- `ip -br addr`, `ip route`, `ss -s`
- `/proc/sys/kernel/tainted`

## Freeze / reboot
1. Check previous boot: `journalctl -b -1`.
2. Kernel-only: `journalctl -k -b -1`.
3. Look for GPU resets, I/O timeout, MCE/EDAC, OOM, watchdog, soft/hard lockup, thermal and ACPI messages.
4. If journal ends abruptly with no shutdown evidence, retain power/hard-lock/storage-path hypotheses.
5. If machine remains reachable by SSH during GUI freeze, collect live `dmesg`, process state, GPU logs and compositor/session logs.

## Persistent crash evidence
Linux pstore can retain kernel panic/oops/shutdown-hang evidence across reboot on supported/configured systems. Check `/sys/fs/pstore` and systemd-pstore storage.

## Kernel taint
Read `/proc/sys/kernel/tainted`. Non-zero flags may indicate proprietary/out-of-tree/unsigned modules, machine check, warning, prior OOPS, or soft lockup. Treat taint as context, not automatic root cause.

## Magic SysRq
High-risk diagnostic/control mechanism. It may respond even when userspace is wedged. Some actions can sync filesystems, dump task state, remount read-only, reboot or deliberately crash for a dump. Never trigger dangerous SysRq actions automatically.

## Memory
- inspect `free`, `vmstat`, PSI if available
- search journal for OOM killer
- boot-time/offline Memtest86+ for suspected RAM
- cross-check EDAC/MCE when supported

## Storage
- `smartctl -x <device>` when smartmontools is installed
- `nvme smart-log <device>` for NVMe where available
- `journalctl -k` / `dmesg` for ATA/NVMe resets, I/O errors, filesystem errors
- never run destructive SMART tests without approval
- filesystem repair (`fsck`) generally requires unmounted/offline context and is disruptive

## Application crashes
- `coredumpctl list`
- `coredumpctl info <PID|EXE>`
- `coredumpctl debug <...>` if configured
- GDB/core dump for deep analysis
- collect package version and linked libraries

## Performance
- CPU/load: `uptime`, `top`, `pidstat`
- memory: `free`, `vmstat`, PSI
- storage: `iostat -xz 1`, `pidstat -d`
- network: `ip -s link`, `ss`, `ethtool -S`, packet capture when needed
- process/syscall: `strace` only on a targeted process; understand overhead

## Network stack
Link -> driver -> address -> neighbor -> route -> DNS -> TCP/UDP -> TLS/app.
Commands may include `ethtool`, `ip -s link`, `ip neigh`, `ip route get`, `ss -plant`, `resolvectl`, `ping`, `tracepath`, `tcpdump`.

## Distribution support bundles
On RHEL-family systems, `sos report` is useful for collecting a standardized diagnostic archive. Kernel crashes can use kdump/crash tooling when configured.
