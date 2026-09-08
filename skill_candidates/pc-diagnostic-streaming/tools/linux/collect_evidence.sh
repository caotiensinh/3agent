#!/usr/bin/env bash
# Candidate deep collector: broad S0 evidence; do not run by default.
set -u
OUT="${1:-$HOME/PC_DIAG_EVIDENCE}"
mkdir -p "$OUT"
run(){ local name="$1"; shift; { echo "# $*"; "$@"; } >"$OUT/$name.txt" 2>&1 || true; }

run uname uname -a
run os-release cat /etc/os-release
run uptime uptime
run boots journalctl --list-boots --no-pager
run previous-boot journalctl -b -1 --no-pager
run previous-kernel journalctl -k -b -1 --no-pager
run current-kernel dmesg -T
run failed-services systemctl --failed --no-pager
run lspci lspci -nnk
run lsusb lsusb
run lsblk lsblk -o NAME,MODEL,SERIAL,SIZE,TYPE,FSTYPE,MOUNTPOINTS
run memory free -h
run vmstat vmstat 1 5
run ip-address ip -br addr
run ip-route ip route
run sockets ss -s
run kernel-taint cat /proc/sys/kernel/tainted

if command -v coredumpctl >/dev/null 2>&1; then run coredumps coredumpctl list --no-pager; fi
if [ -d /sys/fs/pstore ]; then run pstore ls -la /sys/fs/pstore; fi
if command -v smartctl >/dev/null 2>&1; then
  lsblk -dn -o NAME,TYPE | awk '$2=="disk"{print $1}' | while read -r d; do
    sudo smartctl -x "/dev/$d" >"$OUT/smart-$d.txt" 2>&1 || true
  done
fi

cat >"$OUT/manifest.txt" <<MANIFEST
collected_at=$(date --iso-8601=seconds)
note=Evidence collection only. No repair commands were executed.
MANIFEST

echo "Evidence saved to: $OUT"
