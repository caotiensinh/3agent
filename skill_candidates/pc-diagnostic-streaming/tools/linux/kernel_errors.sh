#!/usr/bin/env bash
set -u
journalctl -k -b 0 -p warning..alert --no-pager
printf '\n===== selected kernel patterns =====\n'
journalctl -k -b 0 --no-pager | grep -Ei 'mce|edac|whea|aer|pcie|nvme|ata|i/o error|timeout|reset|oom|watchdog|lockup|thermal|gpu|drm|nvrm|amdgpu' || true
