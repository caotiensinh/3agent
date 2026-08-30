#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/setup_runner_pool.sh"

bash -n "$SCRIPT"
bash "$SCRIPT" --self-test >/dev/null
bash "$SCRIPT" --self-test --general-count=3 --gpu-count=2 >/dev/null

# Missing token must fail closed, not silently proceed.
if bash "$SCRIPT" >/dev/null 2>&1; then
  echo "setup_runner_pool.sh must fail without --token" >&2
  exit 1
fi

# Out-of-range counts must be rejected.
if bash "$SCRIPT" --self-test --general-count=-1 >/dev/null 2>&1; then
  echo "setup_runner_pool.sh must reject a negative --general-count" >&2
  exit 1
fi
if bash "$SCRIPT" --self-test --general-count=100 >/dev/null 2>&1; then
  echo "setup_runner_pool.sh must cap the total instance count" >&2
  exit 1
fi

grep -q -- '--tarball-sha256' "$SCRIPT"
grep -q 'sha256sum -c' "$SCRIPT"
grep -q 'self-hosted,general' "$SCRIPT"
grep -q 'self-hosted,gpu' "$SCRIPT"
grep -q -- '--teardown' "$SCRIPT"
grep -q 'config.sh remove' "$SCRIPT"

# The script must never hardcode a runner release URL/version/checksum of its own —
# those must always come from the caller (GitHub's own New-runner page), per the
# no-fabrication design note at the top of the script.
if grep -Eq 'https://github\.com/actions/runner/releases' "$SCRIPT"; then
  echo "setup_runner_pool.sh must not hardcode a runner release URL" >&2
  exit 1
fi

if grep -Eq 'ubuntu-drivers|nvidia-driver-[0-9]|apt(-get)?[^#\n]*install[^#\n]*nvidia|(^|[[:space:]])reboot([[:space:]]|$)' "$SCRIPT"; then
  echo "Runner-pool script must not mutate NVIDIA driver/kernel state" >&2
  exit 1
fi

echo "Runner-pool contract PASS"
