#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/setup_runner_pool.sh"

bash -n "$SCRIPT"
bash "$SCRIPT" --self-test >/dev/null
bash "$SCRIPT" --self-test --general-count=3 --gpu-count=2 >/dev/null

# Missing token/PAT and no TTY to prompt on must fail closed, not silently proceed.
if env -u GH_PAT -u GITHUB_TOKEN bash "$SCRIPT" </dev/null >/dev/null 2>&1; then
  echo "setup_runner_pool.sh must fail without --token/GH_PAT and no TTY to prompt" >&2
  exit 1
fi

# The fully manual path (explicit --token/--tarball-url/--tarball-sha256) must never
# read GH_PAT — it should fail at the network download, not at a PAT check.
MANUAL_OUTPUT="$(env -u GH_PAT -u GITHUB_TOKEN bash "$SCRIPT" \
  --token=faketoken --tarball-url=https://example.invalid/runner.tar.gz \
  --tarball-sha256=deadbeef --general-count=1 --gpu-count=0 </dev/null 2>&1 || true)"
grep -qi 'PAT' <<<"$MANUAL_OUTPUT" && {
  echo "Manual --token/--tarball-url/--tarball-sha256 path must never mention GH_PAT" >&2
  exit 1
}

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
grep -q -- '--adopt-existing' "$SCRIPT"
grep -q 'config.sh remove' "$SCRIPT"
grep -q 'GH_PAT' "$SCRIPT"
grep -q 'actions/runners/' "$SCRIPT"
grep -q 'mint_token registration' "$SCRIPT"
grep -q 'mint_token remove' "$SCRIPT"
grep -q 'read -rsp' "$SCRIPT"

# The script must resolve the runner release dynamically from GitHub's API at run time,
# never a hardcoded https://github.com/.../releases/download/vX.Y.Z/... asset URL of a
# specific version picked by this repo.
grep -q 'api.github.com/repos/actions/runner/releases/latest' "$SCRIPT"
if grep -Eq 'github\.com/actions/runner/releases/download' "$SCRIPT"; then
  echo "setup_runner_pool.sh must not hardcode a specific runner release download URL" >&2
  exit 1
fi

if grep -Eq 'ubuntu-drivers|nvidia-driver-[0-9]|apt(-get)?[^#\n]*install[^#\n]*nvidia|(^|[[:space:]])reboot([[:space:]]|$)' "$SCRIPT"; then
  echo "Runner-pool script must not mutate NVIDIA driver/kernel state" >&2
  exit 1
fi

echo "Runner-pool contract PASS"
