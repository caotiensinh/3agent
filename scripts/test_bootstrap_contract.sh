#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP="${ROOT}/scripts/bootstrap.sh"

fail() {
  printf '[bootstrap-contract][FAIL] %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[bootstrap-contract][PASS] %s\n' "$*"
}

[[ -f "$BOOTSTRAP" ]] || fail "bootstrap.sh is missing"
bash -n "$BOOTSTRAP" || fail "bash syntax"
bash "$BOOTSTRAP" --self-test >/dev/null || fail "self-test"

grep -Fq 'https://github.com/caotiensinh/3agent.git' "$BOOTSTRAP" || fail "default GitHub repository missing"
grep -Fq 'git -C "$INSTALL_DIR" fetch --prune origin "$REPO_REF"' "$BOOTSTRAP" || fail "GitHub ref fetch contract missing"
grep -Fq 'pip install -e "$INSTALL_DIR"' "$BOOTSTRAP" || fail "editable project install contract missing"
grep -Fq 'three-agent" smoke' "$BOOTSTRAP" || fail "post-deploy smoke contract missing"
grep -Fq '3agent-update' "$BOOTSTRAP" || fail "update launcher missing"

if grep -Eq 'apt(-get)? .*nvidia|ubuntu-drivers|modprobe|update-grub|grub-install|reboot|shutdown' "$BOOTSTRAP"; then
  fail "portable bootstrap must not mutate NVIDIA driver, bootloader, or reboot the host"
fi

pass "portable bootstrap contract"
