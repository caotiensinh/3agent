#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="${ROOT}/scripts/deploy_ubuntu_pc.sh"

fail() {
  printf '[ubuntu-pc-contract][FAIL] %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[ubuntu-pc-contract][PASS] %s\n' "$*"
}

[[ -f "$ENTRYPOINT" ]] || fail "deploy_ubuntu_pc.sh is missing"
bash -n "$ENTRYPOINT" || fail "Bash syntax"
bash "$ENTRYPOINT" --self-test >/dev/null || fail "self-test"

if bash "$ENTRYPOINT" --unknown-option >/dev/null 2>&1; then
  fail "unknown options must fail closed"
fi

grep -Fq 'https://github.com/caotiensinh/3agent.git' "$ENTRYPOINT" || fail "default GitHub repository missing"
grep -Fq 'https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh' "$ENTRYPOINT" || fail "canonical bootstrap URL missing"
grep -Fq '22.04|24.04' "$ENTRYPOINT" || fail "validated Ubuntu versions missing"
grep -Fq 'Run this script as the normal Ubuntu user, not with sudo' "$ENTRYPOINT" || fail "root safety boundary missing"
# shellcheck disable=SC2016
grep -Fq 'export THREE_AGENT_REPO_REF="$REPO_REF"' "$ENTRYPOINT" || fail "repository ref delegation missing"
# shellcheck disable=SC2016
grep -Fq 'export THREE_AGENT_INSTALL_DIR="$INSTALL_DIR"' "$ENTRYPOINT" || fail "install directory delegation missing"
# shellcheck disable=SC2016
grep -Fq 'export THREE_AGENT_CONFIG_PATH="$CONFIG_PATH"' "$ENTRYPOINT" || fail "configuration path delegation missing"
grep -Fq 'bash "$BOOTSTRAP_PATH"' "$ENTRYPOINT" || fail "bootstrap delegation missing"

if grep -Eq 'apt(-get)? .*nvidia|ubuntu-drivers|modprobe|update-grub|grub-install|reboot|shutdown|rm -rf /' "$ENTRYPOINT"; then
  fail "Ubuntu entrypoint must not mutate GPU drivers, bootloader, reboot policy, or destructively remove the host filesystem"
fi

pass "Ubuntu PC deployment entrypoint contract"
