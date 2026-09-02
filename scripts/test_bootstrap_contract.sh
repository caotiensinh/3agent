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
# shellcheck disable=SC2016
grep -Fq 'git -C "$INSTALL_DIR" fetch --prune origin "$REPO_REF"' "$BOOTSTRAP" || fail "GitHub ref fetch contract missing"
# shellcheck disable=SC2016
grep -Fq 'pip install -e "$INSTALL_DIR"' "$BOOTSTRAP" || fail "editable project install contract missing"
grep -Fq 'three-agent" smoke' "$BOOTSTRAP" || fail "post-deploy smoke contract missing"
grep -Fq '3agent-update' "$BOOTSTRAP" || fail "update launcher missing"
grep -Fq 'clean_workspace_generated_artifacts' "$BOOTSTRAP" || fail "allowlisted cleanup function missing"
grep -Fq 'Cleaning only WorkSpace-owned generated artifacts' "$BOOTSTRAP" || fail "allowlisted cleanup audit log missing"
# shellcheck disable=SC2016
grep -Fq '"${INSTALL_DIR}/.venv"' "$BOOTSTRAP" || fail "venv cleanup allowlist missing"
# shellcheck disable=SC2016
grep -Fq '"${INSTALL_DIR}/src/workspace_local_ai.egg-info"' "$BOOTSTRAP" || fail "egg-info cleanup allowlist missing"
# shellcheck disable=SC2016
grep -Fq 'https://raw.githubusercontent.com/caotiensinh/3agent/${REPO_REF}/scripts/bootstrap.sh' "$BOOTSTRAP" || fail "generated updater must follow repository ref"
if grep -Fq "curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh" "$BOOTSTRAP"; then
  fail "generated updater must not hardcode main bootstrap lineage"
fi

# shellcheck disable=SC2016
if grep -Fq 'git -C "$INSTALL_DIR" clean' "$BOOTSTRAP"; then
  fail "portable bootstrap must not broadly delete untracked local state"
fi

if grep -Eq 'rm .*actions-runner|rm .*config/.*(backup|before)' "$BOOTSTRAP"; then
  fail "portable bootstrap must not delete runner state or local configuration backups"
fi

if grep -Eq 'apt(-get)? .*nvidia|ubuntu-drivers|modprobe|update-grub|grub-install|reboot|shutdown' "$BOOTSTRAP"; then
  fail "portable bootstrap must not mutate NVIDIA driver, bootloader, or reboot the host"
fi

pass "portable bootstrap contract"
