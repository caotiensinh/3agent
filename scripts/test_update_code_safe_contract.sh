#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER="${ROOT}/scripts/update_code_safe.sh"

fail() {
  printf '[safe-update-contract][FAIL] %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[safe-update-contract][PASS] %s\n' "$*"
}

[[ -f "$UPDATER" ]] || fail "update_code_safe.sh is missing"
bash -n "$UPDATER" || fail "bash syntax"
bash "$UPDATER" --self-test >/dev/null || fail "self-test"

grep -Fq 'active-releases.log' "$UPDATER" || fail "append-only activation log missing"
grep -Fq '>> "$ACTIVATION_LOG"' "$UPDATER" || fail "activation must append instead of replace history"
grep -Fq 'mktemp -d "${RELEASES_DIR}/release-' "$UPDATER" || fail "immutable release directory creation missing"
grep -Fq 'git clone --filter=blob:none --no-checkout' "$UPDATER" || fail "isolated release checkout missing"
grep -Fq 'backup_launcher' "$UPDATER" || fail "launcher backup missing"
grep -Fq 'Previous installation preserved' "$UPDATER" || fail "preservation audit message missing"
grep -Fq 'THREE_AGENT_UPDATE_VERIFY' "$UPDATER" || fail "verification policy missing"

if grep -Eq '(^|[[:space:];|&])rm([[:space:]]|$)|git[[:space:]].*(clean|reset[[:space:]]+--hard)|rsync[[:space:]].*--delete|find[[:space:]].*[[:space:]]-delete' "$UPDATER"; then
  fail "destructive operation detected in safe updater"
fi

if grep -Eq 'checkout[[:space:]].*LEGACY_INSTALL_DIR|checkout[[:space:]].*INSTALL_DIR|git[[:space:]]+-C[[:space:]]+"?\$\{?LEGACY_INSTALL_DIR' "$UPDATER"; then
  fail "safe updater must never checkout into the legacy installation"
fi

pass "append-only non-destructive updater contract"
