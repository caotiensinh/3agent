#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="${ROOT}/scripts/update_workspace_ubuntu.sh"

fail() {
  printf '[ubuntu-update-contract][FAIL] %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[ubuntu-update-contract][PASS] %s\n' "$*"
}

[[ -f "$ENTRYPOINT" ]] || fail "update_workspace_ubuntu.sh is missing"
bash -n "$ENTRYPOINT" || fail "bash syntax"
bash "$ENTRYPOINT" --self-test >/dev/null || fail "self-test"

grep -Fq 'scripts/update_code_safe.sh' "$ENTRYPOINT" || fail "safe updater delegation missing"
grep -Fq 'raw.githubusercontent.com/caotiensinh/3agent/${sha}/scripts/update_code_safe.sh' "$ENTRYPOINT" \
  || fail "updater must be downloaded by exact source SHA"
grep -Fq 'git ls-remote' "$ENTRYPOINT" || fail "remote ref resolution missing"
grep -Fq 'active_sha' "$ENTRYPOINT" || fail "active source lineage verification missing"
grep -Fq 'THREE_AGENT_UPDATE_VERIFY' "$ENTRYPOINT" || fail "verification mode forwarding missing"
grep -Fq 'Run this updater as the normal Ubuntu user, not with sudo.' "$ENTRYPOINT" || fail "normal-user safety boundary missing"
grep -Fq 'No existing WorkSpace installation was detected' "$ENTRYPOINT" || fail "update-only boundary missing"
grep -Fq 'Prior releases preserved at:' "$ENTRYPOINT" || fail "release preservation evidence missing"

if grep -Eq 'git[[:space:]]+pull|git[[:space:]].*(clean|reset[[:space:]]+--hard)|rsync[[:space:]].*--delete|find[[:space:]].*[[:space:]]-delete' "$ENTRYPOINT"; then
  fail "unsafe in-place update primitive detected"
fi

if grep -Eq 'rm[[:space:]]+-rf[[:space:]].*(INSTALL_DIR|RELEASES_DIR|STATE_DIR|CONFIG_PATH)' "$ENTRYPOINT"; then
  fail "destructive removal of persistent WorkSpace state detected"
fi

pass "real Ubuntu updater pins updater code, verifies lineage, and delegates non-destructively"
