#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER="${ROOT}/scripts/update_code_safe.sh"
TMP_DIR=""

fail() {
  printf '[safe-update-contract][FAIL] %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[safe-update-contract][PASS] %s\n' "$*"
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

[[ -f "$UPDATER" ]] || fail "update_code_safe.sh is missing"
bash -n "$UPDATER" || fail "bash syntax"
bash "$UPDATER" --self-test >/dev/null || fail "self-test"

grep -Fq 'active-releases.log' "$UPDATER" || fail "append-only activation log missing"
# shellcheck disable=SC2016
grep -Fq '>> "$ACTIVATION_LOG"' "$UPDATER" || fail "activation must append instead of replace history"
# shellcheck disable=SC2016
grep -Fq 'mktemp -d "${RELEASES_DIR}/release-' "$UPDATER" || fail "immutable release directory creation missing"
grep -Fq 'git clone --filter=blob:none --no-checkout' "$UPDATER" || fail "isolated release checkout missing"
grep -Fq 'backup_launcher' "$UPDATER" || fail "launcher backup missing"
grep -Fq 'Previous installation preserved' "$UPDATER" || fail "preservation audit message missing"
grep -Fq 'THREE_AGENT_UPDATE_VERIFY' "$UPDATER" || fail "verification policy missing"
# shellcheck disable=SC2016
grep -Fq 'verify_release "$active"' "$UPDATER" || fail "already-current releases must honor the verification policy"

if grep -Eq '(^|[[:space:];|&])rm([[:space:]]|$)|git[[:space:]].*(clean|reset[[:space:]]+--hard)|rsync[[:space:]].*--delete|find[[:space:]].*[[:space:]]-delete' "$UPDATER"; then
  fail "destructive operation detected in safe updater"
fi

if grep -Eq 'checkout[[:space:]].*LEGACY_INSTALL_DIR|checkout[[:space:]].*INSTALL_DIR|git[[:space:]]+-C[[:space:]]+"?\$\{?LEGACY_INSTALL_DIR' "$UPDATER"; then
  fail "safe updater must never checkout into the legacy installation"
fi

TMP_DIR="$(mktemp -d)"
release="${TMP_DIR}/release"
bin_dir="${TMP_DIR}/bin"
state_dir="${TMP_DIR}/state"
config_dir="${TMP_DIR}/config"
python_log="${TMP_DIR}/python.log"

mkdir -p "${release}/.venv/bin" "${release}/src" "${release}/tests" "$bin_dir" "$state_dir" "$config_dir"

git init -q "$release"
git -C "$release" config user.name "WorkSpace CI"
git -C "$release" config user.email "workspace-ci@example.invalid"
printf 'fixture\n' >"${release}/fixture.txt"
git -C "$release" add fixture.txt
git -C "$release" commit -qm "test: create updater fixture"
target_sha="$(git -C "$release" rev-parse HEAD)"

cat >"${release}/.venv/bin/python" <<'EOF_PYTHON'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_PYTHON_LOG:?}"
exit 0
EOF_PYTHON
chmod 0755 "${release}/.venv/bin/python"

cat >"${release}/.venv/bin/three-agent" <<'EOF_AGENT'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "smoke" ]] || exit 2
exit 0
EOF_AGENT
chmod 0755 "${release}/.venv/bin/three-agent"

printf '{}\n' >"${config_dir}/local.json"
printf '2026-01-01T00:00:00Z\t%s\t%s\n' "$target_sha" "$release" >"${state_dir}/active-releases.log"

FAKE_PYTHON_LOG="$python_log" \
THREE_AGENT_REPO_URL="https://github.com/caotiensinh/3agent.git" \
THREE_AGENT_REPO_REF="$target_sha" \
THREE_AGENT_INSTALL_DIR="${TMP_DIR}/legacy" \
THREE_AGENT_BIN_DIR="$bin_dir" \
THREE_AGENT_CONFIG_PATH="${config_dir}/local.json" \
THREE_AGENT_RELEASES_DIR="${TMP_DIR}/releases" \
THREE_AGENT_STATE_DIR="$state_dir" \
THREE_AGENT_ACTIVATION_LOG="${state_dir}/active-releases.log" \
THREE_AGENT_UPDATE_VERIFY=full \
bash "$UPDATER" >/dev/null

[[ -f "$python_log" ]] || fail "full verification did not invoke the active release Python"
grep -Fq -- '-m unittest discover -s tests -v' "$python_log" \
  || fail "full verification skipped unit tests for an already-current release"

pass "append-only non-destructive updater contract including already-current full verification"
