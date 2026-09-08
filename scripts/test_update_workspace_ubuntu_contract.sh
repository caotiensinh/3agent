#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="${ROOT}/scripts/update_workspace_ubuntu.sh"
TMP_DIR=""

fail() {
  printf '[ubuntu-update-contract][FAIL] %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[ubuntu-update-contract][PASS] %s\n' "$*"
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

[[ -f "$ENTRYPOINT" ]] || fail "update_workspace_ubuntu.sh is missing"
bash -n "$ENTRYPOINT" || fail "bash syntax"
bash "$ENTRYPOINT" --self-test >/dev/null || fail "self-test"

grep -Fq 'scripts/update_code_safe.sh' "$ENTRYPOINT" || fail "safe updater delegation missing"
# shellcheck disable=SC2016
grep -Fq 'raw.githubusercontent.com/caotiensinh/3agent/${sha}/scripts/update_code_safe.sh' "$ENTRYPOINT" \
  || fail "updater must be downloaded by exact source SHA"
grep -Fq 'git ls-remote' "$ENTRYPOINT" || fail "remote ref resolution missing"
grep -Fq 'active_sha' "$ENTRYPOINT" || fail "active source lineage verification missing"
grep -Fq 'THREE_AGENT_UPDATE_VERIFY' "$ENTRYPOINT" || fail "verification mode forwarding missing"
grep -Fq 'Run this updater as the normal Ubuntu user, not with sudo.' "$ENTRYPOINT" || fail "normal-user safety boundary missing"
grep -Fq 'No existing WorkSpace installation was detected' "$ENTRYPOINT" || fail "update-only boundary missing"
grep -Fq 'Prior releases preserved at:' "$ENTRYPOINT" || fail "release preservation evidence missing"
# shellcheck disable=SC2016
grep -Fq 'run_safe_update "$expected"' "$ENTRYPOINT" || fail "outer attempt must delegate its exact resolved SHA"
# shellcheck disable=SC2016
grep -Fq 'export THREE_AGENT_REPO_REF="$exact_sha"' "$ENTRYPOINT" || fail "inner updater must receive exact attempt SHA"
# shellcheck disable=SC2016
grep -Fq 'export THREE_AGENT_UPDATE_TRACKING_REF="$REPO_REF"' "$ENTRYPOINT" || fail "moving tracking ref must be separated from exact attempt target"

if grep -Eq 'git[[:space:]]+pull|git[[:space:]].*(clean|reset[[:space:]]+--hard)|rsync[[:space:]].*--delete|find[[:space:]].*[[:space:]]-delete' "$ENTRYPOINT"; then
  fail "unsafe in-place update primitive detected"
fi

if grep -Eq 'rm[[:space:]]+-rf[[:space:]].*(INSTALL_DIR|RELEASES_DIR|STATE_DIR|CONFIG_PATH)' "$ENTRYPOINT"; then
  fail "destructive removal of persistent WorkSpace state detected"
fi

# Deterministic A -> B race fixture. The production run_safe_update() is kept intact;
# only remote resolution, host checks, download and state I/O are isolated in-process.
TMP_DIR="$(mktemp -d)"
lib="${TMP_DIR}/update_workspace_lib.sh"
resolver_state="${TMP_DIR}/resolver-state"
active_state="${TMP_DIR}/active-state"
observed="${TMP_DIR}/observed-inner-targets"

# Remove only the terminal main invocation so the production functions can be exercised.
sed '${/^main "\$@"$/d;}' "$ENTRYPOINT" >"$lib"
printf '0\n' >"$resolver_state"
printf 'old\n' >"$active_state"
: >"$observed"

A_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
B_SHA="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
export A_SHA B_SHA

(
  export THREE_AGENT_REPO_URL="https://github.com/caotiensinh/3agent.git"
  export THREE_AGENT_REPO_REF="main"
  export THREE_AGENT_INSTALL_DIR="${TMP_DIR}/install"
  export THREE_AGENT_BIN_DIR="${TMP_DIR}/bin"
  export THREE_AGENT_CONFIG_PATH="${TMP_DIR}/config/local.json"
  export THREE_AGENT_RELEASES_DIR="${TMP_DIR}/releases"
  export THREE_AGENT_STATE_DIR="${TMP_DIR}/state"
  export THREE_AGENT_ACTIVATION_LOG="${TMP_DIR}/state/active-releases.log"
  export THREE_AGENT_UPDATE_MAX_ATTEMPTS=3
  export THREE_AGENT_ALLOW_ROOT=1
  export RACE_RESOLVER_STATE="$resolver_state"
  export RACE_ACTIVE_STATE="$active_state"
  export RACE_OBSERVED="$observed"

  # shellcheck source=/dev/null
  source "$lib"

  check_ubuntu_host() { :; }
  check_commands() { :; }
  installation_exists() { return 0; }
  active_sha() { cat "$RACE_ACTIVE_STATE"; }
  verify_final_state() { [[ "$(cat "$RACE_ACTIVE_STATE")" == "$1" ]]; }

  resolve_target_sha() {
    local index
    index="$(cat "$RACE_RESOLVER_STATE")"
    case "$index" in
      0) printf '%s\n' "$A_SHA" ;;
      *) printf '%s\n' "$B_SHA" ;;
    esac
    printf '%s\n' "$((index + 1))" >"$RACE_RESOLVER_STATE"
  }

  download_exact_updater() {
    local pinned="$1"
    TMP_UPDATER="${TMP_DIR}/fake-inner-${pinned}.sh"
    cat >"$TMP_UPDATER" <<'EOF_INNER'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\t%s\n' "$THREE_AGENT_REPO_REF" "$THREE_AGENT_UPDATE_TRACKING_REF" >>"$RACE_OBSERVED"
printf '%s\n' "$THREE_AGENT_REPO_REF" >"$RACE_ACTIVE_STATE"
printf 'FINAL PASS: code updated without deleting prior installation or releases\n'
EOF_INNER
    chmod 0755 "$TMP_UPDATER"
  }

  main >/dev/null
)

mapfile -t race_lines <"$observed"
[[ "${#race_lines[@]}" -eq 2 ]] || fail "moving-ref fixture expected exactly two inner attempts"
[[ "${race_lines[0]}" == "${A_SHA}"$'\t'"main" ]] \
  || fail "A attempt was not pinned to A while preserving main as tracking ref"
[[ "${race_lines[1]}" == "${B_SHA}"$'\t'"main" ]] \
  || fail "B must activate only in the subsequent outer attempt"
[[ "$(cat "$active_state")" == "$B_SHA" ]] || fail "stable retry did not finish on B"

pass "real Ubuntu updater pins every attempt exactly; moving ref B cannot activate inside the A attempt"
