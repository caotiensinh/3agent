#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${THREE_AGENT_REPO_URL:-https://github.com/caotiensinh/3agent.git}"
REPO_REF="${THREE_AGENT_REPO_REF:-main}"
INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-${HOME}/3agent}"
BIN_DIR="${THREE_AGENT_BIN_DIR:-${HOME}/.local/bin}"
CONFIG_PATH="${THREE_AGENT_CONFIG_PATH:-${INSTALL_DIR}/config/local.json}"
RELEASES_DIR="${THREE_AGENT_RELEASES_DIR:-${HOME}/.local/share/workspace/releases}"
STATE_DIR="${THREE_AGENT_STATE_DIR:-${HOME}/.local/state/workspace}"
ACTIVATION_LOG="${THREE_AGENT_ACTIVATION_LOG:-${STATE_DIR}/active-releases.log}"
VERIFY_MODE="${THREE_AGENT_UPDATE_VERIFY:-smoke}"
CANONICAL_REPO_URL="https://github.com/caotiensinh/3agent.git"
MAX_ATTEMPTS="${THREE_AGENT_UPDATE_MAX_ATTEMPTS:-3}"
ALLOW_ROOT="${THREE_AGENT_ALLOW_ROOT:-0}"
SELF_TEST=0
TMP_UPDATER=""

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[WorkSpace Ubuntu Update][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[WorkSpace Ubuntu Update] %s\n' "$*"; }
warn() { printf '[WorkSpace Ubuntu Update][WARN] %s\n' "$*" >&2; }
die() { printf '[WorkSpace Ubuntu Update][ERROR] %s\n' "$*" >&2; exit 1; }

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup() {
  if [[ -n "$TMP_UPDATER" && -f "$TMP_UPDATER" ]]; then
    rm -f "$TMP_UPDATER"
  fi
}
trap cleanup EXIT

validate_inputs() {
  [[ "$REPO_URL" == "$CANONICAL_REPO_URL" ]] || die "This one-command updater is bound to the canonical WorkSpace repository"
  [[ -n "$REPO_REF" ]] || die "Repository ref is empty"
  [[ "$REPO_REF" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Repository ref contains unsupported characters: ${REPO_REF}"
  [[ -n "$INSTALL_DIR" ]] || die "Install directory is empty"
  [[ -n "$BIN_DIR" ]] || die "Binary directory is empty"
  [[ -n "$CONFIG_PATH" ]] || die "Configuration path is empty"
  [[ -n "$RELEASES_DIR" ]] || die "Release directory is empty"
  [[ -n "$STATE_DIR" ]] || die "State directory is empty"
  [[ -n "$ACTIVATION_LOG" ]] || die "Activation log is empty"
  [[ "$MAX_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || die "THREE_AGENT_UPDATE_MAX_ATTEMPTS must be a positive integer"
  case "$VERIFY_MODE" in
    smoke|full) ;;
    *) die "THREE_AGENT_UPDATE_VERIFY must be 'smoke' or 'full'" ;;
  esac
}

check_ubuntu_host() {
  [[ "$(uname -s)" == "Linux" ]] || die "This entrypoint supports Ubuntu Linux only"
  [[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Unsupported Linux distribution: ${ID:-unknown}. Ubuntu is required."
  case "${VERSION_ID:-}" in
    22.04|24.04) log "Detected Ubuntu ${VERSION_ID}" ;;
    *) die "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Validated versions are 22.04 and 24.04." ;;
  esac
}

check_commands() {
  local cmd
  for cmd in curl git python3; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
  done
  python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(f"Python >=3.11 is required; detected {sys.version.split()[0]}")
PY
}

installation_exists() {
  [[ -d "${INSTALL_DIR}/.git" || -f "$ACTIVATION_LOG" || -x "${BIN_DIR}/3agent" ]]
}

resolve_target_sha() {
  if [[ "$REPO_REF" =~ ^[0-9a-fA-F]{40}$ ]]; then
    printf '%s\n' "${REPO_REF,,}"
    return 0
  fi

  local lines sha
  lines="$(git ls-remote "$REPO_URL" \
    "refs/heads/${REPO_REF}" \
    "refs/tags/${REPO_REF}^{}" \
    "refs/tags/${REPO_REF}")"
  sha="$(printf '%s\n' "$lines" | awk 'NR == 1 {print $1}')"
  [[ "$sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "Unable to resolve repository ref '${REPO_REF}'"
  printf '%s\n' "${sha,,}"
}

active_sha() {
  if [[ -f "$ACTIVATION_LOG" ]]; then
    tail -n 1 "$ACTIVATION_LOG" | awk -F '\t' 'NF >= 3 {print $2}'
    return 0
  fi
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null || true
  fi
}

download_exact_updater() {
  local sha="$1" url
  url="https://raw.githubusercontent.com/caotiensinh/3agent/${sha}/scripts/update_code_safe.sh"
  [[ -z "$TMP_UPDATER" ]] || rm -f "$TMP_UPDATER"
  TMP_UPDATER="$(mktemp)"
  log "Downloading updater pinned to ${sha}"
  curl -fsSL --retry 3 --connect-timeout 15 "$url" -o "$TMP_UPDATER"
  bash -n "$TMP_UPDATER" || die "Downloaded updater failed Bash syntax validation"
  grep -Fq 'FINAL PASS: code updated without deleting prior installation or releases' "$TMP_UPDATER" \
    || die "Downloaded updater does not expose the reviewed non-destructive completion contract"
}

run_safe_update() {
  export THREE_AGENT_REPO_URL="$REPO_URL"
  export THREE_AGENT_REPO_REF="$REPO_REF"
  export THREE_AGENT_INSTALL_DIR="$INSTALL_DIR"
  export THREE_AGENT_BIN_DIR="$BIN_DIR"
  export THREE_AGENT_CONFIG_PATH="$CONFIG_PATH"
  export THREE_AGENT_RELEASES_DIR="$RELEASES_DIR"
  export THREE_AGENT_STATE_DIR="$STATE_DIR"
  export THREE_AGENT_ACTIVATION_LOG="$ACTIVATION_LOG"
  export THREE_AGENT_UPDATE_VERIFY="$VERIFY_MODE"
  unset THREE_AGENT_UPDATE_SCRIPT_URL
  bash "$TMP_UPDATER"
}

verify_final_state() {
  local expected="$1" active
  active="$(active_sha)"
  [[ "$active" == "$expected" ]] || return 1
  [[ -x "${BIN_DIR}/3agent" ]] || die "Installed command is missing: ${BIN_DIR}/3agent"
  [[ -f "$CONFIG_PATH" ]] || die "Configuration file is missing: ${CONFIG_PATH}"
  THREE_AGENT_CONFIG="$CONFIG_PATH" "${BIN_DIR}/3agent" smoke >/dev/null
  return 0
}

main() {
  validate_inputs

  if [[ "$SELF_TEST" == "1" ]]; then
    log "Real Ubuntu update entrypoint self-test PASS"
    exit 0
  fi

  if [[ "$EUID" -eq 0 ]] && ! is_true "$ALLOW_ROOT"; then
    die "Run this updater as the normal Ubuntu user, not with sudo."
  fi

  check_ubuntu_host
  check_commands
  installation_exists || die "No existing WorkSpace installation was detected. Run scripts/deploy_ubuntu_pc.sh first."

  local before expected latest active attempt
  before="$(active_sha)"
  [[ -n "$before" ]] && log "Current commit: ${before}"

  for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
    expected="$(resolve_target_sha)"
    log "Attempt ${attempt}/${MAX_ATTEMPTS}: ${REPO_REF} -> ${expected}"
    download_exact_updater "$expected"
    run_safe_update

    active="$(active_sha)"
    latest="$(resolve_target_sha)"
    if [[ "$active" == "$expected" && "$latest" == "$expected" ]] && verify_final_state "$expected"; then
      log "FINAL PASS: all WorkSpace code is active at ${expected}"
      log "Configuration preserved at: ${CONFIG_PATH}"
      log "Prior releases preserved at: ${RELEASES_DIR}"
      log "Activation history: ${ACTIVATION_LOG}"
      return 0
    fi

    warn "Repository ref moved during update or activation did not match the pinned updater"
    warn "Pinned=${expected} active=${active:-unknown} latest=${latest:-unknown}; retrying safely"
  done

  die "Unable to obtain a stable exact update after ${MAX_ATTEMPTS} attempts; no prior release was deleted"
}

main "$@"
