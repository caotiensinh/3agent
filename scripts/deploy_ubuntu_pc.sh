#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${THREE_AGENT_REPO_URL:-https://github.com/caotiensinh/3agent.git}"
REPO_REF="${THREE_AGENT_REPO_REF:-main}"
INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-${HOME}/3agent}"
BIN_DIR="${THREE_AGENT_BIN_DIR:-${HOME}/.local/bin}"
CONFIG_PATH="${THREE_AGENT_CONFIG_PATH:-${INSTALL_DIR}/config/local.json}"
MODEL="${THREE_AGENT_MODEL:-}"
INSTALL_OLLAMA="${THREE_AGENT_INSTALL_OLLAMA:-0}"
PULL_MODEL="${THREE_AGENT_PULL_MODEL:-0}"
SKIP_SYSTEM_PACKAGES="${THREE_AGENT_SKIP_SYSTEM_PACKAGES:-0}"
ALLOW_ROOT="${THREE_AGENT_ALLOW_ROOT:-0}"
BOOTSTRAP_URL_OVERRIDE="${THREE_AGENT_BOOTSTRAP_URL:-}"
SELF_TEST=0
TMP_BOOTSTRAP=""
BOOTSTRAP_PATH=""

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[WorkSpace Ubuntu][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[WorkSpace Ubuntu] %s\n' "$*"; }
warn() { printf '[WorkSpace Ubuntu][WARN] %s\n' "$*" >&2; }
die() { printf '[WorkSpace Ubuntu][ERROR] %s\n' "$*" >&2; exit 1; }

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup() {
  if [[ -n "$TMP_BOOTSTRAP" && -f "$TMP_BOOTSTRAP" ]]; then
    rm -f "$TMP_BOOTSTRAP"
  fi
}
trap cleanup EXIT

validate_inputs() {
  [[ -n "$REPO_URL" ]] || die "Repository URL is empty"
  [[ -n "$REPO_REF" ]] || die "Repository ref is empty"
  [[ -n "$INSTALL_DIR" ]] || die "Install directory is empty"
  [[ -n "$BIN_DIR" ]] || die "Binary directory is empty"
  [[ -n "$CONFIG_PATH" ]] || die "Configuration path is empty"

  if [[ ! "$REPO_REF" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    die "Repository ref contains unsupported characters: ${REPO_REF}"
  fi
}

check_ubuntu_host() {
  [[ "$(uname -s)" == "Linux" ]] || die "This entrypoint supports Ubuntu Linux only"
  [[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"

  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Unsupported Linux distribution: ${ID:-unknown}. Ubuntu is required."

  case "${VERSION_ID:-}" in
    22.04|24.04)
      log "Detected Ubuntu ${VERSION_ID}"
      ;;
    *)
      die "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Validated versions are 22.04 and 24.04."
      ;;
  esac
}

resolve_bootstrap() {
  local source_path="${BASH_SOURCE[0]:-}"
  if [[ -n "$source_path" && -f "$source_path" ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "$source_path")" && pwd)"
    if [[ -f "${script_dir}/bootstrap.sh" ]]; then
      BOOTSTRAP_PATH="${script_dir}/bootstrap.sh"
      log "Using repository-local bootstrap: ${BOOTSTRAP_PATH}"
      return 0
    fi
  fi

  command -v curl >/dev/null 2>&1 || die "curl is required to download bootstrap.sh"

  local bootstrap_url
  if [[ -n "$BOOTSTRAP_URL_OVERRIDE" ]]; then
    bootstrap_url="$BOOTSTRAP_URL_OVERRIDE"
  else
    if [[ "$REPO_URL" != "https://github.com/caotiensinh/3agent.git" ]]; then
      die "A custom THREE_AGENT_REPO_URL requires THREE_AGENT_BOOTSTRAP_URL to avoid mixing repositories"
    fi
    bootstrap_url="https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/bootstrap.sh"
  fi

  TMP_BOOTSTRAP="$(mktemp)"
  BOOTSTRAP_PATH="$TMP_BOOTSTRAP"
  log "Downloading canonical bootstrap"
  curl -fsSL --retry 3 --connect-timeout 15 "$bootstrap_url" -o "$BOOTSTRAP_PATH"
  bash -n "$BOOTSTRAP_PATH" || die "Downloaded bootstrap.sh failed Bash syntax validation"
}

run_bootstrap() {
  resolve_bootstrap
  [[ -n "$BOOTSTRAP_PATH" && -f "$BOOTSTRAP_PATH" ]] || die "bootstrap.sh could not be resolved"

  export THREE_AGENT_REPO_URL="$REPO_URL"
  export THREE_AGENT_REPO_REF="$REPO_REF"
  export THREE_AGENT_INSTALL_DIR="$INSTALL_DIR"
  export THREE_AGENT_BIN_DIR="$BIN_DIR"
  export THREE_AGENT_CONFIG_PATH="$CONFIG_PATH"
  export THREE_AGENT_MODEL="$MODEL"
  export THREE_AGENT_INSTALL_OLLAMA="$INSTALL_OLLAMA"
  export THREE_AGENT_PULL_MODEL="$PULL_MODEL"
  export THREE_AGENT_SKIP_SYSTEM_PACKAGES="$SKIP_SYSTEM_PACKAGES"

  bash "$BOOTSTRAP_PATH"
}

verify_result() {
  local command_path="${BIN_DIR}/3agent"
  [[ -x "$command_path" ]] || die "Installed command is missing: ${command_path}"
  [[ -f "$CONFIG_PATH" ]] || die "Configuration file is missing: ${CONFIG_PATH}"

  "$command_path" smoke >/dev/null

  if [[ -d "${INSTALL_DIR}/.git" ]] && command -v git >/dev/null 2>&1; then
    log "Installed commit: $(git -C "$INSTALL_DIR" rev-parse HEAD)"
  fi

  log "FINAL PASS: WorkSpace is deployed on this Ubuntu PC"
  log "Install directory: ${INSTALL_DIR}"
  log "Command: ${command_path}"
  log "Update: ${BIN_DIR}/3agent-update"
  if [[ -z "$MODEL" ]]; then
    warn "No local LLM model was selected. Core CLI/smoke is ready; live AI agents require a configured model."
  fi
}

main() {
  validate_inputs

  if [[ "$SELF_TEST" == "1" ]]; then
    log "Ubuntu deployment entrypoint self-test PASS"
    exit 0
  fi

  if [[ "$EUID" -eq 0 ]] && ! is_true "$ALLOW_ROOT"; then
    die "Run this script as the normal Ubuntu user, not with sudo. The installer will request sudo only for required system packages."
  fi

  check_ubuntu_host
  run_bootstrap
  verify_result
}

main "$@"
