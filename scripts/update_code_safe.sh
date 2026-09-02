#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${THREE_AGENT_REPO_URL:-https://github.com/caotiensinh/3agent.git}"
REPO_REF="${THREE_AGENT_REPO_REF:-main}"
LEGACY_INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-${HOME}/3agent}"
BIN_DIR="${THREE_AGENT_BIN_DIR:-${HOME}/.local/bin}"
CONFIG_PATH="${THREE_AGENT_CONFIG_PATH:-${LEGACY_INSTALL_DIR}/config/local.json}"
RELEASES_DIR="${THREE_AGENT_RELEASES_DIR:-${HOME}/.local/share/workspace/releases}"
STATE_DIR="${THREE_AGENT_STATE_DIR:-${HOME}/.local/state/workspace}"
ACTIVATION_LOG="${THREE_AGENT_ACTIVATION_LOG:-${STATE_DIR}/active-releases.log}"
VERIFY_MODE="${THREE_AGENT_UPDATE_VERIFY:-smoke}"
UPDATE_SCRIPT_URL="${THREE_AGENT_UPDATE_SCRIPT_URL:-}"
CANONICAL_REPO_URL="https://github.com/caotiensinh/3agent.git"
SELF_TEST=0
CREATED_RELEASE=""

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[WorkSpace Update][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[WorkSpace Update] %s\n' "$*"; }
warn() { printf '[WorkSpace Update][WARN] %s\n' "$*" >&2; }
die() { printf '[WorkSpace Update][ERROR] %s\n' "$*" >&2; exit 1; }

validate_inputs() {
  [[ -n "$REPO_URL" ]] || die "Repository URL is empty"
  [[ -n "$REPO_REF" ]] || die "Repository ref is empty"
  [[ -n "$BIN_DIR" ]] || die "Binary directory is empty"
  [[ -n "$CONFIG_PATH" ]] || die "Configuration path is empty"
  [[ -n "$RELEASES_DIR" ]] || die "Release directory is empty"
  [[ -n "$STATE_DIR" ]] || die "State directory is empty"
  [[ -n "$ACTIVATION_LOG" ]] || die "Activation log is empty"
  case "$VERIFY_MODE" in
    smoke|full) ;;
    *) die "THREE_AGENT_UPDATE_VERIFY must be 'smoke' or 'full'" ;;
  esac
}

check_commands() {
  local cmd
  for cmd in git python3; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
  done
  python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(f"Python >=3.11 is required; detected {sys.version.split()[0]}")
PY
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

current_release() {
  [[ -f "$ACTIVATION_LOG" ]] || return 1
  tail -n 1 "$ACTIVATION_LOG" | awk -F '\t' 'NF >= 3 {print $3}'
}

current_release_matches() {
  local target_sha="$1" release
  release="$(current_release || true)"
  [[ -n "$release" && -d "${release}/.git" ]] || return 1
  [[ "$(git -C "$release" rev-parse HEAD 2>/dev/null || true)" == "$target_sha" ]]
}

create_release_checkout() {
  local target_sha="$1" release
  mkdir -p "$RELEASES_DIR"
  release="$(mktemp -d "${RELEASES_DIR}/release-${target_sha:0:12}-XXXXXXXX")"
  log "Creating immutable release: ${release}"

  if ! git clone --filter=blob:none --no-checkout "$REPO_URL" "$release"; then
    warn "Partial clone failed; the failed candidate is preserved for audit and a full clone will be attempted"
    release="$(mktemp -d "${RELEASES_DIR}/release-${target_sha:0:12}-fallback-XXXXXXXX")"
    git clone --no-checkout "$REPO_URL" "$release"
  fi

  if ! git -C "$release" cat-file -e "${target_sha}^{commit}" 2>/dev/null; then
    git -C "$release" fetch --no-tags origin "$REPO_REF"
  fi
  git -C "$release" checkout --detach "$target_sha"

  [[ "$(git -C "$release" rev-parse HEAD)" == "$target_sha" ]] || die "Release checkout lineage mismatch"
  CREATED_RELEASE="$release"
}

ensure_config() {
  local release="$1"
  if [[ -f "$CONFIG_PATH" ]]; then
    log "Preserving existing configuration: ${CONFIG_PATH}"
    return 0
  fi
  mkdir -p "$(dirname "$CONFIG_PATH")"
  cp -p "${release}/config/test.example.json" "$CONFIG_PATH"
  log "Created configuration without modifying any existing file: ${CONFIG_PATH}"
}

build_release() {
  local release="$1"
  log "Building isolated environment in new release"
  python3 -m venv "${release}/.venv"
  "${release}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
  "${release}/.venv/bin/python" -m pip install -e "$release"
}

verify_release() {
  local release="$1"
  log "Verifying new release before activation"
  "${release}/.venv/bin/python" -m compileall -q "${release}/src" "${release}/tests"
  THREE_AGENT_CONFIG="$CONFIG_PATH" "${release}/.venv/bin/three-agent" smoke >/dev/null

  if [[ "$VERIFY_MODE" == "full" ]]; then
    (cd "$release" && "${release}/.venv/bin/python" -m unittest discover -s tests -v)
  fi
}

backup_launcher() {
  local path="$1" stamp backup_dir
  [[ -e "$path" || -L "$path" ]] || return 0
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_dir="${STATE_DIR}/launcher-history"
  mkdir -p "$backup_dir"
  cp -a "$path" "${backup_dir}/$(basename "$path").${stamp}.$$"
}

resolve_update_script_url() {
  if [[ -n "$UPDATE_SCRIPT_URL" ]]; then
    return 0
  fi
  if [[ "$REPO_URL" != "$CANONICAL_REPO_URL" ]]; then
    die "A custom THREE_AGENT_REPO_URL requires THREE_AGENT_UPDATE_SCRIPT_URL"
  fi
  UPDATE_SCRIPT_URL="https://raw.githubusercontent.com/caotiensinh/3agent/${REPO_REF}/scripts/update_code_safe.sh"
}

install_launchers() {
  mkdir -p "$BIN_DIR" "$STATE_DIR"
  resolve_update_script_url
  backup_launcher "${BIN_DIR}/3agent"
  backup_launcher "${BIN_DIR}/3agent-update"

  cat >"${BIN_DIR}/3agent" <<EOF_LAUNCHER
#!/usr/bin/env bash
set -euo pipefail
activation_log=$(printf '%q' "$ACTIVATION_LOG")
config_path=$(printf '%q' "$CONFIG_PATH")
[[ -f "\$activation_log" ]] || { echo '[WorkSpace][ERROR] No active release' >&2; exit 1; }
release="\$(tail -n 1 "\$activation_log" | awk -F '\\t' 'NF >= 3 {print \$3}')"
[[ -n "\$release" && -x "\$release/.venv/bin/three-agent" ]] || { echo '[WorkSpace][ERROR] Active release is invalid' >&2; exit 1; }
export THREE_AGENT_CONFIG="\$config_path"
exec "\$release/.venv/bin/three-agent" "\$@"
EOF_LAUNCHER
  chmod 0755 "${BIN_DIR}/3agent"

  cat >"${BIN_DIR}/3agent-update" <<EOF_UPDATER
#!/usr/bin/env bash
set -euo pipefail
export THREE_AGENT_REPO_URL=$(printf '%q' "$REPO_URL")
export THREE_AGENT_REPO_REF=$(printf '%q' "$REPO_REF")
export THREE_AGENT_INSTALL_DIR=$(printf '%q' "$LEGACY_INSTALL_DIR")
export THREE_AGENT_BIN_DIR=$(printf '%q' "$BIN_DIR")
export THREE_AGENT_CONFIG_PATH=$(printf '%q' "$CONFIG_PATH")
export THREE_AGENT_RELEASES_DIR=$(printf '%q' "$RELEASES_DIR")
export THREE_AGENT_STATE_DIR=$(printf '%q' "$STATE_DIR")
export THREE_AGENT_ACTIVATION_LOG=$(printf '%q' "$ACTIVATION_LOG")
export THREE_AGENT_UPDATE_SCRIPT_URL=$(printf '%q' "$UPDATE_SCRIPT_URL")
exec bash -c $(printf '%q' "curl -fsSL --retry 3 --connect-timeout 15 '${UPDATE_SCRIPT_URL}' | bash")
EOF_UPDATER
  chmod 0755 "${BIN_DIR}/3agent-update"
}

activate_release() {
  local release="$1" target_sha="$2" timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$STATE_DIR"
  printf '%s\t%s\t%s\n' "$timestamp" "$target_sha" "$release" >> "$ACTIVATION_LOG"
  log "Activated release ${target_sha}"
}

main() {
  validate_inputs
  if [[ "$SELF_TEST" == "1" ]]; then
    log "Non-destructive updater self-test PASS"
    exit 0
  fi

  check_commands
  local target_sha active release
  target_sha="$(resolve_target_sha)"
  log "Resolved ${REPO_REF} -> ${target_sha}"

  if current_release_matches "$target_sha"; then
    active="$(current_release)"
    ensure_config "$active"
    install_launchers
    THREE_AGENT_CONFIG="$CONFIG_PATH" "${BIN_DIR}/3agent" smoke >/dev/null
    log "Already current at ${target_sha}; no release files changed"
    exit 0
  fi

  create_release_checkout "$target_sha"
  release="$CREATED_RELEASE"
  ensure_config "$release"
  build_release "$release"
  verify_release "$release"
  install_launchers
  activate_release "$release" "$target_sha"
  THREE_AGENT_CONFIG="$CONFIG_PATH" "${BIN_DIR}/3agent" smoke >/dev/null

  log "FINAL PASS: code updated without deleting prior installation or releases"
  log "Previous installation preserved: ${LEGACY_INSTALL_DIR}"
  log "New release: ${release}"
  log "Commit: ${target_sha}"
  log "Activation history: ${ACTIVATION_LOG}"
}

main "$@"
