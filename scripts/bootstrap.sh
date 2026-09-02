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
SELF_TEST=0
CANONICAL_REPO_URL="https://github.com/caotiensinh/3agent.git"
RELEASES_DIR="${THREE_AGENT_RELEASES_DIR:-${HOME}/.local/share/workspace/releases}"
STATE_DIR="${THREE_AGENT_STATE_DIR:-${HOME}/.local/state/workspace}"
ACTIVATION_LOG="${THREE_AGENT_ACTIVATION_LOG:-${STATE_DIR}/active-releases.log}"
UPDATE_SCRIPT_URL="${THREE_AGENT_UPDATE_SCRIPT_URL:-}"

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[3Agent][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[3Agent] %s\n' "$*"; }
warn() { printf '[3Agent][WARN] %s\n' "$*" >&2; }
die() { printf '[3Agent][ERROR] %s\n' "$*" >&2; exit 1; }

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ "$SELF_TEST" == "1" ]]; then
  [[ -n "$REPO_URL" ]] || die "Repository URL is empty"
  [[ -n "$REPO_REF" ]] || die "Repository ref is empty"
  [[ -n "$INSTALL_DIR" ]] || die "Install directory is empty"
  [[ -n "$BIN_DIR" ]] || die "Binary directory is empty"
  log "Portable bootstrap self-test PASS"
  exit 0
fi

[[ "$(uname -s)" == "Linux" ]] || die "Portable bootstrap currently supports Linux only"

run_root() {
  if [[ "$EUID" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "Root privileges are required to install missing system packages, but sudo is unavailable"
  fi
}

install_system_packages() {
  if is_true "$SKIP_SYSTEM_PACKAGES"; then
    log "Skipping system package installation by request"
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    run_root apt-get update -y
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ca-certificates curl git python3 python3-pip python3-venv
  elif command -v dnf >/dev/null 2>&1; then
    run_root dnf install -y ca-certificates curl git python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    run_root yum install -y ca-certificates curl git python3 python3-pip
  else
    warn "Unsupported package manager. Expecting curl, git and Python >=3.11 to already exist."
  fi
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

install_ollama_if_requested() {
  if ! is_true "$INSTALL_OLLAMA"; then
    return 0
  fi
  if command -v ollama >/dev/null 2>&1; then
    log "Ollama already installed: $(ollama --version 2>&1 | head -n1)"
    return 0
  fi
  log "Installing Ollama from the official installer"
  local tmp
  tmp="$(mktemp)"
  curl -fsSL https://ollama.com/install.sh -o "$tmp"
  sh "$tmp"
  rm -f "$tmp"
  command -v ollama >/dev/null 2>&1 || die "Ollama installation failed"
}

clean_workspace_generated_artifacts() {
  log "Cleaning only WorkSpace-owned generated artifacts"

  rm -rf -- \
    "${INSTALL_DIR}/.venv" \
    "${INSTALL_DIR}/src/workspace_local_ai.egg-info"

  local root
  for root in "${INSTALL_DIR}/src" "${INSTALL_DIR}/tests"; do
    if [[ -d "$root" ]]; then
      find "$root" -type d -name __pycache__ -prune -exec rm -rf -- {} +
    fi
  done
}

deploy_repository() {
  log "Deploying repository ref '${REPO_REF}' into ${INSTALL_DIR}"
  mkdir -p "$(dirname "$INSTALL_DIR")"

  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    if ! git -C "$INSTALL_DIR" diff --quiet || ! git -C "$INSTALL_DIR" diff --cached --quiet; then
      die "Existing checkout has uncommitted changes: ${INSTALL_DIR}"
    fi
    git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
  elif [[ -e "$INSTALL_DIR" ]]; then
    die "Install path exists but is not a Git checkout: ${INSTALL_DIR}"
  else
    git clone --no-checkout "$REPO_URL" "$INSTALL_DIR"
  fi

  git -C "$INSTALL_DIR" fetch --prune origin "$REPO_REF"
  local resolved
  resolved="$(git -C "$INSTALL_DIR" rev-parse FETCH_HEAD)"
  git -C "$INSTALL_DIR" checkout --detach "$resolved"
  clean_workspace_generated_artifacts
  log "Repository deployed at commit ${resolved}"
}

install_python_env() {
  log "Creating/updating isolated Python environment"
  python3 -m venv "${INSTALL_DIR}/.venv"
  "${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
  "${INSTALL_DIR}/.venv/bin/python" -m pip install -e "$INSTALL_DIR"
}

set_model_in_config() {
  [[ -n "$MODEL" ]] || return 0
  "${INSTALL_DIR}/.venv/bin/python" - "$CONFIG_PATH" "$MODEL" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
model = sys.argv[2]
data = json.loads(path.read_text(encoding="utf-8"))
data.setdefault("llm", {})["model"] = model
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

write_config() {
  if [[ -f "$CONFIG_PATH" ]]; then
    log "Preserving existing configuration: ${CONFIG_PATH}"
  else
    mkdir -p "$(dirname "$CONFIG_PATH")"
    cp "${INSTALL_DIR}/config/test.example.json" "$CONFIG_PATH"
    log "Created configuration: ${CONFIG_PATH}"
  fi
  set_model_in_config
}

resolve_update_script_url() {
  if [[ -n "$UPDATE_SCRIPT_URL" ]]; then
    return 0
  fi
  if [[ "$REPO_URL" != "$CANONICAL_REPO_URL" ]]; then
    die "A custom THREE_AGENT_REPO_URL requires THREE_AGENT_UPDATE_SCRIPT_URL for the generated updater"
  fi
  UPDATE_SCRIPT_URL="https://raw.githubusercontent.com/caotiensinh/3agent/${REPO_REF}/scripts/update_code_safe.sh"
}

install_launchers() {
  mkdir -p "$BIN_DIR"
  resolve_update_script_url

  cat >"${BIN_DIR}/3agent" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd $(printf '%q' "$INSTALL_DIR")
export THREE_AGENT_CONFIG=$(printf '%q' "$CONFIG_PATH")
exec $(printf '%q' "${INSTALL_DIR}/.venv/bin/three-agent") "\$@"
EOF
  chmod 0755 "${BIN_DIR}/3agent"

  cat >"${BIN_DIR}/3agent-update" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export THREE_AGENT_REPO_URL=$(printf '%q' "$REPO_URL")
export THREE_AGENT_REPO_REF=$(printf '%q' "$REPO_REF")
export THREE_AGENT_INSTALL_DIR=$(printf '%q' "$INSTALL_DIR")
export THREE_AGENT_BIN_DIR=$(printf '%q' "$BIN_DIR")
export THREE_AGENT_CONFIG_PATH=$(printf '%q' "$CONFIG_PATH")
export THREE_AGENT_RELEASES_DIR=$(printf '%q' "$RELEASES_DIR")
export THREE_AGENT_STATE_DIR=$(printf '%q' "$STATE_DIR")
export THREE_AGENT_ACTIVATION_LOG=$(printf '%q' "$ACTIVATION_LOG")
export THREE_AGENT_UPDATE_SCRIPT_URL=$(printf '%q' "$UPDATE_SCRIPT_URL")
exec bash -c $(printf '%q' "curl -fsSL --retry 3 --connect-timeout 15 '${UPDATE_SCRIPT_URL}' | bash")
EOF
  chmod 0755 "${BIN_DIR}/3agent-update"

  case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *) warn "${BIN_DIR} is not in PATH. Add: export PATH=\"${BIN_DIR}:\$PATH\"" ;;
  esac
}

pull_model_if_requested() {
  if ! is_true "$PULL_MODEL"; then
    return 0
  fi
  [[ -n "$MODEL" ]] || die "THREE_AGENT_PULL_MODEL=1 requires THREE_AGENT_MODEL to be set"
  command -v ollama >/dev/null 2>&1 || die "Ollama is required to pull model '${MODEL}'"
  log "Pulling Ollama model: ${MODEL}"
  ollama pull "$MODEL"
}

verify_install() {
  log "Running compile and unit tests"
  "${INSTALL_DIR}/.venv/bin/python" -m compileall -q "${INSTALL_DIR}/src" "${INSTALL_DIR}/tests"
  (cd "$INSTALL_DIR" && "${INSTALL_DIR}/.venv/bin/python" -m unittest discover -s tests -v)

  log "Running application smoke check"
  THREE_AGENT_CONFIG="$CONFIG_PATH" "${INSTALL_DIR}/.venv/bin/three-agent" smoke >/dev/null

  log "FINAL PASS: portable 3Agent deployment is ready"
  log "Commit: $(git -C "$INSTALL_DIR" rev-parse HEAD)"
  log "Install: ${INSTALL_DIR}"
  log "Command: ${BIN_DIR}/3agent"
  log "Update: ${BIN_DIR}/3agent-update"
  if [[ -z "$MODEL" ]]; then
    warn "No local LLM model was configured. Smoke/CLI works; live agents require Ollama plus a configured model."
  fi
}

main() {
  install_system_packages
  check_commands
  install_ollama_if_requested
  deploy_repository
  install_python_env
  write_config
  install_launchers
  pull_model_if_requested
  verify_install
}

main "$@"
