#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${THREE_AGENT_REPO_URL:-https://github.com/caotiensinh/3agent.git}"
REPO_REF="${THREE_AGENT_REPO_REF:-main}"
MODEL="${THREE_AGENT_MODEL:-qwen3:30b}"
INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-}"
STRICT_POINT_RELEASE="${THREE_AGENT_STRICT_POINT_RELEASE:-1}"
AUTO_REBOOT="${THREE_AGENT_AUTO_REBOOT:-1}"
MIN_DRIVER_MAJOR="${THREE_AGENT_MIN_DRIVER_MAJOR:-570}"
REQUIRED_RTX5090_COUNT="${THREE_AGENT_REQUIRED_RTX5090_COUNT:-2}"
OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-32768}"
BOOTSTRAP_ROOT="/var/lib/3agent-bootstrap"
BOOTSTRAP_ENV="/etc/3agent/bootstrap.env"
RESUME_SCRIPT="/usr/local/lib/3agent/install_ubuntu_2404_rtx5090.sh"
RESUME_SERVICE="/etc/systemd/system/3agent-bootstrap-resume.service"
SCRIPT_URL="https://raw.githubusercontent.com/caotiensinh/3agent/${REPO_REF}/scripts/install_ubuntu_2404_rtx5090.sh"
LOG_FILE="${BOOTSTRAP_ROOT}/install.log"
RESUME_MODE=0
SELF_TEST=0

for arg in "$@"; do
  case "$arg" in
    --resume) RESUME_MODE=1 ;;
    --self-test) SELF_TEST=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '[3Agent] %s\n' "$*"; }
warn() { printf '[3Agent][WARN] %s\n' "$*" >&2; }
die() { printf '[3Agent][ERROR] %s\n' "$*" >&2; exit 1; }

if [[ "$SELF_TEST" == "1" ]]; then
  [[ "$REPO_URL" == https://github.com/*/*.git ]] || die "Invalid default repository URL"
  [[ "$MIN_DRIVER_MAJOR" =~ ^[0-9]+$ ]] || die "MIN_DRIVER_MAJOR must be numeric"
  [[ "$REQUIRED_RTX5090_COUNT" =~ ^[0-9]+$ ]] || die "GPU count must be numeric"
  [[ "$OLLAMA_CONTEXT_LENGTH" =~ ^[0-9]+$ ]] || die "OLLAMA_CONTEXT_LENGTH must be numeric"
  log "installer self-test PASS"
  exit 0
fi

if [[ "$EUID" -eq 0 ]]; then
  if [[ -f "$BOOTSTRAP_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$BOOTSTRAP_ENV"
  fi
  TARGET_USER="${TARGET_USER:-${SUDO_USER:-}}"
else
  TARGET_USER="${TARGET_USER:-${USER:-}}"
fi
[[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]] || die "Run as a normal sudo-capable user, or set TARGET_USER when resuming as root."

TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[[ -n "$TARGET_HOME" ]] || die "Unable to determine home directory for $TARGET_USER"
INSTALL_DIR="${INSTALL_DIR:-${TARGET_HOME}/3agent}"

as_root() {
  if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

as_user() {
  if [[ "$(id -un)" == "$TARGET_USER" ]]; then
    "$@"
  elif [[ "$EUID" -eq 0 ]]; then
    runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" USER="$TARGET_USER" "$@"
  else
    sudo -u "$TARGET_USER" env HOME="$TARGET_HOME" USER="$TARGET_USER" "$@"
  fi
}

ensure_base_dirs() {
  as_root mkdir -p "$BOOTSTRAP_ROOT" /etc/3agent /usr/local/lib/3agent
  as_root touch "$LOG_FILE"
  as_root chmod 0644 "$LOG_FILE"
}

persist_bootstrap_env() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<ENV
TARGET_USER=$(printf '%q' "$TARGET_USER")
TARGET_HOME=$(printf '%q' "$TARGET_HOME")
THREE_AGENT_REPO_URL=$(printf '%q' "$REPO_URL")
THREE_AGENT_REPO_REF=$(printf '%q' "$REPO_REF")
THREE_AGENT_MODEL=$(printf '%q' "$MODEL")
THREE_AGENT_INSTALL_DIR=$(printf '%q' "$INSTALL_DIR")
THREE_AGENT_STRICT_POINT_RELEASE=$(printf '%q' "$STRICT_POINT_RELEASE")
THREE_AGENT_AUTO_REBOOT=$(printf '%q' "$AUTO_REBOOT")
THREE_AGENT_MIN_DRIVER_MAJOR=$(printf '%q' "$MIN_DRIVER_MAJOR")
THREE_AGENT_REQUIRED_RTX5090_COUNT=$(printf '%q' "$REQUIRED_RTX5090_COUNT")
OLLAMA_CONTEXT_LENGTH=$(printf '%q' "$OLLAMA_CONTEXT_LENGTH")
ENV
  as_root install -m 0600 "$tmp" "$BOOTSTRAP_ENV"
  rm -f "$tmp"
}

install_resume_script() {
  as_root curl -fsSL "$SCRIPT_URL" -o "$RESUME_SCRIPT"
  as_root chmod 0755 "$RESUME_SCRIPT"
  as_root tee "$RESUME_SERVICE" >/dev/null <<SERVICE
[Unit]
Description=Resume 3Agent bootstrap after NVIDIA driver reboot
After=network-online.target
Wants=network-online.target
ConditionPathExists=${BOOTSTRAP_ROOT}/resume-required

[Service]
Type=oneshot
ExecStart=/usr/bin/bash ${RESUME_SCRIPT} --resume
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
SERVICE
  as_root systemctl daemon-reload
  as_root systemctl enable 3agent-bootstrap-resume.service >/dev/null
}

clear_resume() {
  as_root rm -f "${BOOTSTRAP_ROOT}/resume-required"
  if [[ -f "$RESUME_SERVICE" ]]; then
    as_root systemctl disable 3agent-bootstrap-resume.service >/dev/null 2>&1 || true
    as_root rm -f "$RESUME_SERVICE"
    as_root systemctl daemon-reload
  fi
}

check_os() {
  [[ -r /etc/os-release ]] || die "/etc/os-release not found"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Ubuntu is required; detected ${ID:-unknown}"
  [[ "${VERSION_ID:-}" == "24.04" ]] || die "Ubuntu 24.04 LTS is required; detected ${VERSION_ID:-unknown}"

  local desc
  if command -v lsb_release >/dev/null 2>&1; then
    desc="$(lsb_release -ds 2>/dev/null || true)"
  elif [[ -r /etc/lsb-release ]]; then
    # shellcheck disable=SC1091
    source /etc/lsb-release
    desc="${DISTRIB_DESCRIPTION:-}"
  else
    desc="${PRETTY_NAME:-Ubuntu 24.04}"
  fi
  if [[ "$STRICT_POINT_RELEASE" == "1" && "$desc" != *"24.04.4"* ]]; then
    die "Ubuntu 24.04.4 is required in strict mode; detected: ${desc:-unknown}. Set THREE_AGENT_STRICT_POINT_RELEASE=0 to allow another 24.04.x point release."
  fi
  log "OS check PASS: ${desc:-Ubuntu 24.04}"
}

install_base_packages() {
  log "Installing base packages"
  as_root apt-get update -y
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl git jq lsb-release pciutils python3 python3-pip python3-venv \
    ubuntu-drivers-common mokutil
}

secure_boot_state() {
  mokutil --sb-state 2>/dev/null || true
}

nvidia_healthy() {
  command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi >/dev/null 2>&1
}

select_open_driver_package() {
  local pkg
  pkg="$(apt-cache search --names-only '^nvidia-driver-[0-9]+-open$' \
    | awk '{print $1}' \
    | awk -F'[-]' -v min="$MIN_DRIVER_MAJOR" '$3+0 >= min {print $0}' \
    | sort -t- -k3,3nr \
    | head -n1)"
  [[ -n "$pkg" ]] || return 1
  printf '%s\n' "$pkg"
}

install_nvidia_driver_if_needed() {
  if nvidia_healthy; then
    log "Existing NVIDIA driver is healthy; preserving it."
    return 0
  fi

  local sb pkg
  sb="$(secure_boot_state)"
  if [[ "$sb" == *"enabled"* ]]; then
    die "NVIDIA driver is not healthy and Secure Boot is enabled. Disable Secure Boot (or enroll the required MOK) before unattended driver installation."
  fi

  pkg="$(select_open_driver_package || true)"
  [[ -n "$pkg" ]] || die "No nvidia-driver-*-open package >= ${MIN_DRIVER_MAJOR} found in configured Ubuntu repositories."
  log "NVIDIA driver is missing/unhealthy; installing ${pkg}"
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"

  ensure_base_dirs
  persist_bootstrap_env
  install_resume_script
  as_root touch "${BOOTSTRAP_ROOT}/resume-required"
  log "Driver installed. A reboot is required; bootstrap is configured to resume automatically."
  if [[ "$AUTO_REBOOT" == "1" ]]; then
    log "Rebooting now. The systemd resume service will continue deployment automatically."
    as_root systemctl reboot
    exit 0
  fi
  die "Reboot required. Reboot the PC once; deployment will resume automatically."
}

verify_dual_rtx5090() {
  nvidia_healthy || die "nvidia-smi is not healthy after driver setup"

  local driver_major count names
  driver_major="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1 | cut -d. -f1)"
  [[ "$driver_major" =~ ^[0-9]+$ ]] || die "Cannot parse NVIDIA driver version"
  (( driver_major >= MIN_DRIVER_MAJOR )) || die "NVIDIA driver ${driver_major} is below required major ${MIN_DRIVER_MAJOR}"

  names="$(nvidia-smi --query-gpu=name --format=csv,noheader)"
  count="$(grep -Eic 'RTX[[:space:]]*5090|GeForce RTX 5090' <<<"$names" || true)"
  (( count >= REQUIRED_RTX5090_COUNT )) || die "Expected at least ${REQUIRED_RTX5090_COUNT} RTX 5090 GPUs; detected ${count}. GPU list: ${names//$'\n'/, }"
  log "GPU check PASS: ${count} RTX 5090 GPU(s), driver $(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1)"
}

rtx5090_uuid_csv() {
  nvidia-smi --query-gpu=name,uuid --format=csv,noheader \
    | awk -F', ' '/RTX[[:space:]]*5090/ {print $2}' \
    | head -n "$REQUIRED_RTX5090_COUNT" \
    | paste -sd, -
}

install_ollama() {
  if ! command -v ollama >/dev/null 2>&1; then
    log "Installing Ollama"
    curl -fsSL https://ollama.com/install.sh | as_root sh
  else
    log "Ollama already installed: $(ollama --version 2>/dev/null || true)"
  fi

  local gpu_uuids
  gpu_uuids="$(rtx5090_uuid_csv)"
  [[ -n "$gpu_uuids" ]] || die "Unable to resolve RTX 5090 GPU UUIDs"

  as_root mkdir -p /etc/systemd/system/ollama.service.d
  as_root tee /etc/systemd/system/ollama.service.d/3agent.conf >/dev/null <<OVERRIDE
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="CUDA_VISIBLE_DEVICES=${gpu_uuids}"
Environment="OLLAMA_CONTEXT_LENGTH=${OLLAMA_CONTEXT_LENGTH}"
OVERRIDE
  as_root systemctl daemon-reload
  as_root systemctl enable --now ollama

  local i
  for i in {1..30}; do
    if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      log "Ollama service PASS"
      return 0
    fi
    sleep 2
  done
  die "Ollama did not become ready on 127.0.0.1:11434"
}

checkout_project() {
  log "Deploying repository to ${INSTALL_DIR}"
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    if ! as_user git -C "$INSTALL_DIR" diff --quiet || ! as_user git -C "$INSTALL_DIR" diff --cached --quiet; then
      die "Existing checkout has local changes: ${INSTALL_DIR}. Commit/stash them before deployment."
    fi
    as_user git -C "$INSTALL_DIR" fetch --prune origin "$REPO_REF"
    as_user git -C "$INSTALL_DIR" checkout "$REPO_REF"
    as_user git -C "$INSTALL_DIR" pull --ff-only origin "$REPO_REF"
  elif [[ -e "$INSTALL_DIR" ]]; then
    die "Install path exists but is not a Git checkout: ${INSTALL_DIR}"
  else
    as_user git clone --branch "$REPO_REF" --single-branch "$REPO_URL" "$INSTALL_DIR"
  fi
}

setup_python() {
  log "Creating Python virtual environment"
  as_user python3 -m venv "${INSTALL_DIR}/.venv"
  as_user "${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
  as_user "${INSTALL_DIR}/.venv/bin/pip" install -e "$INSTALL_DIR"

  if [[ ! -f "${INSTALL_DIR}/config/local.json" ]]; then
    as_user cp "${INSTALL_DIR}/config/test.example.json" "${INSTALL_DIR}/config/local.json"
  fi

  as_user python3 - "$INSTALL_DIR/config/local.json" "$MODEL" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
model = sys.argv[2]
data = json.loads(path.read_text(encoding="utf-8"))
data["llm"]["model"] = model
data["llm"]["base_url"] = "http://127.0.0.1:11434"
data["test_mode_full_access"] = True
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

pull_model() {
  log "Ensuring local model is present: ${MODEL}"
  as_user ollama pull "$MODEL"
}

install_user_command() {
  local wrapper="/usr/local/bin/3agent"
  as_root tee "$wrapper" >/dev/null <<WRAPPER
#!/usr/bin/env bash
set -euo pipefail
export THREE_AGENT_CONFIG="${INSTALL_DIR}/config/local.json"
cd "${INSTALL_DIR}"
exec "${INSTALL_DIR}/.venv/bin/three-agent" "\$@"
WRAPPER
  as_root chmod 0755 "$wrapper"
}

verify_deployment() {
  log "Running deployment verification"
  as_user env THREE_AGENT_CONFIG="${INSTALL_DIR}/config/local.json" \
    "${INSTALL_DIR}/.venv/bin/three-agent" init
  as_user env THREE_AGENT_CONFIG="${INSTALL_DIR}/config/local.json" \
    "${INSTALL_DIR}/.venv/bin/three-agent" smoke
  as_user bash "${INSTALL_DIR}/scripts/verify_deployment.sh" "$MODEL"
}

main() {
  ensure_base_dirs
  exec > >(as_root tee -a "$LOG_FILE") 2>&1
  log "Starting 3Agent Ubuntu 24.04.4 / dual RTX 5090 deployment"
  persist_bootstrap_env
  check_os
  install_base_packages
  install_nvidia_driver_if_needed
  verify_dual_rtx5090
  clear_resume
  install_ollama
  checkout_project
  setup_python
  install_user_command
  pull_model
  verify_deployment
  log "DEPLOYMENT PASS"
  log "Command: 3agent smoke"
  log "Project: ${INSTALL_DIR}"
  log "Model: ${MODEL}"
  log "Log: ${LOG_FILE}"
}

main
