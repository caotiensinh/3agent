#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${WORKSPACE_REPO_URL:-https://github.com/caotiensinh/3agent.git}"
REPO_REF="${WORKSPACE_REPO_REF:-main}"
INSTALL_DIR="${WORKSPACE_INSTALL_DIR:-/opt/workspace}"
MODEL_OVERRIDE="${WORKSPACE_LLM_MODEL:-}"
FAST_MODEL_OVERRIDE="${WORKSPACE_FAST_MODEL:-}"
HARDWARE_PROFILE="${WORKSPACE_HARDWARE_PROFILE:-auto}"
MIN_DRIVER_MAJOR="${WORKSPACE_MIN_DRIVER_MAJOR:-}"
REQUIRED_RTX5090_COUNT="${WORKSPACE_REQUIRED_RTX5090_COUNT:-}"
AUTO_PULL_MODELS="${WORKSPACE_AUTO_PULL_MODELS:-1}"
LOG_FILE="/var/log/workspace/bootstrap.log"
SELF_TEST=0
CONFIG_TMP=""

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[WorkSpace][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[WorkSpace] %s\n' "$*"; }
warn() { printf '[WorkSpace][WARN] %s\n' "$*" >&2; }
die() { printf '[WorkSpace][ERROR] %s\n' "$*" >&2; exit 1; }
as_root() { if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi; }
is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}
cleanup() {
  if [[ -n "$CONFIG_TMP" && -d "$CONFIG_TMP" ]]; then
    rm -rf -- "$CONFIG_TMP"
  fi
}
trap cleanup EXIT

MODEL=""
FAST_MODEL=""
SYSTEM_RAM_MIB=0
TOTAL_VRAM_MIB=0
GPU_COUNT=0
RTX5090_COUNT=0
NVIDIA_AVAILABLE=0
DRIVER="none"
GPU_NAMES=""

select_models_for_capacity() {
  local vram_mib="$1"
  local ram_mib="$2"
  local selected_model selected_fast

  [[ "$vram_mib" =~ ^[0-9]+$ ]] || die "VRAM capacity must be an integer MiB value"
  [[ "$ram_mib" =~ ^[0-9]+$ ]] || die "RAM capacity must be an integer MiB value"

  # qwen3:30b is ~19 GB. Keep enough headroom for the repo's 88% VRAM
  # budget and 1.15 model-size safety factor instead of selecting it at 24 GB.
  if (( vram_mib >= 28672 )); then
    selected_model="qwen3:30b"
    selected_fast="qwen3:14b"
  elif (( vram_mib >= 16384 )); then
    selected_model="qwen3:14b"
    selected_fast="qwen3:8b"
  elif (( vram_mib >= 8192 )); then
    selected_model="qwen3:8b"
    selected_fast="qwen3:4b"
  elif (( vram_mib >= 4096 )); then
    selected_model="qwen3:4b"
    selected_fast="qwen3:1.7b"
  elif (( ram_mib >= 32768 )); then
    selected_model="qwen3:8b"
    selected_fast="qwen3:4b"
  elif (( ram_mib >= 16384 )); then
    selected_model="qwen3:4b"
    selected_fast="qwen3:1.7b"
  else
    selected_model="qwen3:1.7b"
    selected_fast="qwen3:0.6b"
  fi

  MODEL="${MODEL_OVERRIDE:-$selected_model}"
  FAST_MODEL="${FAST_MODEL_OVERRIDE:-$selected_fast}"
}

detect_hardware() {
  SYSTEM_RAM_MIB="$(awk '/MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || true)"
  [[ "$SYSTEM_RAM_MIB" =~ ^[0-9]+$ ]] || SYSTEM_RAM_MIB=0

  if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi >/dev/null 2>&1; then
    NVIDIA_AVAILABLE=1
    DRIVER="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1 | tr -d '[:space:]')"
    while IFS=',' read -r raw_name raw_mem; do
      local name mem
      name="$(printf '%s' "$raw_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      mem="$(printf '%s' "$raw_mem" | tr -dc '0-9')"
      [[ -n "$name" && "$mem" =~ ^[0-9]+$ ]] || continue
      ((GPU_COUNT += 1))
      ((TOTAL_VRAM_MIB += mem))
      if [[ "$name" == *"RTX 5090"* ]]; then
        ((RTX5090_COUNT += 1))
      fi
      if [[ -z "$GPU_NAMES" ]]; then
        GPU_NAMES="$name"
      else
        GPU_NAMES+="; $name"
      fi
    done < <(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits)
  fi
}

validate_hardware_policy() {
  case "$HARDWARE_PROFILE" in
    auto)
      ;;
    nvidia)
      (( NVIDIA_AVAILABLE == 1 )) || die "WORKSPACE_HARDWARE_PROFILE=nvidia requires a healthy NVIDIA runtime"
      ;;
    dual-rtx5090)
      (( NVIDIA_AVAILABLE == 1 )) || die "dual-rtx5090 profile requires a healthy NVIDIA runtime"
      (( RTX5090_COUNT >= 2 )) || die "dual-rtx5090 profile requires at least 2 RTX 5090 GPUs; found ${RTX5090_COUNT}"
      ;;
    *)
      die "Unsupported WORKSPACE_HARDWARE_PROFILE=${HARDWARE_PROFILE}; use auto, nvidia, or dual-rtx5090"
      ;;
  esac

  if [[ -n "$MIN_DRIVER_MAJOR" ]]; then
    [[ "$MIN_DRIVER_MAJOR" =~ ^[0-9]+$ ]] || die "WORKSPACE_MIN_DRIVER_MAJOR must be an integer when set"
    (( NVIDIA_AVAILABLE == 1 )) || die "WORKSPACE_MIN_DRIVER_MAJOR requires a healthy NVIDIA runtime"
    local driver_major="${DRIVER%%.*}"
    [[ "$driver_major" =~ ^[0-9]+$ ]] || die "Cannot parse NVIDIA driver version: ${DRIVER}"
    (( driver_major >= MIN_DRIVER_MAJOR )) || die "NVIDIA driver ${DRIVER} is below operator-required ${MIN_DRIVER_MAJOR}+"
  fi

  if [[ -n "$REQUIRED_RTX5090_COUNT" ]]; then
    [[ "$REQUIRED_RTX5090_COUNT" =~ ^[0-9]+$ ]] || die "WORKSPACE_REQUIRED_RTX5090_COUNT must be an integer when set"
    (( RTX5090_COUNT >= REQUIRED_RTX5090_COUNT )) \
      || die "Operator requires ${REQUIRED_RTX5090_COUNT} RTX 5090 GPUs; found ${RTX5090_COUNT}"
  fi
}

model_installed() {
  ollama list | awk 'NR>1 {print $1}' | grep -Fxq "$1"
}

ensure_model() {
  local model="$1"
  if model_installed "$model"; then
    log "Reusing installed Ollama model: ${model}"
    return 0
  fi
  if ! is_true "$AUTO_PULL_MODELS"; then
    die "Required model ${model} is not installed and WORKSPACE_AUTO_PULL_MODELS=${AUTO_PULL_MODELS}"
  fi
  log "Pulling hardware-selected Ollama model: ${model}"
  ollama pull "$model"
}

render_model_config() {
  local source="$1"
  local destination="$2"
  python3 - "$source" "$destination" "$MODEL" "$FAST_MODEL" <<'PY'
import json
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
main_model = sys.argv[3]
fast_model = sys.argv[4]

data = json.loads(source.read_text(encoding="utf-8"))
llm = data.get("llm")
policy = data.get("model_policy")
if not isinstance(llm, dict) or not isinstance(policy, dict):
    raise SystemExit(f"model config contract missing in {source}")

llm["model"] = main_model
policy["fast_model"] = fast_model
policy["research_model"] = main_model
policy["presentation_model"] = fast_model
policy["report_model"] = fast_model
policy["deep_model"] = main_model

destination.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

if [[ "$SELF_TEST" == "1" ]]; then
  test_vram="${WORKSPACE_TEST_VRAM_MIB:-0}"
  test_ram="${WORKSPACE_TEST_RAM_MIB:-16384}"
  select_models_for_capacity "$test_vram" "$test_ram"
  printf 'profile=%s vram_mib=%s ram_mib=%s model=%s fast_model=%s\n' \
    "$HARDWARE_PROFILE" "$test_vram" "$test_ram" "$MODEL" "$FAST_MODEL"
  exit 0
fi

TARGET_USER="${SUDO_USER:-${USER:-}}"
[[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]] || die "Run as a normal sudo-capable operator user"

as_root install -d -m 0750 /var/log/workspace
exec > >(as_root tee -a "$LOG_FILE") 2>&1

log "Installing secure WorkSpace runtime prerequisites; NVIDIA driver/kernel are not modified."
as_root apt-get update -y
as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates git jq nftables python3 python3-pip python3-venv sudo

detect_hardware
validate_hardware_policy
select_models_for_capacity "$TOTAL_VRAM_MIB" "$SYSTEM_RAM_MIB"

if (( NVIDIA_AVAILABLE == 1 )); then
  log "Hardware detected: NVIDIA driver=${DRIVER}, gpu_count=${GPU_COUNT}, total_vram=${TOTAL_VRAM_MIB}MiB"
  log "GPU(s): ${GPU_NAMES}"
else
  warn "No healthy NVIDIA runtime detected; continuing with CPU/system-RAM model profile"
fi
log "System RAM: ${SYSTEM_RAM_MIB}MiB"
log "Hardware profile: ${HARDWARE_PROFILE}; selected model=${MODEL}; fast_model=${FAST_MODEL}"

command -v ollama >/dev/null 2>&1 || die "Ollama must be installed locally before secure WorkSpace deployment"
curl_local() { python3 - "$1" <<'PY'
import sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
    response.read(1024)
PY
}
curl_local http://127.0.0.1:11434/api/tags || die "Local Ollama is not reachable on 127.0.0.1:11434"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
  as_root git -C "$INSTALL_DIR" diff --quiet || die "Existing WorkSpace checkout has local changes"
  as_root git -C "$INSTALL_DIR" fetch --prune origin "$REPO_REF"
  as_root git -C "$INSTALL_DIR" checkout "$REPO_REF"
  as_root git -C "$INSTALL_DIR" merge --ff-only "origin/${REPO_REF}"
elif [[ -e "$INSTALL_DIR" ]]; then
  die "${INSTALL_DIR} exists but is not a Git checkout"
else
  as_root git clone --branch "$REPO_REF" --single-branch "$REPO_URL" "$INSTALL_DIR"
fi
EXACT_HEAD="$(as_root git -C "$INSTALL_DIR" rev-parse HEAD)"
log "Source pinned for this installation: ${EXACT_HEAD}"

as_root python3 -m venv "${INSTALL_DIR}/.venv"
as_root "${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
as_root "${INSTALL_DIR}/.venv/bin/python" -m pip install -e "$INSTALL_DIR"

ensure_model "$FAST_MODEL"
if [[ "$MODEL" != "$FAST_MODEL" ]]; then
  ensure_model "$MODEL"
fi

CONFIG_TMP="$(mktemp -d)"
render_model_config "${INSTALL_DIR}/config/workspace.secure.json" "${CONFIG_TMP}/workspace.secure.json"
render_model_config "${INSTALL_DIR}/config/workspace.public-research.json" "${CONFIG_TMP}/workspace.public-research.json"

as_root env WORKSPACE_INSTALL_DIR="$INSTALL_DIR" \
  WORKSPACE_VENV="${INSTALL_DIR}/.venv" \
  WORKSPACE_SECURE_CONFIG_SOURCE="${CONFIG_TMP}/workspace.secure.json" \
  WORKSPACE_PUBLIC_CONFIG_SOURCE="${CONFIG_TMP}/workspace.public-research.json" \
  bash "${INSTALL_DIR}/scripts/install_workspace_secure_boundary.sh"

as_root env WORKSPACE_INSTALL_DIR="$INSTALL_DIR" \
  WORKSPACE_VENV="${INSTALL_DIR}/.venv" \
  bash "${INSTALL_DIR}/scripts/install_workspace_knowledge_plane.sh"

log "Running confidential-mode smoke test under the network-blocked Core identity."
workspace-secure smoke

log "FINAL PASS: WorkSpace secure-local runtime installed."
log "Use: workspace-secure <command>"
log "Public research remains isolated from the Confidential Core."
log "Fresh public knowledge enters only through workspace-knowledge-export -> operator approval -> workspace-knowledge-import."
log "Selected models: main=${MODEL}, fast=${FAST_MODEL}"
log "Source SHA: ${EXACT_HEAD}"
log "Bootstrap log: ${LOG_FILE}"
