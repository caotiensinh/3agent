#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${WORKSPACE_REPO_URL:-https://github.com/caotiensinh/3agent.git}"
REPO_REF="${WORKSPACE_REPO_REF:-main}"
INSTALL_DIR="${WORKSPACE_INSTALL_DIR:-/opt/workspace}"
MODEL="${WORKSPACE_LLM_MODEL:-qwen3:30b}"
FAST_MODEL="${WORKSPACE_FAST_MODEL:-qwen3:14b}"
MIN_DRIVER_MAJOR="${WORKSPACE_MIN_DRIVER_MAJOR:-590}"
REQUIRED_GPU_COUNT="${WORKSPACE_REQUIRED_RTX5090_COUNT:-2}"
LOG_FILE="/var/log/workspace/bootstrap.log"

log() { printf '[WorkSpace] %s\n' "$*"; }
die() { printf '[WorkSpace][ERROR] %s\n' "$*" >&2; exit 1; }
as_root() { if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

TARGET_USER="${SUDO_USER:-${USER:-}}"
[[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]] || die "Run as a normal sudo-capable operator user"

as_root install -d -m 0750 /var/log/workspace
exec > >(as_root tee -a "$LOG_FILE") 2>&1

log "Installing secure WorkSpace runtime prerequisites; NVIDIA driver/kernel are not modified."
as_root apt-get update -y
as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates git jq nftables python3 python3-pip python3-venv sudo

command -v nvidia-smi >/dev/null 2>&1 || die "nvidia-smi is required"
nvidia-smi >/dev/null 2>&1 || die "NVIDIA driver is unhealthy"
DRIVER="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1 | tr -d '[:space:]')"
DRIVER_MAJOR="${DRIVER%%.*}"
[[ "$DRIVER_MAJOR" =~ ^[0-9]+$ ]] || die "Cannot parse NVIDIA driver version"
(( DRIVER_MAJOR >= MIN_DRIVER_MAJOR )) || die "NVIDIA driver ${DRIVER} is below required ${MIN_DRIVER_MAJOR}+"
GPU_COUNT="$(nvidia-smi --query-gpu=name --format=csv,noheader | grep -c 'RTX 5090' || true)"
(( GPU_COUNT >= REQUIRED_GPU_COUNT )) || die "Expected ${REQUIRED_GPU_COUNT} RTX 5090 GPUs; found ${GPU_COUNT}"
log "GPU preflight PASS: driver=${DRIVER}, RTX5090=${GPU_COUNT}"

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
EXACT_HEAD="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
log "Source pinned for this installation: ${EXACT_HEAD}"

as_root python3 -m venv "${INSTALL_DIR}/.venv"
as_root "${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
as_root "${INSTALL_DIR}/.venv/bin/python" -m pip install -e "$INSTALL_DIR"

for local_model in "$FAST_MODEL" "$MODEL"; do
  if ! ollama list | awk 'NR>1 {print $1}' | grep -Fxq "$local_model"; then
    log "Pulling local model ${local_model}"
    ollama pull "$local_model"
  fi
done

as_root env WORKSPACE_INSTALL_DIR="$INSTALL_DIR" \
  WORKSPACE_VENV="${INSTALL_DIR}/.venv" \
  bash "${INSTALL_DIR}/scripts/install_workspace_secure_boundary.sh"

log "Running confidential-mode smoke test under the network-blocked Core identity."
workspace-secure smoke

log "FINAL PASS: WorkSpace secure-local runtime installed."
log "Use: workspace-secure <command>"
log "Public search remains disabled by default."
log "Source SHA: ${EXACT_HEAD}"
log "Bootstrap log: ${LOG_FILE}"
