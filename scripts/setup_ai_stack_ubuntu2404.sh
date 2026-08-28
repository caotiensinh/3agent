#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${THREE_AGENT_REPO_URL:-https://github.com/caotiensinh/3agent.git}"
REPO_REF="${THREE_AGENT_REPO_REF:-main}"
MODEL="${THREE_AGENT_MODEL:-qwen3:30b}"
FAST_MODEL="${THREE_AGENT_FAST_MODEL:-qwen3:14b}"
RESEARCH_MODEL="${THREE_AGENT_RESEARCH_MODEL:-$MODEL}"
PRESENTATION_MODEL="${THREE_AGENT_PRESENTATION_MODEL:-$FAST_MODEL}"
REPORT_MODEL="${THREE_AGENT_REPORT_MODEL:-$FAST_MODEL}"
DEEP_MODEL="${THREE_AGENT_DEEP_MODEL:-deepseek-r1:32b}"
INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-}"
REQUIRED_GPU_COUNT="${THREE_AGENT_REQUIRED_RTX5090_COUNT:-2}"
MIN_DRIVER_MAJOR="${THREE_AGENT_MIN_DRIVER_MAJOR:-590}"
OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-65536}"
OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-2m}"
OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"
OLLAMA_NUM_PARALLEL="${OLLAMA_NUM_PARALLEL:-1}"
LOG_DIR="${THREE_AGENT_LOG_DIR:-/var/log/3agent}"
LOG_FILE="${LOG_DIR}/ai-stack-setup.log"
SELF_TEST=0

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[3Agent][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[3Agent] %s\n' "$*"; }
warn() { printf '[3Agent][WARN] %s\n' "$*" >&2; }
die() { printf '[3Agent][ERROR] %s\n' "$*" >&2; exit 1; }

if [[ "$SELF_TEST" == "1" ]]; then
  [[ "$REPO_URL" == https://github.com/*/*.git ]] || die "Invalid repository URL"
  [[ "$REQUIRED_GPU_COUNT" =~ ^[0-9]+$ ]] || die "GPU count must be numeric"
  [[ "$MIN_DRIVER_MAJOR" =~ ^[0-9]+$ ]] || die "driver major must be numeric"
  [[ "$OLLAMA_CONTEXT_LENGTH" =~ ^[0-9]+$ ]] || die "context length must be numeric"
  [[ "$OLLAMA_MAX_LOADED_MODELS" =~ ^[0-9]+$ ]] || die "max loaded models must be numeric"
  [[ "$OLLAMA_NUM_PARALLEL" =~ ^[0-9]+$ ]] || die "parallel count must be numeric"
  [[ -n "$FAST_MODEL" && -n "$RESEARCH_MODEL" && -n "$PRESENTATION_MODEL" && -n "$REPORT_MODEL" ]] || die "model pool contains an empty required model"
  log "AI stack installer self-test PASS"
  exit 0
fi

if [[ "$EUID" -eq 0 ]]; then
  TARGET_USER="${TARGET_USER:-${SUDO_USER:-}}"
else
  TARGET_USER="${TARGET_USER:-${USER:-}}"
fi
[[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]] || die "Run as the normal sudo-capable desktop user."
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[[ -n "$TARGET_HOME" ]] || die "Unable to resolve home directory for $TARGET_USER"
INSTALL_DIR="${INSTALL_DIR:-${TARGET_HOME}/3agent}"

as_root() {
  if [[ "$EUID" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
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

setup_log() {
  as_root mkdir -p "$LOG_DIR"
  as_root touch "$LOG_FILE"
  as_root chmod 0644 "$LOG_FILE"
  exec > >(as_root tee -a "$LOG_FILE") 2>&1
}

check_os() {
  [[ -r /etc/os-release ]] || die "/etc/os-release is missing"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Ubuntu is required; detected ${ID:-unknown}"
  [[ "${VERSION_ID:-}" == 24.04* ]] || die "Ubuntu 24.04.x is required; detected ${VERSION_ID:-unknown}"
  [[ "$(uname -m)" == "x86_64" ]] || die "x86_64 is required"
  log "OS PASS: Ubuntu ${VERSION_ID}"
}

install_base_packages() {
  log "Installing application prerequisites only; NVIDIA driver and kernel are untouched."
  as_root apt-get update -y
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl git jq python3 python3-pip python3-venv sqlite3
}

GPU_UUID_CSV=""

check_existing_gpu_stack() {
  command -v nvidia-smi >/dev/null 2>&1 || die "nvidia-smi not found. This installer intentionally does not install NVIDIA drivers."
  nvidia-smi >/dev/null 2>&1 || die "NVIDIA driver is not healthy. Fix the driver first; this installer will not modify it."

  local driver_version driver_major
  driver_version="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1 | tr -d '[:space:]')"
  driver_major="${driver_version%%.*}"
  [[ "$driver_major" =~ ^[0-9]+$ ]] || die "Unable to parse NVIDIA driver version: $driver_version"
  (( driver_major >= MIN_DRIVER_MAJOR )) || die "NVIDIA driver ${driver_version} is below required branch ${MIN_DRIVER_MAJOR}. No driver changes were made."

  mapfile -t gpu_rows < <(nvidia-smi --query-gpu=name,uuid --format=csv,noheader)
  local -a selected_uuids=()
  local row name uuid
  for row in "${gpu_rows[@]}"; do
    name="${row%%,*}"
    uuid="${row#*,}"
    name="$(printf '%s' "$name" | xargs)"
    uuid="$(printf '%s' "$uuid" | xargs)"
    if [[ "$name" == *"RTX 5090"* ]]; then
      selected_uuids+=("$uuid")
    fi
  done

  (( ${#selected_uuids[@]} >= REQUIRED_GPU_COUNT )) || die "Need at least ${REQUIRED_GPU_COUNT} RTX 5090 GPUs; found ${#selected_uuids[@]}."
  local -a chosen=("${selected_uuids[@]:0:REQUIRED_GPU_COUNT}")
  GPU_UUID_CSV="$(IFS=,; printf '%s' "${chosen[*]}")"

  log "NVIDIA driver PASS: ${driver_version}"
  log "RTX 5090 count PASS: ${#selected_uuids[@]}"
  log "Ollama GPU allow-list: ${GPU_UUID_CSV}"
}

install_ollama() {
  log "Installing/updating Ollama application runtime."
  local tmp
  tmp="$(mktemp)"
  curl -fsSL https://ollama.com/install.sh -o "$tmp"
  sh "$tmp"
  rm -f "$tmp"
  command -v ollama >/dev/null 2>&1 || die "Ollama installation failed"
  log "Ollama binary: $(ollama --version 2>&1 | head -n1)"
}

configure_ollama() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
[Service]
Environment="CUDA_VISIBLE_DEVICES=${GPU_UUID_CSV}"
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_CONTEXT_LENGTH=${OLLAMA_CONTEXT_LENGTH}"
Environment="OLLAMA_KEEP_ALIVE=${OLLAMA_KEEP_ALIVE}"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_MAX_LOADED_MODELS=${OLLAMA_MAX_LOADED_MODELS}"
Environment="OLLAMA_NUM_PARALLEL=${OLLAMA_NUM_PARALLEL}"
EOF
  as_root mkdir -p /etc/systemd/system/ollama.service.d
  as_root install -m 0644 "$tmp" /etc/systemd/system/ollama.service.d/override.conf
  rm -f "$tmp"
  as_root systemctl daemon-reload
  as_root systemctl enable ollama
  as_root systemctl restart ollama

  for _ in {1..60}; do
    if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      log "Ollama service PASS"
      return 0
    fi
    sleep 2
  done
  as_root systemctl status ollama --no-pager || true
  die "Ollama API did not become ready"
}

deploy_repository() {
  log "Deploying 3Agent repository to ${INSTALL_DIR}"
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    if ! as_user git -C "$INSTALL_DIR" diff --quiet || ! as_user git -C "$INSTALL_DIR" diff --cached --quiet; then
      die "Existing checkout has uncommitted changes: ${INSTALL_DIR}. Commit or clean them first."
    fi
    as_user git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
    as_user git -C "$INSTALL_DIR" fetch origin "$REPO_REF"
    as_user git -C "$INSTALL_DIR" checkout "$REPO_REF"
    as_user git -C "$INSTALL_DIR" merge --ff-only "origin/${REPO_REF}"
  elif [[ -e "$INSTALL_DIR" ]]; then
    die "${INSTALL_DIR} exists but is not a Git checkout"
  else
    as_user git clone --branch "$REPO_REF" --single-branch "$REPO_URL" "$INSTALL_DIR"
  fi

  as_user python3 -m venv "${INSTALL_DIR}/.venv"
  as_user "${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
  as_user "${INSTALL_DIR}/.venv/bin/python" -m pip install -e "$INSTALL_DIR"

  local tmp_config
  tmp_config="$(mktemp)"
  jq \
    --arg model "$MODEL" \
    --arg fast "$FAST_MODEL" \
    --arg research "$RESEARCH_MODEL" \
    --arg presentation "$PRESENTATION_MODEL" \
    --arg report "$REPORT_MODEL" \
    --arg deep "$DEEP_MODEL" \
    --arg keep_alive "$OLLAMA_KEEP_ALIVE" \
    '.test_mode_full_access = true
     | .llm.provider = "ollama"
     | .llm.base_url = "http://127.0.0.1:11434"
     | .llm.model = $model
     | .llm.keep_alive = $keep_alive
     | .model_policy = {
         enabled: true,
         fast_model: $fast,
         research_model: $research,
         presentation_model: $presentation,
         report_model: $report,
         deep_model: $deep,
         deep_escalation: true,
         deep_prompt_chars: 14000
       }' \
    "${INSTALL_DIR}/config/test.example.json" >"$tmp_config"
  as_root install -o "$TARGET_USER" -g "$(id -gn "$TARGET_USER")" -m 0644 "$tmp_config" "${INSTALL_DIR}/config/local.json"
  rm -f "$tmp_config"
}

install_command() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd $(printf '%q' "$INSTALL_DIR")
export THREE_AGENT_CONFIG=$(printf '%q' "${INSTALL_DIR}/config/local.json")
exec $(printf '%q' "${INSTALL_DIR}/.venv/bin/three-agent") "\$@"
EOF
  as_root install -m 0755 "$tmp" /usr/local/bin/3agent
  rm -f "$tmp"
  log "Installed command: /usr/local/bin/3agent"
}

pull_models() {
  local -a requested=(
    "$FAST_MODEL"
    "$RESEARCH_MODEL"
    "$PRESENTATION_MODEL"
    "$REPORT_MODEL"
    "$DEEP_MODEL"
  )
  local -a unique=()
  local model seen existing
  for model in "${requested[@]}"; do
    [[ -n "$model" ]] || continue
    seen=0
    for existing in "${unique[@]}"; do
      if [[ "$existing" == "$model" ]]; then
        seen=1
        break
      fi
    done
    if [[ "$seen" == "0" ]]; then
      unique+=("$model")
    fi
  done

  log "Pulling on-demand model pool sequentially (${#unique[@]} unique models)."
  for model in "${unique[@]}"; do
    log "Pulling model: $model"
    as_user ollama pull "$model"
  done
}

verify_stack() {
  log "Running project regression checks."
  as_user env PYTHONPATH="${INSTALL_DIR}/src" bash "${INSTALL_DIR}/scripts/test.sh"

  log "Running 3Agent smoke test."
  local smoke
  smoke="$(as_user /usr/local/bin/3agent smoke)"
  printf '%s\n' "$smoke"
  grep -q 'model_policy_enabled' <<<"$smoke" || die "Smoke output does not expose model policy"

  log "Running live local-model inference with research model."
  local payload response
  payload="$(jq -nc --arg model "$RESEARCH_MODEL" \
    '{model:$model,prompt:"Reply with only the word READY.",stream:false,think:false,keep_alive:"2m",options:{num_predict:64}}')"
  response="$(curl -fsS --max-time 300 \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    http://127.0.0.1:11434/api/generate)"
  if ! jq -e '(.response // "") | strings | length > 0' <<<"$response" >/dev/null; then
    warn "Ollama validation payload: $(jq -c '{response,thinking,done,done_reason}' <<<"$response" 2>/dev/null || printf '%s' "$response")"
    die "Ollama live generation failed"
  fi

  local ps_json
  ps_json="$(curl -fsS http://127.0.0.1:11434/api/ps)"
  jq -e '.models | length > 0' <<<"$ps_json" >/dev/null || die "No model is loaded after live inference"
  jq -e '[.models[].size_vram] | add > 0' <<<"$ps_json" >/dev/null || die "Model did not report GPU VRAM usage"

  log "Loaded model state:"
  as_user ollama ps || true
  log "GPU state:"
  nvidia-smi --query-gpu=index,name,driver_version,memory.total,memory.used,utilization.gpu \
    --format=csv,noheader

  log "FINAL PASS: 3Agent AI stack is ready with model-on-demand routing."
  log "Project: ${INSTALL_DIR}"
  log "Fast model: ${FAST_MODEL}"
  log "Research model: ${RESEARCH_MODEL}"
  log "Presentation model: ${PRESENTATION_MODEL}"
  log "Report model: ${REPORT_MODEL}"
  log "Deep escalation model: ${DEEP_MODEL}"
  log "Ollama max loaded models: ${OLLAMA_MAX_LOADED_MODELS}"
  log "Command: 3agent"
  log "Log: ${LOG_FILE}"
}

main() {
  setup_log
  check_os
  install_base_packages
  check_existing_gpu_stack
  install_ollama
  configure_ollama
  deploy_repository
  install_command
  pull_models
  verify_stack
}

main "$@"
