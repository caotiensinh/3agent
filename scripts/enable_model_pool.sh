#!/usr/bin/env bash
set -Eeuo pipefail

FAST_MODEL_OVERRIDE="${THREE_AGENT_FAST_MODEL:-}"
RESEARCH_MODEL_OVERRIDE="${THREE_AGENT_RESEARCH_MODEL:-}"
PRESENTATION_MODEL_OVERRIDE="${THREE_AGENT_PRESENTATION_MODEL:-}"
REPORT_MODEL_OVERRIDE="${THREE_AGENT_REPORT_MODEL:-}"
DEEP_MODEL_OVERRIDE="${THREE_AGENT_DEEP_MODEL:-}"
HARDWARE_PROFILE="${THREE_AGENT_HARDWARE_PROFILE:-auto}"
MIN_DRIVER_MAJOR="${THREE_AGENT_MIN_DRIVER_MAJOR:-}"
REQUIRED_RTX5090_COUNT="${THREE_AGENT_REQUIRED_RTX5090_COUNT:-}"
KEEP_ALIVE="${THREE_AGENT_MODEL_KEEP_ALIVE:-2m}"
DEEP_PROMPT_CHARS="${THREE_AGENT_DEEP_PROMPT_CHARS:-14000}"
MAX_VRAM_PERCENT="${THREE_AGENT_MAX_VRAM_PERCENT:-88}"
MAX_RAM_PERCENT="${THREE_AGENT_MAX_RAM_PERCENT:-82}"
MAX_GPU_UTIL_PERCENT="${THREE_AGENT_MAX_GPU_UTIL_PERCENT:-95}"
MAX_GPU_POWER_PERCENT="${THREE_AGENT_MAX_GPU_POWER_PERCENT:-95}"
MAX_GPU_TEMP_C="${THREE_AGENT_MAX_GPU_TEMP_C:-85}"
MODEL_SIZE_SAFETY_FACTOR="${THREE_AGENT_MODEL_SIZE_SAFETY_FACTOR:-1.15}"
MODEL_RAM_OVERHEAD_FACTOR="${THREE_AGENT_MODEL_RAM_OVERHEAD_FACTOR:-0.15}"
INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-$HOME/3agent}"
CONFIG_FILE="${THREE_AGENT_CONFIG:-$INSTALL_DIR/config/local.json}"
OLLAMA_DROPIN="/etc/systemd/system/ollama.service.d/zz-3agent-model-pool.conf"
SELF_TEST=0
CONFIG_BACKUP=""
DROPIN_BACKUP=""
CONFIG_CHANGED=0
DROPIN_CHANGED=0
UPGRADE_COMPLETE=0

FAST_MODEL=""
RESEARCH_MODEL=""
PRESENTATION_MODEL=""
REPORT_MODEL=""
DEEP_MODEL=""
SYSTEM_RAM_MIB=0
TOTAL_VRAM_MIB=0
GPU_COUNT=0
RTX5090_COUNT=0
NVIDIA_AVAILABLE=0
DRIVER="none"
GPU_NAMES=""
RESOURCE_CONTROL_ENABLED=false

declare -a MODELS=()

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[3Agent-ModelPool][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[3Agent-ModelPool] %s\n' "$*"; }
warn() { printf '[3Agent-ModelPool][WARN] %s\n' "$*" >&2; }
die() { printf '[3Agent-ModelPool][ERROR] %s\n' "$*" >&2; exit 1; }

is_percent() {
  awk -v value="$1" 'BEGIN { exit !(value+0 >= 1 && value+0 <= 100) }'
}

is_ratio() {
  awk -v value="$1" 'BEGIN { exit !(value+0 >= 0 && value+0 <= 1) }'
}

is_safety_factor() {
  awk -v value="$1" 'BEGIN { exit !(value+0 >= 1 && value+0 <= 4) }'
}

select_models_for_capacity() {
  local vram_mib="$1"
  local ram_mib="$2"
  local selected_research selected_fast selected_deep

  [[ "$vram_mib" =~ ^[0-9]+$ ]] || die "VRAM capacity must be an integer MiB value"
  [[ "$ram_mib" =~ ^[0-9]+$ ]] || die "RAM capacity must be an integer MiB value"

  # Keep the bootstrap tiers aligned with setup_workspace_secure.sh. 30B needs
  # >=28 GiB aggregate NVIDIA VRAM so the 88% budget and safety factor retain headroom.
  if (( vram_mib >= 28672 )); then
    selected_research="qwen3:30b"
    selected_fast="qwen3:14b"
  elif (( vram_mib >= 16384 )); then
    selected_research="qwen3:14b"
    selected_fast="qwen3:8b"
  elif (( vram_mib >= 8192 )); then
    selected_research="qwen3:8b"
    selected_fast="qwen3:4b"
  elif (( vram_mib >= 4096 )); then
    selected_research="qwen3:4b"
    selected_fast="qwen3:1.7b"
  elif (( ram_mib >= 32768 )); then
    selected_research="qwen3:8b"
    selected_fast="qwen3:4b"
  elif (( ram_mib >= 16384 )); then
    selected_research="qwen3:4b"
    selected_fast="qwen3:1.7b"
  else
    selected_research="qwen3:1.7b"
    selected_fast="qwen3:0.6b"
  fi
  selected_deep="$selected_research"

  FAST_MODEL="${FAST_MODEL_OVERRIDE:-$selected_fast}"
  RESEARCH_MODEL="${RESEARCH_MODEL_OVERRIDE:-$selected_research}"
  PRESENTATION_MODEL="${PRESENTATION_MODEL_OVERRIDE:-$FAST_MODEL}"
  REPORT_MODEL="${REPORT_MODEL_OVERRIDE:-$FAST_MODEL}"
  DEEP_MODEL="${DEEP_MODEL_OVERRIDE:-$selected_deep}"
}

validate_settings() {
  [[ -n "$FAST_MODEL" ]] || die "FAST_MODEL is empty"
  [[ -n "$RESEARCH_MODEL" ]] || die "RESEARCH_MODEL is empty"
  [[ -n "$PRESENTATION_MODEL" ]] || die "PRESENTATION_MODEL is empty"
  [[ -n "$REPORT_MODEL" ]] || die "REPORT_MODEL is empty"
  [[ -n "$DEEP_MODEL" ]] || die "DEEP_MODEL is empty"
  [[ "$DEEP_PROMPT_CHARS" =~ ^[0-9]+$ ]] || die "DEEP_PROMPT_CHARS must be numeric"
  (( DEEP_PROMPT_CHARS >= 2000 )) || die "DEEP_PROMPT_CHARS must be >= 2000"
  is_percent "$MAX_VRAM_PERCENT" || die "MAX_VRAM_PERCENT must be 1..100"
  is_percent "$MAX_RAM_PERCENT" || die "MAX_RAM_PERCENT must be 1..100"
  is_percent "$MAX_GPU_UTIL_PERCENT" || die "MAX_GPU_UTIL_PERCENT must be 1..100"
  is_percent "$MAX_GPU_POWER_PERCENT" || die "MAX_GPU_POWER_PERCENT must be 1..100"
  is_safety_factor "$MODEL_SIZE_SAFETY_FACTOR" || die "MODEL_SIZE_SAFETY_FACTOR must be 1..4"
  is_ratio "$MODEL_RAM_OVERHEAD_FACTOR" || die "MODEL_RAM_OVERHEAD_FACTOR must be 0..1"
}

if [[ "$SELF_TEST" == "1" ]]; then
  test_vram="${THREE_AGENT_TEST_VRAM_MIB:-0}"
  test_ram="${THREE_AGENT_TEST_RAM_MIB:-16384}"
  select_models_for_capacity "$test_vram" "$test_ram"
  validate_settings
  printf 'profile=%s vram_mib=%s ram_mib=%s fast=%s research=%s presentation=%s report=%s deep=%s\n' \
    "$HARDWARE_PROFILE" "$test_vram" "$test_ram" "$FAST_MODEL" "$RESEARCH_MODEL" \
    "$PRESENTATION_MODEL" "$REPORT_MODEL" "$DEEP_MODEL"
  exit 0
fi

rollback() {
  local original_rc="$?"
  if [[ "$UPGRADE_COMPLETE" == "1" ]]; then
    return 0
  fi
  set +e
  warn "Upgrade failed; restoring pre-upgrade runtime configuration."
  if [[ "$CONFIG_CHANGED" == "1" && -n "$CONFIG_BACKUP" && -f "$CONFIG_BACKUP" ]]; then
    cp -a "$CONFIG_BACKUP" "$CONFIG_FILE"
    warn "Restored config: $CONFIG_FILE"
  fi
  if [[ "$DROPIN_CHANGED" == "1" ]]; then
    if [[ -n "$DROPIN_BACKUP" && -f "$DROPIN_BACKUP" ]]; then
      sudo cp -a "$DROPIN_BACKUP" "$OLLAMA_DROPIN"
      warn "Restored previous Ollama lifecycle drop-in."
    else
      sudo rm -f "$OLLAMA_DROPIN"
      warn "Removed newly-created Ollama lifecycle drop-in."
    fi
    sudo systemctl daemon-reload
    sudo systemctl restart ollama
  fi
  if systemctl --user list-unit-files 3agent-chat.service --no-legend 2>/dev/null | grep -q '^3agent-chat.service'; then
    systemctl --user restart 3agent-chat.service >/dev/null 2>&1 || true
  fi
  warn "Rollback finished. Downloaded Ollama model files are intentionally retained because they are inert disk data."
  exit "$original_rc"
}
trap rollback ERR

detect_hardware() {
  SYSTEM_RAM_MIB="$(awk '/MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || true)"
  [[ "$SYSTEM_RAM_MIB" =~ ^[0-9]+$ ]] || SYSTEM_RAM_MIB=0

  if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi >/dev/null 2>&1; then
    NVIDIA_AVAILABLE=1
    RESOURCE_CONTROL_ENABLED=true
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
      (( NVIDIA_AVAILABLE == 1 )) || die "THREE_AGENT_HARDWARE_PROFILE=nvidia requires a healthy NVIDIA runtime"
      ;;
    dual-rtx5090)
      (( NVIDIA_AVAILABLE == 1 )) || die "dual-rtx5090 profile requires a healthy NVIDIA runtime"
      (( RTX5090_COUNT >= 2 )) || die "dual-rtx5090 profile requires at least 2 RTX 5090 GPUs; found ${RTX5090_COUNT}"
      ;;
    *)
      die "Unsupported THREE_AGENT_HARDWARE_PROFILE=${HARDWARE_PROFILE}; use auto, nvidia, or dual-rtx5090"
      ;;
  esac

  if [[ -n "$MIN_DRIVER_MAJOR" ]]; then
    [[ "$MIN_DRIVER_MAJOR" =~ ^[0-9]+$ ]] || die "THREE_AGENT_MIN_DRIVER_MAJOR must be an integer when set"
    (( NVIDIA_AVAILABLE == 1 )) || die "THREE_AGENT_MIN_DRIVER_MAJOR requires a healthy NVIDIA runtime"
    local driver_major="${DRIVER%%.*}"
    [[ "$driver_major" =~ ^[0-9]+$ ]] || die "Cannot parse NVIDIA driver version: ${DRIVER}"
    (( driver_major >= MIN_DRIVER_MAJOR )) || die "NVIDIA driver ${DRIVER} is below operator-required ${MIN_DRIVER_MAJOR}+"
  fi

  if [[ -n "$REQUIRED_RTX5090_COUNT" ]]; then
    [[ "$REQUIRED_RTX5090_COUNT" =~ ^[0-9]+$ ]] || die "THREE_AGENT_REQUIRED_RTX5090_COUNT must be an integer when set"
    (( RTX5090_COUNT >= REQUIRED_RTX5090_COUNT )) \
      || die "Operator requires ${REQUIRED_RTX5090_COUNT} RTX 5090 GPUs; found ${RTX5090_COUNT}"
  fi
}

check_ollama() {
  systemctl is-active --quiet ollama || die "ollama.service is not active"
  curl -fsS http://127.0.0.1:11434/api/tags >/dev/null || die "Ollama API is unavailable"
  log "Ollama preflight PASS"
}

unique_models() {
  local -a requested=(
    "$FAST_MODEL"
    "$RESEARCH_MODEL"
    "$PRESENTATION_MODEL"
    "$REPORT_MODEL"
    "$DEEP_MODEL"
  )
  local -a unique=()
  local model existing found
  for model in "${requested[@]}"; do
    [[ -n "$model" ]] || continue
    found=0
    for existing in "${unique[@]}"; do
      if [[ "$existing" == "$model" ]]; then
        found=1
        break
      fi
    done
    if [[ "$found" == "0" ]]; then
      unique+=("$model")
    fi
  done
  printf '%s\n' "${unique[@]}"
}

pull_models_sequentially() {
  local model
  mapfile -t MODELS < <(unique_models)
  (( ${#MODELS[@]} > 0 )) || die "No models selected"
  log "Model pool contains ${#MODELS[@]} unique models; pulls are sequential."
  for model in "${MODELS[@]}"; do
    if ollama list | awk 'NR>1 {print $1}' | grep -Fxq "$model"; then
      log "Model already present: $model"
    else
      log "Pulling model: $model"
      ollama pull "$model"
    fi
  done
}

update_local_config() {
  local tmp
  CONFIG_BACKUP="${CONFIG_FILE}.before-model-pool.$(date +%Y%m%d-%H%M%S)"
  cp -a "$CONFIG_FILE" "$CONFIG_BACKUP"
  tmp="$(mktemp)"
  jq \
    --arg fast "$FAST_MODEL" \
    --arg research "$RESEARCH_MODEL" \
    --arg presentation "$PRESENTATION_MODEL" \
    --arg report "$REPORT_MODEL" \
    --arg deep "$DEEP_MODEL" \
    --arg keep_alive "$KEEP_ALIVE" \
    --argjson threshold "$DEEP_PROMPT_CHARS" \
    --argjson max_vram "$MAX_VRAM_PERCENT" \
    --argjson max_ram "$MAX_RAM_PERCENT" \
    --argjson max_util "$MAX_GPU_UTIL_PERCENT" \
    --argjson max_power "$MAX_GPU_POWER_PERCENT" \
    --argjson max_temp "$MAX_GPU_TEMP_C" \
    --argjson size_factor "$MODEL_SIZE_SAFETY_FACTOR" \
    --argjson ram_factor "$MODEL_RAM_OVERHEAD_FACTOR" \
    --argjson resource_enabled "$RESOURCE_CONTROL_ENABLED" \
    '.llm.model = $research
     | .llm.keep_alive = $keep_alive
     | .model_policy = {
         enabled: true,
         fast_model: $fast,
         research_model: $research,
         presentation_model: $presentation,
         report_model: $report,
         deep_model: $deep,
         deep_escalation: true,
         deep_prompt_chars: $threshold,
         resource_control: {
           enabled: $resource_enabled,
           max_vram_percent: $max_vram,
           max_ram_percent: $max_ram,
           max_gpu_util_percent: $max_util,
           max_gpu_power_percent: $max_power,
           max_gpu_temp_c: $max_temp,
           model_size_safety_factor: $size_factor,
           model_ram_overhead_factor: $ram_factor,
           serialize_generation: true,
           reservation_ttl_seconds: 900
         }
       }' \
    "$CONFIG_FILE" >"$tmp"
  jq -e '.model_policy.enabled == true and (.model_policy.resource_control.enabled | type == "boolean")' "$tmp" >/dev/null \
    || die "Generated model policy failed validation"
  install -m 0644 "$tmp" "$CONFIG_FILE"
  rm -f "$tmp"
  CONFIG_CHANGED=1
  log "Config updated; backup: $CONFIG_BACKUP"
}

configure_ollama_lifecycle() {
  local tmp timestamp environment
  timestamp="$(date +%Y%m%d-%H%M%S)"
  if sudo test -f "$OLLAMA_DROPIN"; then
    DROPIN_BACKUP="${TMPDIR:-/tmp}/3agent-ollama-model-pool.${timestamp}.conf"
    sudo cp -a "$OLLAMA_DROPIN" "$DROPIN_BACKUP"
  fi
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
[Service]
Environment="OLLAMA_KEEP_ALIVE=${KEEP_ALIVE}"
Environment="OLLAMA_NUM_PARALLEL=1"
UnsetEnvironment=OLLAMA_MAX_LOADED_MODELS
EOF
  sudo mkdir -p /etc/systemd/system/ollama.service.d
  sudo install -m 0644 "$tmp" "$OLLAMA_DROPIN"
  rm -f "$tmp"
  DROPIN_CHANGED=1
  sudo systemctl daemon-reload
  sudo systemctl restart ollama
  for _ in {1..60}; do
    if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      environment="$(systemctl show ollama --property=Environment --value)"
      if grep -q 'OLLAMA_MAX_LOADED_MODELS=' <<<"$environment"; then
        die "Legacy OLLAMA_MAX_LOADED_MODELS is still active after restart"
      fi
      log "Ollama lifecycle PASS: legacy fixed model cap cleared; KEEP_ALIVE=$KEEP_ALIVE"
      return 0
    fi
    sleep 1
  done
  sudo systemctl status ollama --no-pager || true
  die "Ollama did not recover after lifecycle-policy restart"
}

update_package() {
  "$INSTALL_DIR/.venv/bin/python" -m pip install -e "$INSTALL_DIR"
}

verify_application() {
  log "Running full project regression tests."
  PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/.venv/bin/python" -m unittest discover -s "$INSTALL_DIR/tests" -v

  log "Checking model policy."
  local smoke
  smoke="$(THREE_AGENT_CONFIG="$CONFIG_FILE" "$INSTALL_DIR/.venv/bin/three-agent" smoke)"
  printf '%s\n' "$smoke"
  grep -q '"model_policy_enabled": true' <<<"$smoke" || die "3Agent model policy is not enabled"
  if [[ "$RESOURCE_CONTROL_ENABLED" == "true" ]]; then
    grep -q '"resource_control_enabled": true' <<<"$smoke" || die "GPU resource control is not enabled"
  else
    grep -q '"resource_control_enabled": false' <<<"$smoke" || die "CPU/RAM profile must not instantiate NVIDIA resource control"
  fi
  grep -q '"fixed_model_count_limit": false' <<<"$smoke" || die "Fixed model-count limit is still active"
  grep -Fq "$RESEARCH_MODEL" <<<"$smoke" || die "Research model is not active in config"
  grep -Fq "$PRESENTATION_MODEL" <<<"$smoke" || die "Presentation model is not active in config"
  grep -Fq "$REPORT_MODEL" <<<"$smoke" || die "Report model is not active in config"
  grep -Fq "$DEEP_MODEL" <<<"$smoke" || die "Deep model is not active in config"
}

admission_check() {
  local model="$1"
  THREE_AGENT_CONFIG="$CONFIG_FILE" MODEL_TO_CHECK="$model" PYTHONPATH="$INSTALL_DIR/src" \
    "$INSTALL_DIR/.venv/bin/python" - <<'PY'
import os
from three_agent.config import load_config
from three_agent.orchestrator import Orchestrator
from three_agent.resource_budget import ResourceAdmissionError

config = load_config(os.environ["THREE_AGENT_CONFIG"])
manager = Orchestrator(config).resource_manager
if manager is None:
    raise SystemExit("resource manager is not enabled")
model = os.environ["MODEL_TO_CHECK"]
try:
    with manager.admit(model) as decision:
        print(
            f"ADMIT model={model} projected_vram={decision.projected_vram_percent:.1f}% "
            f"projected_ram={decision.projected_ram_percent:.1f}%"
        )
except ResourceAdmissionError as exc:
    print(f"DENY model={model} reason={exc}")
    raise SystemExit(42)
PY
}

read_ram_percent() {
  awk '/MemTotal:/ {total=$2} /MemAvailable:/ {available=$2} END {if (total > 0) printf "%.2f", ((total-available)/total)*100; else print "100.00"}' /proc/meminfo
}

cpu_ram_preflight() {
  local model="$1"
  local tags size_bytes total_kib available_kib projected_percent
  tags="$(curl -fsS http://127.0.0.1:11434/api/tags)"
  size_bytes="$(jq -r --arg model "$model" '.models[] | select(.name == $model) | .size' <<<"$tags" | head -n1)"
  [[ "$size_bytes" =~ ^[0-9]+$ ]] || die "Cannot determine Ollama model size for CPU/RAM admission: $model"
  read -r total_kib available_kib < <(awk '/MemTotal:/ {total=$2} /MemAvailable:/ {available=$2} END {print int(total), int(available)}' /proc/meminfo)
  (( total_kib > 0 )) || die "Unable to determine system RAM"
  projected_percent="$(awk \
    -v total_kib="$total_kib" \
    -v available_kib="$available_kib" \
    -v bytes="$size_bytes" \
    -v safety="$MODEL_SIZE_SAFETY_FACTOR" \
    -v overhead="$MODEL_RAM_OVERHEAD_FACTOR" \
    'BEGIN {
      total=total_kib*1024;
      used=(total_kib-available_kib)*1024;
      projected=used + (bytes*safety*(1+overhead));
      printf "%.2f", (projected/total)*100;
    }')"
  awk -v used="$projected_percent" -v limit="$MAX_RAM_PERCENT" 'BEGIN { exit !(used <= limit) }' \
    || die "CPU/RAM projected usage ${projected_percent}% would exceed configured ${MAX_RAM_PERCENT}% for ${model}"
  log "CPU/RAM admission PASS for $model: projected_ram=${projected_percent}%"
}

verify_models_under_budget() {
  local model payload response ps_json total_vram used_vram projected_percent actual_ram admitted=0 denied=0

  if (( NVIDIA_AVAILABLE == 1 )); then
    total_vram="$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | awk '{sum += $1} END {print int(sum)}')"
    (( total_vram > 0 )) || die "Unable to determine total GPU VRAM"
  else
    total_vram=0
  fi

  for model in "${MODELS[@]}"; do
    if (( NVIDIA_AVAILABLE == 1 )); then
      log "Pre-calculating GPU resource admission for: $model"
      if ! admission_check "$model"; then
        warn "Model safely denied by current GPU resource budget: $model"
        denied=$((denied + 1))
        continue
      fi
    else
      cpu_ram_preflight "$model"
    fi

    payload="$(jq -nc --arg model "$model" --arg keep "$KEEP_ALIVE" '{model:$model,prompt:"Reply with only READY.",stream:false,think:false,keep_alive:$keep,options:{num_predict:32}}')"
    response="$(curl -fsS --max-time 600 -H 'Content-Type: application/json' -d "$payload" http://127.0.0.1:11434/api/generate)"
    jq -e '(.response // "") | strings | length > 0' <<<"$response" >/dev/null || die "Model inference failed: $model"
    admitted=$((admitted + 1))

    actual_ram="$(read_ram_percent)"
    awk -v used="$actual_ram" -v limit="$MAX_RAM_PERCENT" 'BEGIN { exit !(used <= limit) }' \
      || die "Actual RAM ${actual_ram}% exceeded configured ${MAX_RAM_PERCENT}% after ${model}"

    if (( NVIDIA_AVAILABLE == 1 )); then
      ps_json="$(curl -fsS http://127.0.0.1:11434/api/ps)"
      used_vram="$(jq '[.models[].size_vram] | add // 0' <<<"$ps_json")"
      projected_percent="$(awk -v bytes="$used_vram" -v mib="$total_vram" 'BEGIN { printf "%.2f", (bytes / (mib * 1024 * 1024)) * 100 }')"
      awk -v used="$projected_percent" -v limit="$MAX_VRAM_PERCENT" 'BEGIN { exit !(used <= limit) }' \
        || die "Actual resident model VRAM ${projected_percent}% exceeded configured ${MAX_VRAM_PERCENT}%"
      log "Resident set PASS after $model: $(jq '.models | length' <<<"$ps_json") model(s), VRAM=${projected_percent}%, RAM=${actual_ram}%"
    else
      log "CPU/RAM resident check PASS after $model: RAM=${actual_ram}%"
    fi
  done

  (( admitted > 0 )) || die "No model could be admitted under the configured resource budget"
  log "Dynamic admission verification PASS: admitted=$admitted safely_denied=$denied"
}

restart_chat() {
  if systemctl --user list-unit-files 3agent-chat.service --no-legend 2>/dev/null | grep -q '^3agent-chat.service'; then
    systemctl --user restart 3agent-chat.service
    sleep 2
    systemctl --user is-active --quiet 3agent-chat.service || die "3agent-chat.service failed after upgrade"
    log "LAN Chat restart PASS"
  else
    warn "3agent-chat.service is not installed; skipped chat restart"
  fi
}

main() {
  log "Starting safe dynamic model-pool upgrade. NVIDIA driver/kernel will not be modified."
  [[ -d "$INSTALL_DIR/.git" ]] || die "3Agent checkout not found: $INSTALL_DIR"
  [[ -x "$INSTALL_DIR/.venv/bin/python" ]] || die "3Agent virtualenv is missing: $INSTALL_DIR/.venv"
  [[ -f "$CONFIG_FILE" ]] || die "Local config is missing: $CONFIG_FILE"
  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v ollama >/dev/null 2>&1 || die "ollama is required"

  detect_hardware
  validate_hardware_policy
  select_models_for_capacity "$TOTAL_VRAM_MIB" "$SYSTEM_RAM_MIB"
  validate_settings

  if (( NVIDIA_AVAILABLE == 1 )); then
    log "Hardware detected: NVIDIA driver=${DRIVER}, gpu_count=${GPU_COUNT}, total_vram=${TOTAL_VRAM_MIB}MiB"
    log "GPU(s): ${GPU_NAMES}"
  else
    warn "No healthy NVIDIA runtime detected; using CPU/system-RAM model profile with GPU resource control disabled"
  fi
  log "System RAM: ${SYSTEM_RAM_MIB}MiB"
  log "Hardware profile: ${HARDWARE_PROFILE}; research=${RESEARCH_MODEL}; fast=${FAST_MODEL}; deep=${DEEP_MODEL}"

  check_ollama
  pull_models_sequentially
  update_local_config
  configure_ollama_lifecycle
  update_package
  verify_application
  verify_models_under_budget
  restart_chat

  UPGRADE_COMPLETE=1
  trap - ERR
  log "FINAL PASS: dynamic resource-aware model pool completed."
  log "Fast/Presentation/Report: $FAST_MODEL / $PRESENTATION_MODEL / $REPORT_MODEL"
  log "Research: $RESEARCH_MODEL"
  log "Deep escalation: $DEEP_MODEL"
  log "VRAM/RAM budget: ${MAX_VRAM_PERCENT}% / ${MAX_RAM_PERCENT}%"
  log "GPU resource control enabled: ${RESOURCE_CONTROL_ENABLED}"
  log "GPU util/power/temp guards: ${MAX_GPU_UTIL_PERCENT}% / ${MAX_GPU_POWER_PERCENT}% / ${MAX_GPU_TEMP_C}C"
  log "Resident model count: dynamic; no fixed one-model cap"
}

main "$@"
