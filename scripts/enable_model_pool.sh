#!/usr/bin/env bash
set -Eeuo pipefail

FAST_MODEL="${THREE_AGENT_FAST_MODEL:-qwen3:14b}"
RESEARCH_MODEL="${THREE_AGENT_RESEARCH_MODEL:-qwen3:30b}"
PRESENTATION_MODEL="${THREE_AGENT_PRESENTATION_MODEL:-$FAST_MODEL}"
REPORT_MODEL="${THREE_AGENT_REPORT_MODEL:-$FAST_MODEL}"
DEEP_MODEL="${THREE_AGENT_DEEP_MODEL:-deepseek-r1:32b}"
KEEP_ALIVE="${THREE_AGENT_MODEL_KEEP_ALIVE:-2m}"
DEEP_PROMPT_CHARS="${THREE_AGENT_DEEP_PROMPT_CHARS:-14000}"
INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-$HOME/3agent}"
CONFIG_FILE="${THREE_AGENT_CONFIG:-$INSTALL_DIR/config/local.json}"
OLLAMA_DROPIN="/etc/systemd/system/ollama.service.d/zz-3agent-model-pool.conf"
SELF_TEST=0
CONFIG_BACKUP=""
DROPIN_BACKUP=""
CONFIG_CHANGED=0
DROPIN_CHANGED=0
UPGRADE_COMPLETE=0

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

validate_settings() {
  [[ -n "$FAST_MODEL" ]] || die "FAST_MODEL is empty"
  [[ -n "$RESEARCH_MODEL" ]] || die "RESEARCH_MODEL is empty"
  [[ -n "$PRESENTATION_MODEL" ]] || die "PRESENTATION_MODEL is empty"
  [[ -n "$REPORT_MODEL" ]] || die "REPORT_MODEL is empty"
  [[ "$DEEP_PROMPT_CHARS" =~ ^[0-9]+$ ]] || die "DEEP_PROMPT_CHARS must be numeric"
  (( DEEP_PROMPT_CHARS >= 2000 )) || die "DEEP_PROMPT_CHARS must be >= 2000"
}

if [[ "$SELF_TEST" == "1" ]]; then
  validate_settings
  log "Model-pool upgrader self-test PASS"
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

validate_settings
[[ -d "$INSTALL_DIR/.git" ]] || die "3Agent checkout not found: $INSTALL_DIR"
[[ -x "$INSTALL_DIR/.venv/bin/python" ]] || die "3Agent virtualenv is missing: $INSTALL_DIR/.venv"
[[ -f "$CONFIG_FILE" ]] || die "Local config is missing: $CONFIG_FILE"
command -v jq >/dev/null 2>&1 || die "jq is required"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v ollama >/dev/null 2>&1 || die "ollama is required"
command -v nvidia-smi >/dev/null 2>&1 || die "nvidia-smi is required"

check_gpu() {
  nvidia-smi >/dev/null 2>&1 || die "NVIDIA driver is not healthy; no changes were made"
  local count
  count="$(nvidia-smi --query-gpu=name --format=csv,noheader | grep -c 'RTX 5090' || true)"
  (( count >= 2 )) || die "Need at least 2 RTX 5090 GPUs; found $count. No GPU settings were changed."
  log "GPU preflight PASS: $count RTX 5090 GPUs"
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
    '.llm.keep_alive = $keep_alive
     | .model_policy = {
         enabled: true,
         fast_model: $fast,
         research_model: $research,
         presentation_model: $presentation,
         report_model: $report,
         deep_model: $deep,
         deep_escalation: true,
         deep_prompt_chars: $threshold
       }' \
    "$CONFIG_FILE" >"$tmp"
  jq -e '.model_policy.enabled == true' "$tmp" >/dev/null || die "Generated config failed validation"
  install -m 0644 "$tmp" "$CONFIG_FILE"
  rm -f "$tmp"
  CONFIG_CHANGED=1
  log "Config updated; backup: $CONFIG_BACKUP"
}

configure_ollama_lifecycle() {
  local tmp timestamp
  timestamp="$(date +%Y%m%d-%H%M%S)"
  if sudo test -f "$OLLAMA_DROPIN"; then
    DROPIN_BACKUP="${TMPDIR:-/tmp}/3agent-ollama-model-pool.${timestamp}.conf"
    sudo cat "$OLLAMA_DROPIN" >"$DROPIN_BACKUP"
  fi
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
[Service]
Environment="OLLAMA_KEEP_ALIVE=${KEEP_ALIVE}"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
EOF
  sudo mkdir -p /etc/systemd/system/ollama.service.d
  sudo install -m 0644 "$tmp" "$OLLAMA_DROPIN"
  rm -f "$tmp"
  DROPIN_CHANGED=1
  sudo systemctl daemon-reload
  sudo systemctl restart ollama
  for _ in {1..60}; do
    if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      log "Ollama lifecycle policy PASS: MAX_LOADED_MODELS=1, KEEP_ALIVE=$KEEP_ALIVE"
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

verify_model_sequentially() {
  local model payload response ps_json loaded_count unload_payload
  for model in "${MODELS[@]}"; do
    log "Live-check model: $model"
    payload="$(jq -nc --arg model "$model" '{model:$model,prompt:"Reply with only READY.",stream:false,think:false,keep_alive:"2m",options:{num_predict:32}}')"
    response="$(curl -fsS --max-time 600 -H 'Content-Type: application/json' -d "$payload" http://127.0.0.1:11434/api/generate)"
    jq -e '(.response // "") | strings | length > 0' <<<"$response" >/dev/null || die "Model inference failed: $model"

    ps_json="$(curl -fsS http://127.0.0.1:11434/api/ps)"
    loaded_count="$(jq '.models | length' <<<"$ps_json")"
    (( loaded_count <= 1 )) || die "Resource policy violated: $loaded_count models are loaded simultaneously"
    jq -e --arg model "$model" '.models | length == 1 and .[0].name == $model' <<<"$ps_json" >/dev/null \
      || warn "Ollama model name differs from requested tag; continuing because only one model is resident"

    unload_payload="$(jq -nc --arg model "$model" '{model:$model,prompt:"",stream:false,keep_alive:0}')"
    curl -fsS --max-time 120 -H 'Content-Type: application/json' -d "$unload_payload" http://127.0.0.1:11434/api/generate >/dev/null
    sleep 1
    ps_json="$(curl -fsS http://127.0.0.1:11434/api/ps)"
    jq -e '.models | length == 0' <<<"$ps_json" >/dev/null || die "Model did not unload cleanly after test: $model"
    log "Model PASS + unload PASS: $model"
  done
}

verify_application() {
  log "Running full project regression tests."
  PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/.venv/bin/python" -m unittest discover -s "$INSTALL_DIR/tests" -v

  log "Checking role model policy."
  local smoke
  smoke="$(THREE_AGENT_CONFIG="$CONFIG_FILE" "$INSTALL_DIR/.venv/bin/three-agent" smoke)"
  printf '%s\n' "$smoke"
  grep -q '"model_policy_enabled": true' <<<"$smoke" || die "3Agent model policy is not enabled"
  grep -Fq "$RESEARCH_MODEL" <<<"$smoke" || die "Research model is not active in config"
  grep -Fq "$PRESENTATION_MODEL" <<<"$smoke" || die "Presentation model is not active in config"
  grep -Fq "$REPORT_MODEL" <<<"$smoke" || die "Report model is not active in config"
  grep -Fq "$DEEP_MODEL" <<<"$smoke" || die "Deep model is not active in config"
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
  log "Starting safe model-pool upgrade. NVIDIA driver/kernel will not be modified."
  check_gpu
  check_ollama
  pull_models_sequentially
  update_local_config
  configure_ollama_lifecycle
  update_package
  verify_model_sequentially
  verify_application
  restart_chat

  UPGRADE_COMPLETE=1
  trap - ERR
  log "FINAL PASS: model-on-demand upgrade completed."
  log "Fast/Presentation/Report: $FAST_MODEL / $PRESENTATION_MODEL / $REPORT_MODEL"
  log "Research: $RESEARCH_MODEL"
  log "Deep escalation: $DEEP_MODEL"
  log "VRAM policy: max 1 loaded model; explicit unload between workflow stages"
}

main "$@"
