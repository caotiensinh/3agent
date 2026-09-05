#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${THREE_AGENT_INSTALL_DIR:-$HOME/3agent}"
CONFIG_FILE="${THREE_AGENT_CONFIG:-$INSTALL_DIR/config/local.json}"
GPU0_PORT="${THREE_AGENT_GPU0_OLLAMA_PORT:-11435}"
GPU1_PORT="${THREE_AGENT_GPU1_OLLAMA_PORT:-11436}"
DUAL_PORT="${THREE_AGENT_DUAL_OLLAMA_PORT:-11434}"
TEST_MODEL="${THREE_AGENT_WORKER_TEST_MODEL:-qwen3:14b}"
KEEP_ALIVE="${THREE_AGENT_MODEL_KEEP_ALIVE:-2m}"
SELF_TEST=0
RETIRE_DUAL_SERVICE=0
CONFIG_BACKUP=""
UNIT0_BACKUP=""
UNIT1_BACKUP=""
UNIT0="/etc/systemd/system/ollama-gpu0.service"
UNIT1="/etc/systemd/system/ollama-gpu1.service"
COMPLETE=0

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    --retire-dual-service) RETIRE_DUAL_SERVICE=1 ;;
    *) printf '[3Agent-GPUWorkers][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[3Agent-GPUWorkers] %s\n' "$*"; }
warn() { printf '[3Agent-GPUWorkers][WARN] %s\n' "$*" >&2; }
die() { printf '[3Agent-GPUWorkers][ERROR] %s\n' "$*" >&2; exit 1; }

validate_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1024 && "$1" <= 65535 ))
}

validate_settings() {
  validate_port "$GPU0_PORT" || die "Invalid GPU0 port: $GPU0_PORT"
  validate_port "$GPU1_PORT" || die "Invalid GPU1 port: $GPU1_PORT"
  validate_port "$DUAL_PORT" || die "Invalid dual port: $DUAL_PORT"
  [[ "$GPU0_PORT" != "$GPU1_PORT" && "$GPU0_PORT" != "$DUAL_PORT" && "$GPU1_PORT" != "$DUAL_PORT" ]] \
    || die "Worker ports must be unique"
  [[ -n "$TEST_MODEL" ]] || die "TEST_MODEL is empty"
}

if [[ "$SELF_TEST" == "1" ]]; then
  validate_settings
  log "GPU worker-pool self-test PASS"
  exit 0
fi

rollback() {
  local rc="$?"
  if [[ "$COMPLETE" == "1" ]]; then
    return 0
  fi
  set +e
  warn "Worker-pool deployment failed; rolling back."
  if [[ -n "$CONFIG_BACKUP" && -f "$CONFIG_BACKUP" ]]; then
    cp -a "$CONFIG_BACKUP" "$CONFIG_FILE"
  fi
  if [[ -n "$UNIT0_BACKUP" && -f "$UNIT0_BACKUP" ]]; then
    sudo cp -a "$UNIT0_BACKUP" "$UNIT0"
  else
    sudo rm -f "$UNIT0"
  fi
  if [[ -n "$UNIT1_BACKUP" && -f "$UNIT1_BACKUP" ]]; then
    sudo cp -a "$UNIT1_BACKUP" "$UNIT1"
  else
    sudo rm -f "$UNIT1"
  fi
  sudo systemctl daemon-reload
  sudo systemctl stop ollama-gpu0.service ollama-gpu1.service >/dev/null 2>&1 || true
  systemctl --user restart 3agent-chat.service >/dev/null 2>&1 || true
  warn "Rollback complete."
  exit "$rc"
}
trap rollback ERR

validate_settings
[[ -d "$INSTALL_DIR/.git" ]] || die "3Agent checkout not found: $INSTALL_DIR"
[[ -f "$CONFIG_FILE" ]] || die "Config not found: $CONFIG_FILE"
command -v nvidia-smi >/dev/null 2>&1 || die "nvidia-smi is required"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"
OLLAMA_BIN="$(command -v ollama)"
[[ -n "$OLLAMA_BIN" ]] || die "ollama is required"

systemctl is-active --quiet ollama || die "Existing dual-GPU ollama.service must be active"

mapfile -t GPU_ROWS < <(nvidia-smi --query-gpu=index,name,uuid --format=csv,noheader)
declare -a GPU_UUIDS=()
for row in "${GPU_ROWS[@]}"; do
  IFS=',' read -r index name uuid <<<"$row"
  name="$(xargs <<<"$name")"
  uuid="$(xargs <<<"$uuid")"
  if [[ "$name" == *"RTX 5090"* ]]; then
    GPU_UUIDS+=("$uuid")
    log "Detected RTX 5090 index=$(xargs <<<"$index") uuid=$uuid"
  fi
done
(( ${#GPU_UUIDS[@]} >= 2 )) || die "Need at least two RTX 5090 GPUs"
GPU0_UUID="${GPU_UUIDS[0]}"
GPU1_UUID="${GPU_UUIDS[1]}"

SERVICE_USER="$(systemctl show ollama --property=User --value)"
SERVICE_GROUP="$(systemctl show ollama --property=Group --value)"
[[ -n "$SERVICE_USER" ]] || SERVICE_USER="ollama"
[[ -n "$SERVICE_GROUP" ]] || SERVICE_GROUP="$SERVICE_USER"

MODEL_DIR=""
SERVICE_ENV="$(systemctl show ollama --property=Environment --value)"
if [[ "$SERVICE_ENV" =~ OLLAMA_MODELS=([^[:space:]]+) ]]; then
  MODEL_DIR="${BASH_REMATCH[1]}"
  MODEL_DIR="${MODEL_DIR%\"}"
  MODEL_DIR="${MODEL_DIR#\"}"
fi
if [[ -z "$MODEL_DIR" ]]; then
  MODEL_DIR="/usr/share/ollama/.ollama/models"
fi
[[ -d "$MODEL_DIR" ]] || warn "Shared model directory is not currently visible at $MODEL_DIR; workers will still start and report any model-path error explicitly."

backup_unit() {
  local unit="$1"
  local var_name="$2"
  if sudo test -f "$unit"; then
    local backup
    backup="${TMPDIR:-/tmp}/$(basename "$unit").before-3agent.$(date +%Y%m%d-%H%M%S)"
    sudo cp -a "$unit" "$backup"
    printf -v "$var_name" '%s' "$backup"
  fi
}
backup_unit "$UNIT0" UNIT0_BACKUP
backup_unit "$UNIT1" UNIT1_BACKUP

write_worker_unit() {
  local unit="$1"
  local description="$2"
  local port="$3"
  local uuid="$4"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
[Unit]
Description=${description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
Environment="CUDA_VISIBLE_DEVICES=${uuid}"
Environment="OLLAMA_HOST=127.0.0.1:${port}"
Environment="OLLAMA_MODELS=${MODEL_DIR}"
Environment="OLLAMA_KEEP_ALIVE=${KEEP_ALIVE}"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
ExecStart=${OLLAMA_BIN} serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  sudo install -m 0644 "$tmp" "$unit"
  rm -f "$tmp"
}

write_worker_unit "$UNIT0" "Ollama GPU0 Worker for 3Agent" "$GPU0_PORT" "$GPU0_UUID"
write_worker_unit "$UNIT1" "Ollama GPU1 Worker for 3Agent" "$GPU1_PORT" "$GPU1_UUID"
sudo systemctl daemon-reload
sudo systemctl enable --now ollama-gpu0.service ollama-gpu1.service

wait_api() {
  local port="$1"
  local name="$2"
  for _ in {1..60}; do
    if curl -fsS "http://127.0.0.1:${port}/api/tags" >/dev/null 2>&1; then
      log "$name API PASS on port $port"
      return 0
    fi
    sleep 1
  done
  sudo systemctl status "$name" --no-pager || true
  die "$name API did not become ready"
}
wait_api "$GPU0_PORT" ollama-gpu0.service
wait_api "$GPU1_PORT" ollama-gpu1.service
wait_api "$DUAL_PORT" ollama.service

CONFIG_BACKUP="${CONFIG_FILE}.before-gpu-workers.$(date +%Y%m%d-%H%M%S)"
cp -a "$CONFIG_FILE" "$CONFIG_BACKUP"
TMP_CONFIG="$(mktemp)"
jq \
  --arg gpu0 "http://127.0.0.1:${GPU0_PORT}" \
  --arg gpu1 "http://127.0.0.1:${GPU1_PORT}" \
  --arg dual "http://127.0.0.1:${DUAL_PORT}" \
  '.model_policy.worker_pool = {
      enabled: true,
      gpu0_url: $gpu0,
      gpu1_url: $gpu1,
      dual_url: $dual
    }' \
  "$CONFIG_FILE" >"$TMP_CONFIG"
jq -e '.model_policy.worker_pool.enabled == true' "$TMP_CONFIG" >/dev/null
install -m 0644 "$TMP_CONFIG" "$CONFIG_FILE"
rm -f "$TMP_CONFIG"

"$INSTALL_DIR/.venv/bin/python" -m pip install -e "$INSTALL_DIR"
PYTHONPATH="$INSTALL_DIR/src" "$INSTALL_DIR/.venv/bin/python" -m unittest discover -s "$INSTALL_DIR/tests" -v

SMOKE="$(THREE_AGENT_CONFIG="$CONFIG_FILE" "$INSTALL_DIR/.venv/bin/three-agent" smoke)"
printf '%s\n' "$SMOKE"
grep -q '"worker_pool_enabled": true' <<<"$SMOKE" || die "Worker pool is not enabled in runtime"
grep -Fq "127.0.0.1:${GPU0_PORT}" <<<"$SMOKE" || die "GPU0 worker URL missing"
grep -Fq "127.0.0.1:${GPU1_PORT}" <<<"$SMOKE" || die "GPU1 worker URL missing"

unload_model() {
  local port="$1"
  local payload
  payload="$(jq -nc --arg model "$TEST_MODEL" '{model:$model,prompt:"",stream:false,keep_alive:0}')"
  curl -fsS --max-time 60 -H 'Content-Type: application/json' -d "$payload" \
    "http://127.0.0.1:${port}/api/generate" >/dev/null 2>&1 || true
}

read_used_mib() {
  nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | awk '{print int($1)}'
}

verify_affinity() {
  local port="$1"
  local target="$2"
  local label="$3"
  local -a before after
  local payload response target_delta other other_delta

  unload_model "$GPU0_PORT"
  unload_model "$GPU1_PORT"
  unload_model "$DUAL_PORT"
  sleep 2
  mapfile -t before < <(read_used_mib)

  payload="$(jq -nc --arg model "$TEST_MODEL" --arg keep "$KEEP_ALIVE" '{model:$model,prompt:"Reply with only READY.",stream:false,think:false,keep_alive:$keep,options:{num_predict:32}}')"
  response="$(curl -fsS --max-time 600 -H 'Content-Type: application/json' -d "$payload" "http://127.0.0.1:${port}/api/generate")"
  jq -e '(.response // "") | strings | length > 0' <<<"$response" >/dev/null || die "$label inference failed"
  mapfile -t after < <(read_used_mib)
  (( ${#before[@]} >= 2 && ${#after[@]} >= 2 )) || die "Could not read both GPU memory counters"

  target_delta=$(( after[target] - before[target] ))
  other=$(( 1 - target ))
  other_delta=$(( after[other] - before[other] ))
  log "$label affinity delta: target=${target_delta}MiB other=${other_delta}MiB"
  (( target_delta >= 1024 )) || die "$label did not allocate significant VRAM on its target GPU"
  (( other_delta < 1024 )) || die "$label unexpectedly allocated >=1GiB on the non-target GPU"
  unload_model "$port"
  sleep 1
}

verify_affinity "$GPU0_PORT" 0 "GPU0 worker"
verify_affinity "$GPU1_PORT" 1 "GPU1 worker"

systemctl --user restart 3agent-chat.service
sleep 2
systemctl --user is-active --quiet 3agent-chat.service || die "3Agent chat service did not recover"

COMPLETE=1

# Optional, opt-in avoid-duplicate-work step (see docs/WORKSPACE_LEAN_DUAL_5090_32GB_PROFILE.md).
#
# ollama.service (the pre-existing dual-GPU daemon on $DUAL_PORT) is only reachable by
# OllamaWorkerPool as a fallback when a model does not fit the single-GPU VRAM budget of
# either worker. If every model in the configured pool fits one RTX 5090, that fallback
# path is never exercised and the resident dual-GPU daemon is pure duplicate overhead
# (a third Ollama runtime plus its own model-metadata cache) on a host where system RAM,
# not GPU VRAM, is the constrained resource. Retirement is opt-in and reversible: it only
# proceeds after verifying every configured model actually fits, and it never touches the
# already-verified GPU0/GPU1 worker units.
retire_dual_service_if_safe() {
  log "Evaluating whether ollama.service (dual-GPU fallback) can be retired for this model pool."

  local vram_limit_percent
  vram_limit_percent="$(jq -r '.model_policy.resource_control.max_vram_percent // 90' "$CONFIG_FILE")"
  [[ "$vram_limit_percent" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { warn "Cannot read max_vram_percent from $CONFIG_FILE"; return 1; }

  local -a gpu_total_mib
  mapfile -t gpu_total_mib < <(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits)
  (( ${#gpu_total_mib[@]} >= 2 )) || { warn "Could not read per-GPU VRAM totals"; return 1; }
  local smallest_total_mib="${gpu_total_mib[0]}" candidate
  for candidate in "${gpu_total_mib[@]}"; do
    (( candidate < smallest_total_mib )) && smallest_total_mib="$candidate"
  done
  local budget_mib
  budget_mib="$(awk -v t="$smallest_total_mib" -v p="$vram_limit_percent" 'BEGIN { printf "%d", (t * p / 100) }')"

  local -a pool_models
  mapfile -t pool_models < <(jq -r '
      (.model_policy | [.fast_model, .research_model, .presentation_model, .report_model, .deep_model]) // []
      | map(select(type == "string" and length > 0)) | unique[]
    ' "$CONFIG_FILE" 2>/dev/null)
  (( ${#pool_models[@]} > 0 )) || { warn "No configured model pool found in $CONFIG_FILE; leaving ollama.service running"; return 1; }

  local tags_json
  tags_json="$(curl -fsS "http://127.0.0.1:${GPU0_PORT}/api/tags")" || { warn "Could not query GPU0 worker for model sizes"; return 1; }

  local model size_bytes size_mib
  for model in "${pool_models[@]}"; do
    size_bytes="$(jq -r --arg m "$model" '
        [.models[] | select(.name == $m or (.name | split(":")[0]) == ($m | split(":")[0])) | .size][0] // empty
      ' <<<"$tags_json")"
    if [[ -z "$size_bytes" ]]; then
      warn "Model $model has no size metadata on the GPU0 worker yet; leaving ollama.service running"
      return 1
    fi
    size_mib="$(awk -v b="$size_bytes" 'BEGIN { printf "%d", (b / 1024 / 1024) * 1.15 }')"
    if (( size_mib > budget_mib )); then
      warn "Model $model (~${size_mib}MiB with safety margin) exceeds the single-GPU budget (~${budget_mib}MiB);" \
        "the dual-GPU fallback is still required. Leaving ollama.service running."
      return 1
    fi
    log "Model $model fits the single-GPU budget: ~${size_mib}MiB <= ~${budget_mib}MiB"
  done

  log "Every pooled model fits one RTX 5090's VRAM budget; ollama.service is redundant capacity for this pool."
  sudo systemctl disable --now ollama.service
  log "ollama.service (dual-GPU fallback) is now stopped and disabled. GPU0/GPU1 workers are unaffected."
  log "Re-enable it any time with: sudo systemctl enable --now ollama.service"
  return 0
}

if [[ "$RETIRE_DUAL_SERVICE" == "1" ]]; then
  retire_dual_service_if_safe || warn "Dual-service retirement was skipped; ollama.service is left running and unchanged."
fi
trap - ERR
log "FINAL PASS: GPU-affined worker pool enabled."
log "GPU0 worker: http://127.0.0.1:${GPU0_PORT} -> ${GPU0_UUID}"
log "GPU1 worker: http://127.0.0.1:${GPU1_PORT} -> ${GPU1_UUID}"
log "Dual worker: http://127.0.0.1:${DUAL_PORT} -> both GPUs"
log "Per-GPU VRAM hard cap remains 90%; scheduler balance target remains <=10% when splittable."
