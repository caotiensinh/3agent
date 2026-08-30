#!/usr/bin/env bash
# Read-only resource snapshot for validating lean-profile / worker-pool changes on the
# real target machine (docs/WORKSPACE_LEAN_DUAL_5090_32GB_PROFILE.md).
#
# This script never changes system state. It prints one JSON object to stdout so a
# caller can capture a "before" snapshot, apply a change (e.g. the lean RAM profile, or
# `enable_gpu_worker_pool.sh --retire-dual-service`), capture an "after" snapshot, and
# diff the two. WorkSpace's own measurement discipline (docs/D3_METRICS.md,
# docs/WORKSPACE_DESIGN_PRINCIPLES.md Principle 10) requires every optimization claim to
# be backed by an actual before/after measurement rather than an assumption; this script
# is that instrument for host RAM/VRAM/service-count, since that measurement can only be
# taken on the physical dual-RTX5090 workstation, not in a CI runner or review sandbox.
#
# Privacy: only aggregate counters are captured. No hostname, GPU UUID/serial, process
# command line, model name or file content is recorded, matching the metadata-only
# discipline already used by evaluation/representative_hardware_closure_*.json.
set -Eeuo pipefail

LABEL="${1:-snapshot}"

log() { printf '[RAMBaseline] %s\n' "$*" >&2; }

ram_json() {
  local total_kib=0 avail_kib=0
  if [[ -r /proc/meminfo ]]; then
    total_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    avail_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
  fi
  local used_kib=$(( total_kib - avail_kib ))
  printf '"ram": {"total_kib": %d, "available_kib": %d, "used_kib": %d, "used_percent": %s}' \
    "$total_kib" "$avail_kib" "$used_kib" \
    "$(awk -v u="$used_kib" -v t="$total_kib" 'BEGIN { if (t > 0) printf "%.2f", (u / t) * 100; else print 0 }')"
}

gpu_json() {
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    printf '"gpus": null'
    return
  fi
  local rows
  rows="$(nvidia-smi --query-gpu=index,memory.total,memory.used,utilization.gpu,temperature.gpu \
    --format=csv,noheader,nounits 2>/dev/null || true)"
  if [[ -z "$rows" ]]; then
    printf '"gpus": null'
    return
  fi
  local first=1 out="["
  while IFS=',' read -r index total used util temp; do
    index="$(xargs <<<"$index")"; total="$(xargs <<<"$total")"
    used="$(xargs <<<"$used")"; util="$(xargs <<<"$util")"; temp="$(xargs <<<"$temp")"
    [[ -n "$index" ]] || continue
    (( first )) || out+=","
    first=0
    out+="{\"index\": ${index}, \"memory_total_mib\": ${total}, \"memory_used_mib\": ${used}, \"util_percent\": ${util}, \"temp_c\": ${temp}}"
  done <<<"$rows"
  out+="]"
  printf '"gpus": %s' "$out"
}

service_state() {
  systemctl is-active "$1" 2>/dev/null || printf 'unknown'
}

services_json() {
  local svc first=1 out="{"
  for svc in ollama ollama-gpu0.service ollama-gpu1.service 3agent-chat.service; do
    (( first )) || out+=","
    first=0
    out+="\"${svc}\": \"$(service_state "$svc")\""
  done
  out+="}"
  printf '"services": %s' "$out"
}

resident_models_json() {
  local port label first=1 out="{"
  for label_port in "dual:11434" "gpu0:11435" "gpu1:11436"; do
    label="${label_port%%:*}"
    port="${label_port##*:}"
    (( first )) || out+=","
    first=0
    local count
    count="$(curl -fsS --max-time 2 "http://127.0.0.1:${port}/api/ps" 2>/dev/null \
      | grep -o '"name"' | wc -l | tr -d ' ' || true)"
    [[ -n "$count" ]] || count="null"
    out+="\"${label}\": ${count}"
  done
  out+="}"
  printf '"resident_model_counts": %s' "$out"
}

printf '{\n'
printf '  "schema": "workspace-ram-baseline/v1",\n'
printf '  "label": "%s",\n' "$LABEL"
printf '  "timestamp": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  %s,\n' "$(ram_json)"
printf '  %s,\n' "$(gpu_json)"
printf '  %s,\n' "$(services_json)"
printf '  %s\n' "$(resident_models_json)"
printf '}\n'

log "Snapshot '$LABEL' captured. Redirect stdout to a file and diff before/after a change, e.g.:"
log "  scripts/measure_ram_baseline.sh before > /tmp/before.json"
log "  # ...apply the lean profile or --retire-dual-service..."
log "  scripts/measure_ram_baseline.sh after > /tmp/after.json"
log "  diff /tmp/before.json /tmp/after.json"
