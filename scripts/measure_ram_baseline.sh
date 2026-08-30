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
# Every field is assembled through `jq`, never hand-rolled string concatenation: a first
# version built the JSON by hand and broke on real hardware (nvidia-smi/systemctl output
# containing bytes that are invalid unescaped inside a JSON string), a class of bug that
# only jq's own escaping reliably rules out regardless of what those commands print.
#
# Privacy: only aggregate counters are captured. No hostname, GPU UUID/serial, process
# command line, model name or file content is recorded, matching the metadata-only
# discipline already used by evaluation/representative_hardware_closure_*.json.
set -Eeuo pipefail

LABEL="${1:-snapshot}"

log() { printf '[RAMBaseline] %s\n' "$*" >&2; }
die() { printf '[RAMBaseline][ERROR] %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || die "jq is required"

ram_snapshot() {
  local total_kib=0 avail_kib=0
  if [[ -r /proc/meminfo ]]; then
    total_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    avail_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
  fi
  local used_kib=$(( total_kib - avail_kib ))
  jq -n --argjson total "$total_kib" --argjson avail "$avail_kib" --argjson used "$used_kib" '
    {
      total_kib: $total,
      available_kib: $avail,
      used_kib: $used,
      used_percent: (if $total > 0 then (($used / $total * 100 * 100 | round) / 100) else 0 end)
    }'
}

# Raw CSV lines from nvidia-smi, each field jq-parsed and coerced to a number where
# possible; a non-numeric field (nvidia-smi prints "[N/A]" for some metrics on some
# driver/power states) becomes null instead of producing invalid JSON or aborting.
gpu_snapshot() {
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    printf 'null'
    return
  fi
  local rows
  rows="$(nvidia-smi --query-gpu=index,memory.total,memory.used,utilization.gpu,temperature.gpu \
    --format=csv,noheader,nounits 2>/dev/null || true)"
  if [[ -z "$rows" ]]; then
    printf 'null'
    return
  fi
  jq -Rn '
    [inputs
      | select(length > 0)
      | split(",")
      | map(gsub("^\\s+|\\s+$"; ""))
      | select(length == 5)
      | {
          index: (.[0] | tonumber? // null),
          memory_total_mib: (.[1] | tonumber? // null),
          memory_used_mib: (.[2] | tonumber? // null),
          util_percent: (.[3] | tonumber? // null),
          temp_c: (.[4] | tonumber? // null)
        }]' <<<"$rows"
}

service_state() {
  # `systemctl is-active` exits non-zero for every state except "active" (inactive,
  # failed, unknown, ...) while still printing that state name to stdout, so gating the
  # fallback on exit status via `||` runs it even when the real state was already
  # printed, concatenating both into one garbled value. Gate on captured output instead.
  local state
  state="$(systemctl is-active "$1" 2>/dev/null)"
  if [[ -n "$state" ]]; then
    printf '%s' "$state"
  else
    printf 'unknown'
  fi
}

services_snapshot() {
  local json='{}' svc
  for svc in ollama ollama-gpu0.service ollama-gpu1.service 3agent-chat.service; do
    json="$(jq -c --arg k "$svc" --arg v "$(service_state "$svc")" '. + {($k): $v}' <<<"$json")"
  done
  printf '%s' "$json"
}

# Actual resident-model count per worker, parsed from Ollama's own /api/ps JSON rather
# than substring-counting the raw response text.
resident_models_snapshot() {
  local json='{}' label_port label port count
  for label_port in "dual:11434" "gpu0:11435" "gpu1:11436"; do
    label="${label_port%%:*}"
    port="${label_port##*:}"
    count="$(curl -fsS --max-time 2 "http://127.0.0.1:${port}/api/ps" 2>/dev/null \
      | jq '[.models[]?] | length' 2>/dev/null || true)"
    if [[ "$count" =~ ^[0-9]+$ ]]; then
      json="$(jq -c --arg k "$label" --argjson v "$count" '. + {($k): $v}' <<<"$json")"
    else
      json="$(jq -c --arg k "$label" '. + {($k): null}' <<<"$json")"
    fi
  done
  printf '%s' "$json"
}

jq -n \
  --arg schema "workspace-ram-baseline/v1" \
  --arg label "$LABEL" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson ram "$(ram_snapshot)" \
  --argjson gpus "$(gpu_snapshot)" \
  --argjson services "$(services_snapshot)" \
  --argjson resident_model_counts "$(resident_models_snapshot)" \
  '{
    schema: $schema,
    label: $label,
    timestamp: $timestamp,
    ram: $ram,
    gpus: $gpus,
    services: $services,
    resident_model_counts: $resident_model_counts
  }'

log "Snapshot '$LABEL' captured. Redirect stdout to a file and diff before/after a change, e.g.:"
log "  scripts/measure_ram_baseline.sh before > /tmp/before.json"
log "  # ...apply the lean profile or --retire-dual-service..."
log "  scripts/measure_ram_baseline.sh after > /tmp/after.json"
log "  diff /tmp/before.json /tmp/after.json"
