#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/enable_model_pool.sh"

bash -n "$SCRIPT"
bash "$SCRIPT" --self-test >/dev/null

grep -q 'THREE_AGENT_FAST_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_RESEARCH_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_PRESENTATION_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_REPORT_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_DEEP_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_VRAM_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_RAM_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_UTIL_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_POWER_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_TEMP_C' "$SCRIPT"
grep -q 'resource_control' "$SCRIPT"
grep -q 'admission_check' "$SCRIPT"
grep -q 'Actual resident model VRAM' "$SCRIPT"
grep -q 'Resident model count: dynamic' "$SCRIPT"
grep -q 'OLLAMA_NUM_PARALLEL=1' "$SCRIPT"
grep -q 'unittest discover' "$SCRIPT"
grep -q '3agent-chat.service' "$SCRIPT"
grep -q 'trap rollback ERR' "$SCRIPT"
grep -q 'Restored config' "$SCRIPT"
grep -q 'Removed newly-created Ollama lifecycle drop-in' "$SCRIPT"
grep -q 'UPGRADE_COMPLETE=1' "$SCRIPT"

if grep -q 'OLLAMA_MAX_LOADED_MODELS' "$SCRIPT"; then
  echo "Model-pool upgrade must not impose a fixed loaded-model count" >&2
  exit 1
fi

if grep -Eq 'ubuntu-drivers|nvidia-driver-[0-9]|apt(-get)?[^#\n]*install[^#\n]*nvidia|(^|[[:space:]])reboot([[:space:]]|$)|rmmod[[:space:]]+nvidia|modprobe[[:space:]]+nvidia' "$SCRIPT"; then
  echo "Model-pool upgrade must not mutate NVIDIA driver/kernel state" >&2
  exit 1
fi

echo "Dynamic model resource contract PASS"
