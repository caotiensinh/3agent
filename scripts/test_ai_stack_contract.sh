#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/setup_ai_stack_ubuntu2404.sh"

bash -n "$SCRIPT"
bash "$SCRIPT" --self-test >/dev/null

grep -q 'nvidia-smi' "$SCRIPT"
grep -q 'CUDA_VISIBLE_DEVICES' "$SCRIPT"
grep -q 'ollama.com/install.sh' "$SCRIPT"
grep -q 'python3 -m venv' "$SCRIPT"
grep -q 'pip install -e' "$SCRIPT"
grep -q '/usr/local/bin/3agent' "$SCRIPT"
grep -q 'api/generate' "$SCRIPT"
grep -q 'think:false' "$SCRIPT"
grep -q 'num_predict:64' "$SCRIPT"
# shellcheck disable=SC2016 # literal installer contract, not shell expansion
grep -q 'OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-2m}"' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_VRAM_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_RAM_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_UTIL_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_POWER_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_TEMP_C' "$SCRIPT"
grep -q 'resource_control' "$SCRIPT"
grep -q 'fixed_model_count_limit' "$SCRIPT"
grep -q 'THREE_AGENT_FAST_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_RESEARCH_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_PRESENTATION_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_REPORT_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_DEEP_MODEL' "$SCRIPT"
grep -q 'deep_escalation: true' "$SCRIPT"
grep -q 'pull_models' "$SCRIPT"

if grep -q 'OLLAMA_MAX_LOADED_MODELS' "$SCRIPT"; then
  echo "AI-stack installer must not impose a fixed loaded-model count" >&2
  exit 1
fi

if grep -Eq 'ubuntu-drivers|nvidia-driver-[0-9]|apt(-get)?[^#\n]*install[^#\n]*nvidia|(^|[[:space:]])reboot([[:space:]]|$)|rmmod[[:space:]]+nvidia|modprobe[[:space:]]+nvidia' "$SCRIPT"; then
  echo "AI-stack installer must not mutate NVIDIA driver/kernel state" >&2
  exit 1
fi

echo "AI stack installer contract PASS"
