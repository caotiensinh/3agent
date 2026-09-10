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
grep -q 'THREE_AGENT_HARDWARE_PROFILE' "$SCRIPT"
grep -q 'THREE_AGENT_MIN_DRIVER_MAJOR' "$SCRIPT"
grep -q 'THREE_AGENT_REQUIRED_RTX5090_COUNT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_VRAM_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_RAM_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_UTIL_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_POWER_PERCENT' "$SCRIPT"
grep -q 'THREE_AGENT_MAX_GPU_TEMP_C' "$SCRIPT"
grep -q 'THREE_AGENT_MODEL_RAM_OVERHEAD_FACTOR' "$SCRIPT"
grep -q 'resource_control' "$SCRIPT"
grep -q 'admission_check' "$SCRIPT"
grep -q 'cpu_ram_preflight' "$SCRIPT"
grep -q 'Actual resident model VRAM' "$SCRIPT"
grep -q 'Actual RAM' "$SCRIPT"
grep -q 'Resident model count: dynamic' "$SCRIPT"
grep -q 'OLLAMA_NUM_PARALLEL=1' "$SCRIPT"
grep -q '^UnsetEnvironment=OLLAMA_MAX_LOADED_MODELS$' "$SCRIPT"
grep -q 'Legacy OLLAMA_MAX_LOADED_MODELS is still active' "$SCRIPT"
grep -q 'unittest discover' "$SCRIPT"
grep -q '3agent-chat.service' "$SCRIPT"
grep -q 'trap rollback ERR' "$SCRIPT"
grep -q 'Restored config' "$SCRIPT"
grep -q 'Removed newly-created Ollama lifecycle drop-in' "$SCRIPT"
grep -q 'UPGRADE_COMPLETE=1' "$SCRIPT"

# Hardware policy must be adaptive by default; strict NVIDIA/RTX requirements are opt-in.
# shellcheck disable=SC2016
grep -Fq 'HARDWARE_PROFILE="${THREE_AGENT_HARDWARE_PROFILE:-auto}"' "$SCRIPT"
# shellcheck disable=SC2016
grep -Fq 'MIN_DRIVER_MAJOR="${THREE_AGENT_MIN_DRIVER_MAJOR:-}"' "$SCRIPT"
# shellcheck disable=SC2016
grep -Fq 'REQUIRED_RTX5090_COUNT="${THREE_AGENT_REQUIRED_RTX5090_COUNT:-}"' "$SCRIPT"
grep -Fq 'No healthy NVIDIA runtime detected; using CPU/system-RAM model profile with GPU resource control disabled' "$SCRIPT"

if grep -Fq 'Need at least 2 RTX 5090 GPUs' "$SCRIPT"; then
  echo "Generic model-pool upgrade must not require two RTX 5090 GPUs" >&2
  exit 1
fi
if grep -Fq 'command -v nvidia-smi >/dev/null 2>&1 || die' "$SCRIPT"; then
  echo "Generic model-pool upgrade must not require nvidia-smi in auto mode" >&2
  exit 1
fi
if grep -Eq '^Environment="OLLAMA_MAX_LOADED_MODELS=' "$SCRIPT"; then
  echo "Model-pool upgrade must not impose a fixed loaded-model count" >&2
  exit 1
fi
if grep -Eq 'ubuntu-drivers|nvidia-driver-[0-9]|apt(-get)?[^#\n]*install[^#\n]*nvidia|(^|[[:space:]])reboot([[:space:]]|$)|rmmod[[:space:]]+nvidia|modprobe[[:space:]]+nvidia' "$SCRIPT"; then
  echo "Model-pool upgrade must not mutate NVIDIA driver/kernel state" >&2
  exit 1
fi

check_profile() {
  local expected="$1"
  shift
  local output
  output="$(env "$@" bash "$SCRIPT" --self-test)"
  printf '%s\n' "$output" | grep -Fq "$expected" || {
    printf 'adaptive model-pool selection mismatch\nexpected fragment: %s\nactual: %s\n' "$expected" "$output" >&2
    exit 1
  }
}

check_profile 'fast=qwen3:0.6b research=qwen3:1.7b' THREE_AGENT_TEST_VRAM_MIB=0 THREE_AGENT_TEST_RAM_MIB=8192
check_profile 'fast=qwen3:1.7b research=qwen3:4b' THREE_AGENT_TEST_VRAM_MIB=0 THREE_AGENT_TEST_RAM_MIB=16384
check_profile 'fast=qwen3:4b research=qwen3:8b' THREE_AGENT_TEST_VRAM_MIB=0 THREE_AGENT_TEST_RAM_MIB=32768
check_profile 'fast=qwen3:1.7b research=qwen3:4b' THREE_AGENT_TEST_VRAM_MIB=4096 THREE_AGENT_TEST_RAM_MIB=8192
check_profile 'fast=qwen3:4b research=qwen3:8b' THREE_AGENT_TEST_VRAM_MIB=8192 THREE_AGENT_TEST_RAM_MIB=8192
check_profile 'fast=qwen3:8b research=qwen3:14b' THREE_AGENT_TEST_VRAM_MIB=16384 THREE_AGENT_TEST_RAM_MIB=8192
check_profile 'fast=qwen3:8b research=qwen3:14b' THREE_AGENT_TEST_VRAM_MIB=24576 THREE_AGENT_TEST_RAM_MIB=8192
check_profile 'fast=qwen3:14b research=qwen3:30b' THREE_AGENT_TEST_VRAM_MIB=28672 THREE_AGENT_TEST_RAM_MIB=8192
check_profile 'fast=operator-fast research=operator-research' \
  THREE_AGENT_TEST_VRAM_MIB=4096 THREE_AGENT_TEST_RAM_MIB=8192 \
  THREE_AGENT_FAST_MODEL=operator-fast THREE_AGENT_RESEARCH_MODEL=operator-research

echo "Dynamic model resource contract PASS"
