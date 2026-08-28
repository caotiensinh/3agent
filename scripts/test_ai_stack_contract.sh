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
grep -q 'OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-2m}"' "$SCRIPT"
grep -q 'OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"' "$SCRIPT"
grep -q 'THREE_AGENT_FAST_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_RESEARCH_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_PRESENTATION_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_REPORT_MODEL' "$SCRIPT"
grep -q 'THREE_AGENT_DEEP_MODEL' "$SCRIPT"
grep -q 'deep_escalation: true' "$SCRIPT"
grep -q 'pull_models' "$SCRIPT"

if grep -Eq 'ubuntu-drivers|nvidia-driver-[0-9]|apt(-get)?[^#\n]*install[^#\n]*nvidia|(^|[[:space:]])reboot([[:space:]]|$)|rmmod[[:space:]]+nvidia|modprobe[[:space:]]+nvidia' "$SCRIPT"; then
  echo "AI-stack installer must not mutate NVIDIA driver/kernel state" >&2
  exit 1
fi

echo "AI stack installer contract PASS"
