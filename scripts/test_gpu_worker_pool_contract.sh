#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/enable_gpu_worker_pool.sh"

bash -n "$SCRIPT"
bash "$SCRIPT" --self-test >/dev/null

grep -q 'THREE_AGENT_GPU0_OLLAMA_PORT' "$SCRIPT"
grep -q 'THREE_AGENT_GPU1_OLLAMA_PORT' "$SCRIPT"
grep -q 'THREE_AGENT_DUAL_OLLAMA_PORT' "$SCRIPT"
grep -q 'worker_pool' "$SCRIPT"
grep -q 'verify_affinity' "$SCRIPT"
grep -q 'trap rollback ERR' "$SCRIPT"
grep -q 'unittest discover' "$SCRIPT"
grep -q '3agent-chat.service' "$SCRIPT"

# Opt-in, avoid-duplicate-work retirement of the redundant dual-GPU ollama.service.
grep -q -- '--retire-dual-service' "$SCRIPT"
grep -q 'RETIRE_DUAL_SERVICE=0' "$SCRIPT"
grep -q 'retire_dual_service_if_safe' "$SCRIPT"
# shellcheck disable=SC2016 # literal source-text match, not shell expansion
grep -Fq 'if [[ "$RETIRE_DUAL_SERVICE" == "1" ]]' "$SCRIPT"

# The safety check must exist: it must refuse to retire when a pooled model does not fit
# a single GPU's VRAM budget, and it must state how to reverse the retirement.
grep -q 'the dual-GPU fallback is still required' "$SCRIPT"
grep -q 'sudo systemctl enable --now ollama.service' "$SCRIPT"
grep -q 'sudo systemctl disable --now ollama.service' "$SCRIPT"

# The retirement step must be defined strictly after COMPLETE=1 so a failure inside it
# cannot trigger the install rollback trap and tear down an already-working worker pool.
COMPLETE_LINE="$(grep -n '^COMPLETE=1$' "$SCRIPT" | tail -1 | cut -d: -f1)"
RETIRE_DEF_LINE="$(grep -n '^retire_dual_service_if_safe()' "$SCRIPT" | cut -d: -f1)"
[[ -n "$COMPLETE_LINE" && -n "$RETIRE_DEF_LINE" ]] || {
  echo "Could not locate COMPLETE=1 or retire_dual_service_if_safe() markers" >&2
  exit 1
}
(( RETIRE_DEF_LINE > COMPLETE_LINE )) || {
  echo "retire_dual_service_if_safe must be defined after COMPLETE=1" >&2
  exit 1
}

# The retirement call must never be able to abort the script via set -e: it must be
# guarded with || so a failed safety check only warns and leaves ollama.service running.
grep -q 'retire_dual_service_if_safe || warn' "$SCRIPT"

if grep -Eq 'ubuntu-drivers|nvidia-driver-[0-9]|apt(-get)?[^#\n]*install[^#\n]*nvidia|(^|[[:space:]])reboot([[:space:]]|$)|rmmod[[:space:]]+nvidia|modprobe[[:space:]]+nvidia' "$SCRIPT"; then
  echo "GPU worker-pool script must not mutate NVIDIA driver/kernel state" >&2
  exit 1
fi

echo "GPU worker-pool contract PASS"
