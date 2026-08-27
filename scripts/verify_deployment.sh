#!/usr/bin/env bash
set -Eeuo pipefail

MODEL="${1:-${THREE_AGENT_MODEL:-qwen3:30b}}"
fail() { echo "[verify][FAIL] $*" >&2; exit 1; }
pass() { echo "[verify][PASS] $*"; }

command -v nvidia-smi >/dev/null 2>&1 || fail "nvidia-smi not found"
nvidia-smi >/dev/null 2>&1 || fail "nvidia-smi failed"

GPU_COUNT="$(nvidia-smi --query-gpu=name --format=csv,noheader | grep -Eic 'RTX[[:space:]]*5090|GeForce RTX 5090' || true)"
(( GPU_COUNT >= 2 )) || fail "expected at least two RTX 5090 GPUs, found ${GPU_COUNT}"
pass "dual RTX 5090 visible"

curl -fsS http://127.0.0.1:11434/api/tags >/dev/null || fail "Ollama API unavailable"
pass "Ollama API reachable"

ollama list | awk 'NR>1 {print $1}' | grep -Fxq "$MODEL" || fail "model ${MODEL} not found in ollama list"
pass "model ${MODEL} installed"

command -v 3agent >/dev/null 2>&1 || fail "3agent command not installed"
3agent smoke >/dev/null || fail "3agent smoke failed"
pass "3Agent harness smoke"

# Keep the live generation check simple and shell-portable.
RESPONSE="$(curl -fsS http://127.0.0.1:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg model "$MODEL" '{model:$model,prompt:"Reply with exactly: 3AGENT_GPU_OK",stream:false,options:{num_predict:16,temperature:0}}')")"
jq -e '.done == true and (.response | type == "string")' <<<"$RESPONSE" >/dev/null || fail "Ollama live generation failed"
pass "local model generation"

nvidia-smi --query-compute-apps=gpu_uuid,process_name,used_gpu_memory --format=csv,noheader 2>/dev/null || true
pass "deployment verification complete"
