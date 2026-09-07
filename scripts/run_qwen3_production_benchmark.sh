#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SOURCE="config/model-candidates/qwen3-embedding-0.6b.source.json"
ARTIFACTS="config/model-candidates/qwen3-embedding-0.6b.artifacts.txt"
BENCHMARK="config/benchmarks/qwen3-embedding-retrieval-v1.json"
OUTPUT="${1:-reports/model-candidates/qwen3-production-benchmark.json}"
WORK_ROOT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/workspace-qwen3-production-${GITHUB_RUN_ID:-$$}"
EVIDENCE="$WORK_ROOT/candidate-evidence.json"
SNAPSHOT="$WORK_ROOT/verified-snapshot"
HF_HOME="$WORK_ROOT/hf-home"
SENTENCE_TRANSFORMERS_HOME="$WORK_ROOT/sentence-transformers"

cleanup() {
  rm -rf "$SNAPSHOT" "$HF_HOME" "$SENTENCE_TRANSFORMERS_HOME"
}
trap cleanup EXIT
mkdir -p "$WORK_ROOT" "$(dirname "$OUTPUT")"

command -v nvidia-smi >/dev/null || { echo "ERROR: nvidia-smi is required" >&2; exit 20; }
GPU_COUNT="$(nvidia-smi --query-gpu=name --format=csv,noheader | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
RTX5090_COUNT="$(nvidia-smi --query-gpu=name --format=csv,noheader | grep -c 'RTX 5090' || true)"
if [[ "$GPU_COUNT" -lt 2 ]]; then
  echo "ERROR: representative benchmark requires at least 2 NVIDIA GPUs; found $GPU_COUNT" >&2
  exit 21
fi
if [[ "$RTX5090_COUNT" -lt 2 ]]; then
  echo "ERROR: representative WorkSpace gate requires two RTX 5090 GPUs; found $RTX5090_COUNT" >&2
  exit 22
fi

readarray -t IDENTITY < <(python3 - <<'PY'
import json
from pathlib import Path
src = json.loads(Path('config/model-candidates/qwen3-embedding-0.6b.source.json').read_text(encoding='utf-8'))
if src.get('status') != 'candidate_only' or src.get('approval', {}).get('approved') is not False:
    raise SystemExit('candidate must remain candidate_only and unapproved')
if src.get('repo_id') != 'Qwen/Qwen3-Embedding-0.6B':
    raise SystemExit('candidate repo drift')
if src.get('revision') != '97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3':
    raise SystemExit('candidate revision drift')
print(src['repo_id'])
print(src['revision'])
PY
)
REPO_ID="${IDENTITY[0]}"
REVISION="${IDENTITY[1]}"

export HF_HOME SENTENCE_TRANSFORMERS_HOME
python3 scripts/audit_hf_model_candidate.py \
  --repo-id "$REPO_ID" \
  --revision "$REVISION" \
  --artifact-file "$ARTIFACTS" \
  --output "$EVIDENCE" \
  --snapshot-output "$SNAPSHOT"

python3 - "$SOURCE" "$EVIDENCE" <<'PY'
import json, sys
from pathlib import Path
source = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
evidence = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
if evidence.get('schema') != 'workspace.model-candidate-evidence/v1':
    raise SystemExit('unexpected evidence schema')
if evidence.get('status') != 'candidate_only' or evidence.get('runtime_download') is not False:
    raise SystemExit('candidate evidence authority drift')
if evidence.get('approval', {}).get('approved') is not False:
    raise SystemExit('candidate evidence unexpectedly approved')
if evidence.get('repo_id') != source.get('repo_id') or evidence.get('revision') != source.get('revision'):
    raise SystemExit('candidate identity drift')
by_path = {x['path']: x for x in evidence.get('artifacts', [])}
for path, anchor in source.get('expected_anchors', {}).items():
    if by_path.get(path, {}).get('sha256') != anchor.get('sha256'):
        raise SystemExit(f'anchor mismatch: {path}')
print('candidate anchors verified')
PY

export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export HF_HUB_DISABLE_TELEMETRY=1

PYTHON_BIN="$(command -v python3)"
if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
  sudo --preserve-env=HF_HUB_OFFLINE,TRANSFORMERS_OFFLINE,HF_HUB_DISABLE_TELEMETRY,HF_HOME,SENTENCE_TRANSFORMERS_HOME \
    unshare --net -- "$PYTHON_BIN" scripts/run_qwen3_production_benchmark.py \
      --evidence "$EVIDENCE" \
      --snapshot "$SNAPSHOT" \
      --benchmark "$BENCHMARK" \
      --output "$OUTPUT"
else
  echo "ERROR: passwordless sudo is required to prove OS-level network isolation" >&2
  exit 23
fi

python3 - "$OUTPUT" <<'PY'
import json, sys
from pathlib import Path
receipt = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if receipt.get('schema') != 'workspace.embedding-production-benchmark/v1':
    raise SystemExit('unexpected benchmark receipt schema')
if receipt.get('status') != 'production_benchmark_pass':
    raise SystemExit('production benchmark did not pass')
if receipt.get('admission', {}).get('production_approval') is not False:
    raise SystemExit('benchmark must not grant production approval')
if receipt.get('admission', {}).get('runtime_authority') is not False:
    raise SystemExit('benchmark must not grant runtime authority')
print(f"PASS: {sys.argv[1]}")
PY
