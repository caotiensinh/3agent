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
DOCKER_IMAGE=""

cleanup() {
  if [[ -n "$DOCKER_IMAGE" ]] && command -v docker >/dev/null; then
    docker image rm -f "$DOCKER_IMAGE" >/dev/null 2>&1 || true
  fi
  rm -rf "$SNAPSHOT" "$HF_HOME" "$SENTENCE_TRANSFORMERS_HOME" "$WORK_ROOT/container-runtime"
  rm -f "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/qwen3-empty-${GITHUB_RUN_ID:-$$}.tar"
}
trap cleanup EXIT
mkdir -p "$WORK_ROOT" "$(dirname "$OUTPUT")"

command -v nvidia-smi >/dev/null || { echo "ERROR: nvidia-smi is required" >&2; exit 20; }
echo "GPU inventory:"
nvidia-smi --query-gpu=index,name,memory.total,driver_version --format=csv,noheader
GPU_COUNT="$(nvidia-smi --query-gpu=index --format=csv,noheader | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
echo "Detected NVIDIA GPU count: $GPU_COUNT"
if [[ "$GPU_COUNT" -lt 2 ]]; then
  echo "ERROR: representative benchmark requires at least 2 NVIDIA GPUs; found $GPU_COUNT" >&2
  exit 21
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

make_empty_docker_image() {
  local image="$1"
  local tarball="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/qwen3-empty-${GITHUB_RUN_ID:-$$}.tar"
  tar -cf "$tarball" --files-from /dev/null
  docker import "$tarball" "$image" >/dev/null
}

docker_base_mounts() {
  printf '%s\n' "--mount" "type=bind,src=/usr,dst=/usr,readonly" "--mount" "type=bind,src=/lib,dst=/lib,readonly"
  if [[ -d /lib64 ]]; then
    printf '%s\n' "--mount" "type=bind,src=/lib64,dst=/lib64,readonly"
  fi
}

probe_docker_isolation() {
  command -v docker >/dev/null || return 1
  docker info >/dev/null 2>&1 || return 1
  local image="workspace-qwen3-netprobe:${GITHUB_RUN_ID:-$$}"
  local probe="import socket; names={n for _,n in socket.if_nameindex()}; assert names <= {'lo'}, names; s=socket.socket(); s.settimeout(0.5); rc=s.connect_ex(('1.1.1.1',443)); s.close(); assert rc != 0, rc; print('network isolation verified', sorted(names))"
  local -a mounts=()
  while IFS= read -r item; do mounts+=("$item"); done < <(docker_base_mounts)
  make_empty_docker_image "$image"
  if ! docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
      "${mounts[@]}" --entrypoint /usr/bin/python3 "$image" -c "$probe" >/dev/null; then
    docker image rm -f "$image" >/dev/null 2>&1 || true
    return 1
  fi
  if ! docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
      --gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,utility \
      "${mounts[@]}" --entrypoint /usr/bin/nvidia-smi "$image" \
      --query-gpu=index,name --format=csv,noheader >/dev/null; then
    docker image rm -f "$image" >/dev/null 2>&1 || true
    return 1
  fi
  docker image rm -f "$image" >/dev/null 2>&1 || true
  return 0
}

select_isolation() {
  local probe="import socket; names={n for _,n in socket.if_nameindex()}; assert names <= {'lo'}, names; s=socket.socket(); s.settimeout(0.5); rc=s.connect_ex(('1.1.1.1',443)); s.close(); assert rc != 0, rc; print('network isolation verified', sorted(names))"
  if [[ -n "${NETWORK_ISOLATION_MODE:-}" ]]; then
    case "$NETWORK_ISOLATION_MODE" in
      sudo-net|userns-net|firejail-net|docker-none) echo "$NETWORK_ISOLATION_MODE"; return 0 ;;
      *) echo "ERROR: invalid requested NETWORK_ISOLATION_MODE=$NETWORK_ISOLATION_MODE" >&2; return 1 ;;
    esac
  fi
  if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
    if sudo unshare --net -- python3 -c "$probe" >/dev/null 2>&1; then
      echo sudo-net
      return 0
    fi
  fi
  if unshare --user --map-root-user --net -- python3 -c "$probe" >/dev/null 2>&1; then
    echo userns-net
    return 0
  fi
  if command -v firejail >/dev/null && firejail --quiet --net=none -- python3 -c "$probe" >/dev/null 2>&1; then
    echo firejail-net
    return 0
  fi
  if probe_docker_isolation; then
    echo docker-none
    return 0
  fi
  return 1
}

ISOLATION_MODE="$(select_isolation || true)"
if [[ -z "$ISOLATION_MODE" ]]; then
  echo "ERROR: no verified OS-level network isolation path is available" >&2
  exit 23
fi
echo "Network isolation mode: $ISOLATION_MODE"

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
export PYTHONDONTWRITEBYTECODE=1
PYTHON_BIN="$(command -v python3)"
COMMON_ARGS=(
  scripts/run_qwen3_production_benchmark.py
  --evidence "$EVIDENCE"
  --snapshot "$SNAPSHOT"
  --benchmark "$BENCHMARK"
  --output "$OUTPUT"
)

if [[ "$ISOLATION_MODE" == "sudo-net" ]]; then
  sudo --preserve-env=HF_HUB_OFFLINE,TRANSFORMERS_OFFLINE,HF_HUB_DISABLE_TELEMETRY,HF_HOME,SENTENCE_TRANSFORMERS_HOME,PYTHONDONTWRITEBYTECODE,NETWORK_ISOLATION_MODE \
    unshare --net -- "$PYTHON_BIN" "${COMMON_ARGS[@]}"
elif [[ "$ISOLATION_MODE" == "userns-net" ]]; then
  unshare --user --map-root-user --net -- "$PYTHON_BIN" "${COMMON_ARGS[@]}"
elif [[ "$ISOLATION_MODE" == "firejail-net" ]]; then
  firejail --quiet --net=none -- "$PYTHON_BIN" "${COMMON_ARGS[@]}"
elif [[ "$ISOLATION_MODE" == "docker-none" ]]; then
  command -v docker >/dev/null || { echo 'ERROR: Docker selected but CLI is unavailable' >&2; exit 24; }
  docker info >/dev/null 2>&1 || { echo 'ERROR: Docker selected but daemon access is unavailable' >&2; exit 24; }
  DOCKER_IMAGE="workspace-qwen3-offline:${GITHUB_RUN_ID:-$$}"
  make_empty_docker_image "$DOCKER_IMAGE"
  VENV_ROOT="$(cd "$(dirname "$PYTHON_BIN")/.." && pwd)"
  CONTAINER_RUNTIME="$WORK_ROOT/container-runtime"
  CONTAINER_OUTPUT="$CONTAINER_RUNTIME/qwen3-production-benchmark.json"
  mkdir -p "$CONTAINER_RUNTIME/hf-home" "$CONTAINER_RUNTIME/sentence-transformers" "$CONTAINER_RUNTIME/tmp"
  local_mounts=(
    --mount "type=bind,src=/usr,dst=/usr,readonly"
    --mount "type=bind,src=/lib,dst=/lib,readonly"
    --mount "type=bind,src=$ROOT,dst=$ROOT,readonly"
    --mount "type=bind,src=$VENV_ROOT,dst=$VENV_ROOT,readonly"
    --mount "type=bind,src=$WORK_ROOT,dst=$WORK_ROOT,readonly"
    --mount "type=bind,src=$CONTAINER_RUNTIME,dst=$CONTAINER_RUNTIME"
  )
  if [[ -d /lib64 ]]; then local_mounts+=(--mount "type=bind,src=/lib64,dst=/lib64,readonly"); fi
  docker run --rm \
    --network none \
    --gpus all \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 1024 \
    --tmpfs /tmp:rw,nosuid,nodev,size=1073741824 \
    -e NVIDIA_DRIVER_CAPABILITIES=compute,utility \
    -e HF_HUB_OFFLINE=1 \
    -e TRANSFORMERS_OFFLINE=1 \
    -e HF_HUB_DISABLE_TELEMETRY=1 \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -e NETWORK_ISOLATION_MODE=docker-none \
    -e "HF_HOME=$CONTAINER_RUNTIME/hf-home" \
    -e "SENTENCE_TRANSFORMERS_HOME=$CONTAINER_RUNTIME/sentence-transformers" \
    -e "TMPDIR=$CONTAINER_RUNTIME/tmp" \
    -w "$ROOT" \
    "${local_mounts[@]}" \
    --entrypoint "$PYTHON_BIN" \
    "$DOCKER_IMAGE" \
    scripts/run_qwen3_production_benchmark.py \
      --evidence "$EVIDENCE" \
      --snapshot "$SNAPSHOT" \
      --benchmark "$BENCHMARK" \
      --output "$CONTAINER_OUTPUT"
  cp "$CONTAINER_OUTPUT" "$OUTPUT"
else
  echo "ERROR: unsupported isolation mode: $ISOLATION_MODE" >&2
  exit 24
fi

python3 - "$OUTPUT" "$ISOLATION_MODE" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
mode = sys.argv[2]
receipt = json.loads(path.read_text(encoding='utf-8'))
if receipt.get('schema') != 'workspace.embedding-production-benchmark/v1':
    raise SystemExit('unexpected benchmark receipt schema')
if receipt.get('status') != 'production_benchmark_pass':
    raise SystemExit('production benchmark did not pass')
if receipt.get('admission', {}).get('production_approval') is not False:
    raise SystemExit('benchmark must not grant production approval')
if receipt.get('admission', {}).get('runtime_authority') is not False:
    raise SystemExit('benchmark must not grant runtime authority')
security = receipt.setdefault('security', {})
security['network_isolation_mode'] = mode
path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(f"PASS: {path}")
PY
