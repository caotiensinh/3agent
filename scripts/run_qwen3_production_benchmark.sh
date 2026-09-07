#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROBE_ONLY=false
if [[ "${1:-}" == "--probe-isolation" ]]; then
  PROBE_ONLY=true
  shift
fi

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

rootless_docker_host() {
  local candidate="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/docker.sock"
  if [[ -S "$candidate" ]]; then
    printf 'unix://%s\n' "$candidate"
    return 0
  fi
  return 1
}

docker_group_member() {
  command -v getent >/dev/null || return 1
  local entry user docker_gid members
  entry="$(getent group docker 2>/dev/null || true)"
  [[ -n "$entry" ]] || return 1
  user="$(id -un)"
  IFS=: read -r _ _ docker_gid members <<< "$entry"
  if [[ "$(id -g)" == "$docker_gid" ]]; then
    return 0
  fi
  [[ ",${members}," == *",${user},"* ]]
}

docker_access_mode() {
  command -v docker >/dev/null || return 1
  if docker info >/dev/null 2>&1; then
    echo direct
    return 0
  fi
  local rootless_host
  rootless_host="$(rootless_docker_host || true)"
  if [[ -n "$rootless_host" ]] && DOCKER_HOST="$rootless_host" docker info >/dev/null 2>&1; then
    echo rootless
    return 0
  fi
  if command -v sg >/dev/null && docker_group_member && sg docker -c 'docker info >/dev/null 2>&1'; then
    echo group
    return 0
  fi
  return 1
}

run_docker() {
  local mode="${DOCKER_ACCESS_MODE:-}"
  if [[ -z "$mode" ]]; then
    mode="$(docker_access_mode || true)"
  fi
  case "$mode" in
    direct)
      docker "$@"
      ;;
    rootless)
      local rootless_host
      rootless_host="$(rootless_docker_host)"
      DOCKER_HOST="$rootless_host" docker "$@"
      ;;
    group)
      local quoted
      printf -v quoted '%q ' docker "$@"
      sg docker -c "$quoted"
      ;;
    *)
      echo "ERROR: Docker daemon access is unavailable" >&2
      return 1
      ;;
  esac
}

cleanup() {
  if [[ -n "$DOCKER_IMAGE" ]] && command -v docker >/dev/null; then
    run_docker image rm -f "$DOCKER_IMAGE" >/dev/null 2>&1 || true
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
  run_docker import "$tarball" "$image" >/dev/null
}

docker_base_mounts() {
  printf '%s\n' "--mount" "type=bind,src=/usr,dst=/usr,readonly" "--mount" "type=bind,src=/lib,dst=/lib,readonly"
  if [[ -d /lib64 ]]; then
    printf '%s\n' "--mount" "type=bind,src=/lib64,dst=/lib64,readonly"
  fi
}

probe_docker_isolation() {
  local access_mode
  access_mode="$(docker_access_mode || true)"
  [[ -n "$access_mode" ]] || return 1
  DOCKER_ACCESS_MODE="$access_mode"
  export DOCKER_ACCESS_MODE
  local image="workspace-qwen3-netprobe:${GITHUB_RUN_ID:-$$}"
  local probe="import socket; names={n for _,n in socket.if_nameindex()}; assert names <= {'lo'}, names; s=socket.socket(); s.settimeout(0.5); rc=s.connect_ex(('1.1.1.1',443)); s.close(); assert rc != 0, rc; print('network isolation verified', sorted(names))"
  local -a mounts=()
  while IFS= read -r item; do mounts+=("$item"); done < <(docker_base_mounts)
  make_empty_docker_image "$image"
  if ! run_docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
      "${mounts[@]}" --entrypoint /usr/bin/python3 "$image" -c "$probe" >/dev/null; then
    run_docker image rm -f "$image" >/dev/null 2>&1 || true
    return 1
  fi
  if ! run_docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
      --gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,utility \
      "${mounts[@]}" --entrypoint /usr/bin/nvidia-smi "$image" \
      --query-gpu=index,name --format=csv,noheader >/dev/null; then
    run_docker image rm -f "$image" >/dev/null 2>&1 || true
    return 1
  fi
  run_docker image rm -f "$image" >/dev/null 2>&1 || true
  return 0
}

probe_systemd_user_isolation() {
  command -v systemd-run >/dev/null || return 1
  local probe="import socket; names={n for _,n in socket.if_nameindex()}; assert names <= {'lo'}, names; s=socket.socket(); s.settimeout(0.5); rc=s.connect_ex(('1.1.1.1',443)); s.close(); assert rc != 0, rc"
  systemd-run --user --quiet --pipe --wait --collect -p PrivateNetwork=yes \
    /usr/bin/python3 -c "$probe" >/dev/null 2>&1
}

print_isolation_diagnostics() {
  echo '=== Runner identity ==='
  id || true
  echo '=== Docker socket/group evidence ==='
  getent group docker 2>/dev/null || echo 'docker-group=missing'
  if [[ -e /var/run/docker.sock ]]; then
    stat -Lc 'docker-socket owner=%U group=%G mode=%a path=%n' /var/run/docker.sock 2>/dev/null || ls -l /var/run/docker.sock || true
  else
    echo 'docker-socket=missing'
  fi
  if command -v docker >/dev/null; then
    echo 'docker-cli=yes'
    docker info --format 'docker-direct-server={{.ServerVersion}}' 2>&1 || true
    local rootless_host
    rootless_host="$(rootless_docker_host || true)"
    if [[ -n "$rootless_host" ]]; then
      DOCKER_HOST="$rootless_host" docker info --format 'docker-rootless-server={{.ServerVersion}}' 2>&1 || true
    else
      echo 'docker-rootless-socket=missing'
    fi
    if command -v sg >/dev/null && docker_group_member; then
      sg docker -c "docker info --format 'docker-group-server={{.ServerVersion}}'" 2>&1 || true
    else
      echo 'docker-sg-eligible=no'
    fi
    echo "DOCKER_ACCESS_MODE=$(docker_access_mode || echo unavailable)"
  else
    echo 'docker-cli=no'
  fi
  if command -v systemd-run >/dev/null; then
    echo 'systemd-run=yes'
  else
    echo 'systemd-run=no'
  fi
}

select_isolation() {
  local probe="import socket; names={n for _,n in socket.if_nameindex()}; assert names <= {'lo'}, names; s=socket.socket(); s.settimeout(0.5); rc=s.connect_ex(('1.1.1.1',443)); s.close(); assert rc != 0, rc; print('network isolation verified', sorted(names))"
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
  if probe_systemd_user_isolation; then
    echo systemd-user-net
    return 0
  fi
  if probe_docker_isolation; then
    echo docker-none
    return 0
  fi
  return 1
}

print_isolation_diagnostics
ISOLATION_MODE="$(select_isolation || true)"
if [[ -z "$ISOLATION_MODE" ]]; then
  echo "ERROR: no verified OS-level network isolation path is available" >&2
  exit 23
fi
echo "NETWORK_ISOLATION_MODE=$ISOLATION_MODE"
if [[ "$ISOLATION_MODE" == "docker-none" ]]; then
  DOCKER_ACCESS_MODE="$(docker_access_mode)"
  export DOCKER_ACCESS_MODE
  echo "DOCKER_ACCESS_MODE=$DOCKER_ACCESS_MODE"
fi

if [[ "$PROBE_ONLY" == true ]]; then
  exit 0
fi

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
export NETWORK_ISOLATION_MODE="$ISOLATION_MODE"
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
elif [[ "$ISOLATION_MODE" == "systemd-user-net" ]]; then
  systemd-run --user --quiet --pipe --wait --collect -p PrivateNetwork=yes \
    --setenv=HF_HUB_OFFLINE=1 \
    --setenv=TRANSFORMERS_OFFLINE=1 \
    --setenv=HF_HUB_DISABLE_TELEMETRY=1 \
    --setenv=PYTHONDONTWRITEBYTECODE=1 \
    --setenv=NETWORK_ISOLATION_MODE=systemd-user-net \
    --setenv="HF_HOME=$HF_HOME" \
    --setenv="SENTENCE_TRANSFORMERS_HOME=$SENTENCE_TRANSFORMERS_HOME" \
    "$PYTHON_BIN" "${COMMON_ARGS[@]}"
elif [[ "$ISOLATION_MODE" == "docker-none" ]]; then
  DOCKER_ACCESS_MODE="${DOCKER_ACCESS_MODE:-$(docker_access_mode)}"
  export DOCKER_ACCESS_MODE
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
  run_docker run --rm \
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

python3 - "$OUTPUT" "$ISOLATION_MODE" "${DOCKER_ACCESS_MODE:-}" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
mode = sys.argv[2]
docker_access = sys.argv[3] or None
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
if docker_access is not None:
    security['docker_access_mode'] = docker_access
path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(f"PASS: {path}")
PY
