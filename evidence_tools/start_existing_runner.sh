#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/caotiensinh/3agent"
MODEL="qwen3:30b"

fail() {
  printf '[FAIL] %s\n' "$1" >&2
  exit "${2:-3}"
}

printf '%s\n' '=== WorkSpace RTX5090 evidence runner preflight ==='

[[ "$(uname -s)" == "Linux" ]] || fail 'Linux is required.'
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) fail 'x86_64 is required.' ;;
esac

command -v python3 >/dev/null 2>&1 || fail 'python3 is required.'
command -v nvidia-smi >/dev/null 2>&1 || fail 'nvidia-smi is required.'
command -v ollama >/dev/null 2>&1 || fail 'ollama is required.'

mapfile -t GPU_ROWS < <(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader,nounits 2>/dev/null)
RTX_COUNT=0
DRIVER=""
for row in "${GPU_ROWS[@]}"; do
  name="${row%%,*}"
  driver="${row#*,}"
  name="$(printf '%s' "$name" | xargs)"
  driver="$(printf '%s' "$driver" | xargs)"
  if [[ "$name" == *"RTX 5090"* ]]; then
    RTX_COUNT=$((RTX_COUNT + 1))
    if [[ -z "$DRIVER" ]]; then
      DRIVER="$driver"
    elif [[ "$DRIVER" != "$driver" ]]; then
      fail 'RTX5090 GPUs do not use one uniform driver version.'
    fi
  fi
done
(( RTX_COUNT >= 2 )) || fail "At least two RTX 5090 GPUs are required; found $RTX_COUNT."
printf '[PASS] RTX5090 count=%d, uniform driver=%s\n' "$RTX_COUNT" "$DRIVER"

ollama --version >/dev/null 2>&1 || fail 'Ollama is not healthy.'
ollama show "$MODEL" >/dev/null 2>&1 || fail "Required local model is not preinstalled: $MODEL"
printf '[PASS] Ollama and preinstalled model %s are available.\n' "$MODEL"

# Prefer an already-installed systemd service. Do not install or register a new runner.
MATCHING_UNITS=()
if command -v systemctl >/dev/null 2>&1; then
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    case "$unit" in
      actions.runner.*3agent*.service) MATCHING_UNITS+=("$unit") ;;
    esac
  done < <(systemctl list-unit-files --type=service --no-legend 'actions.runner.*.service' 2>/dev/null | awk '{print $1}')
fi

if (( ${#MATCHING_UNITS[@]} > 1 )); then
  fail 'Multiple 3agent Actions runner services were found; refusing ambiguous start.'
fi

if (( ${#MATCHING_UNITS[@]} == 1 )); then
  unit="${MATCHING_UNITS[0]}"
  if systemctl is-active --quiet "$unit"; then
    printf '[PASS] Existing GitHub Actions runner service is already active.\n'
    exit 0
  fi
  printf '[INFO] Starting existing runner service: %s\n' "$unit"
  if [[ "$(id -u)" -eq 0 ]]; then
    systemctl start "$unit"
  else
    sudo systemctl start "$unit"
  fi
  systemctl is-active --quiet "$unit" || fail 'Runner service did not become active.'
  printf '[PASS] Existing GitHub Actions runner service is active.\n'
  exit 0
fi

# If the runner was configured without a service, locate only a registration that
# is already bound to this repository. Never print .runner contents or tokens.
RUNNER_DIR=""
SEARCH_ROOTS=("$HOME")
[[ -d /opt ]] && SEARCH_ROOTS+=(/opt)
[[ -d /srv ]] && SEARCH_ROOTS+=(/srv)
while IFS= read -r runner_file; do
  [[ -f "$runner_file" ]] || continue
  if python3 - "$runner_file" "$REPO_URL" <<'PY' >/dev/null 2>&1
import json, sys
path, expected = sys.argv[1:]
try:
    data = json.load(open(path, encoding='utf-8'))
except Exception:
    raise SystemExit(1)
values = [str(data.get(k, '')).rstrip('/') for k in ('gitHubUrl', 'serverUrl')]
raise SystemExit(0 if expected.rstrip('/') in values else 1)
PY
  then
    dir="$(dirname "$runner_file")"
    if [[ -n "$RUNNER_DIR" && "$RUNNER_DIR" != "$dir" ]]; then
      fail 'Multiple repository-bound runner directories were found; refusing ambiguous start.'
    fi
    RUNNER_DIR="$dir"
  fi
done < <(find "${SEARCH_ROOTS[@]}" -maxdepth 5 -type f -name .runner 2>/dev/null || true)

if [[ -z "$RUNNER_DIR" ]]; then
  cat >&2 <<'EOF'
[BLOCKED] No existing GitHub Actions runner registration for caotiensinh/3agent was found.
This script intentionally does not create a runner registration or obtain a registration token.
Register this dual-RTX5090 machine once from the repository Actions > Runners settings,
then run this script again. The queued WorkSpace closure job will be picked up automatically.
EOF
  exit 4
fi

[[ -x "$RUNNER_DIR/run.sh" ]] || fail 'Registered runner directory exists but run.sh is missing or not executable.'
if pgrep -f "$RUNNER_DIR/bin/Runner.Listener" >/dev/null 2>&1; then
  printf '[PASS] Existing repository-bound runner process is already active.\n'
  exit 0
fi

printf '[INFO] Starting existing repository-bound runner process from %s\n' "$RUNNER_DIR"
mkdir -p "$RUNNER_DIR/_diag"
nohup "$RUNNER_DIR/run.sh" >"$RUNNER_DIR/_diag/workspace-evidence-runner.log" 2>&1 < /dev/null &
runner_pid=$!
for _ in $(seq 1 15); do
  if kill -0 "$runner_pid" 2>/dev/null; then
    sleep 1
    continue
  fi
  fail 'Runner process exited before becoming available.'
done
printf '[PASS] Existing GitHub Actions runner process is running (pid=%d).\n' "$runner_pid"
printf '[INFO] The queued exact-SHA WorkSpace evidence job can now be assigned by GitHub Actions.\n'
