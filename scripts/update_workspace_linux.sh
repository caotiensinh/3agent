#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

# WorkSpace transactional updater for an existing Ubuntu 24.04 install.
# Deliberate non-goals: NVIDIA driver/kernel, apt packages, Docker/databases,
# Ollama/model installation, GitHub Actions runner configuration.

ROOT="${THREE_AGENT_ROOT:-$HOME/3agent}"
TARGET_REF="${WORKSPACE_UPDATE_REF:-main}"
TARGET_SHA_OVERRIDE="${WORKSPACE_TARGET_SHA:-}"
EXPECTED_GPU_COUNT="${WORKSPACE_EXPECTED_GPU_COUNT:-2}"
OLLAMA_URL="${WORKSPACE_OLLAMA_URL:-http://127.0.0.1:11434}"
CHAT_ENV="${WORKSPACE_CHAT_ENV:-$HOME/.config/3agent/chat.env}"
CHAT_SERVICE="${WORKSPACE_CHAT_SERVICE:-3agent-chat.service}"
STATE_ROOT="${WORKSPACE_UPDATE_STATE_ROOT:-$HOME/.local/state/workspace}"
CACHE_ROOT="${WORKSPACE_UPDATE_CACHE_ROOT:-$HOME/.cache/workspace-update}"
DRY_RUN=0

UPDATE_STAGE="preflight"
log()  { printf '[WorkSpace-Update] %s\n' "$*"; }
pass() { printf '[WorkSpace-Update][PASS] %s\n' "$*"; }
warn() { printf '[WorkSpace-Update][WARN] %s\n' "$*" >&2; }
die()  { printf '[WorkSpace-Update][ERROR][%s] %s\n' "$UPDATE_STAGE" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  bash update_workspace_linux.sh [options]

Options:
  --root PATH          Existing WorkSpace checkout (default: $HOME/3agent)
  --ref REF            Trusted origin ref to update from (default: main)
  --target-sha SHA     Optional exact 40-hex commit, required to be on REF
  --gpu-count N        Required NVIDIA GPU count (default: 2)
  --dry-run            Resolve and validate target without mutating checkout/venv/service
  -h, --help           Show this help

Environment equivalents:
  THREE_AGENT_ROOT, WORKSPACE_UPDATE_REF, WORKSPACE_TARGET_SHA,
  WORKSPACE_EXPECTED_GPU_COUNT, WORKSPACE_OLLAMA_URL.
EOF
}

while (($#)); do
  case "$1" in
    --root) ROOT="${2:?missing PATH}"; shift 2 ;;
    --ref) TARGET_REF="${2:?missing REF}"; shift 2 ;;
    --target-sha) TARGET_SHA_OVERRIDE="${2:?missing SHA}"; shift 2 ;;
    --gpu-count) EXPECTED_GPU_COUNT="${2:?missing N}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ $EUID -ne 0 ]] || die "Run this updater as the WorkSpace owner, not root/sudo."
[[ "$EXPECTED_GPU_COUNT" =~ ^[1-9][0-9]*$ ]] || die "--gpu-count must be a positive integer."
[[ "$TARGET_REF" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Invalid target ref."
if [[ -n "$TARGET_SHA_OVERRIDE" ]]; then
  [[ "$TARGET_SHA_OVERRIDE" =~ ^[0-9a-f]{40}$ ]] || die "--target-sha must be lowercase 40-hex."
fi
[[ "$OLLAMA_URL" == "http://127.0.0.1:11434" ]] \
  || die "Updater only accepts the local Ollama boundary http://127.0.0.1:11434."

for cmd in git python3 nvidia-smi curl flock systemctl; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] \
    || die "This updater is approved for Ubuntu 24.04 only."
else
  die "/etc/os-release is required."
fi

mkdir -p "$STATE_ROOT" "$CACHE_ROOT"
chmod 700 "$STATE_ROOT" "$CACHE_ROOT"
LOCK_FILE="$CACHE_ROOT/update.lock"
exec 9>"$LOCK_FILE"
flock -n 9 || die "Another WorkSpace update is already running."

[[ -d "$ROOT/.git" ]] || die "Repository not found: $ROOT"
[[ -x "$ROOT/.venv/bin/python" ]] || die "Existing WorkSpace venv missing: $ROOT/.venv"
ROOT="$(cd "$ROOT" && pwd -P)"
cd "$ROOT"

ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
case "$ORIGIN_URL" in
  https://github.com/caotiensinh/3agent|https://github.com/caotiensinh/3agent.git) ;;
  *) die "Refusing untrusted origin: $ORIGIN_URL" ;;
esac

CURRENT_BRANCH="$(git branch --show-current)"
[[ "$CURRENT_BRANCH" == "main" ]] || die "Refusing in-place update from branch '$CURRENT_BRANCH'; expected main."
[[ -z "$(git status --porcelain --untracked-files=no)" ]] \
  || die "Tracked WorkSpace files are modified. Commit/stash them before update."
BEFORE_SHA="$(git rev-parse HEAD)"
[[ "$BEFORE_SHA" =~ ^[0-9a-f]{40}$ ]] || die "Current checkout SHA is invalid."

GPU_BEFORE="$(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader,nounits 2>/dev/null)" \
  || die "nvidia-smi failed before update."
GPU_COUNT_BEFORE="$(printf '%s\n' "$GPU_BEFORE" | sed '/^[[:space:]]*$/d' | wc -l)"
[[ "$GPU_COUNT_BEFORE" -eq "$EXPECTED_GPU_COUNT" ]] \
  || die "Expected $EXPECTED_GPU_COUNT GPUs, detected $GPU_COUNT_BEFORE before update."
pass "GPU preflight: $GPU_COUNT_BEFORE GPU(s); driver inventory readable."

curl -fsS --max-time 5 "$OLLAMA_URL/api/tags" >/dev/null \
  || die "Local Ollama is not reachable at $OLLAMA_URL."
pass "Local Ollama preflight."

RUNNERS_BEFORE="$(systemctl list-units --type=service --all 'actions.runner.*' --no-legend --no-pager 2>/dev/null || true)"
CHAT_INSTALLED=0
CHAT_WAS_ACTIVE=0
if systemctl --user cat "$CHAT_SERVICE" >/dev/null 2>&1; then
  CHAT_INSTALLED=1
  systemctl --user is-active --quiet "$CHAT_SERVICE" && CHAT_WAS_ACTIVE=1
fi

UPDATE_STAGE="target_resolution"
log "Fetching trusted origin/$TARGET_REF (application source only)."
git fetch --no-tags --prune origin "$TARGET_REF"
REMOTE_REF_SHA="$(git rev-parse FETCH_HEAD)"
[[ "$REMOTE_REF_SHA" =~ ^[0-9a-f]{40}$ ]] || die "Unable to resolve exact origin/$TARGET_REF SHA."

if [[ -n "$TARGET_SHA_OVERRIDE" ]]; then
  TARGET_SHA="$TARGET_SHA_OVERRIDE"
  if ! git cat-file -e "$TARGET_SHA^{commit}" 2>/dev/null; then
    git fetch --no-tags origin "$TARGET_SHA"
  fi
  git cat-file -e "$TARGET_SHA^{commit}" 2>/dev/null || die "Target SHA is not available."
  git merge-base --is-ancestor "$TARGET_SHA" "$REMOTE_REF_SHA" \
    || die "Target SHA is not an ancestor of trusted origin/$TARGET_REF."
else
  TARGET_SHA="$REMOTE_REF_SHA"
fi
git merge-base --is-ancestor "$BEFORE_SHA" "$TARGET_SHA" \
  || die "Refusing non-fast-forward update from $BEFORE_SHA to $TARGET_SHA."

RECEIPT="$STATE_ROOT/update-last.json"
STAGE_ROOT=""
NEXT_VENV=""
OLD_VENV=""
MUTATED=0
VENV_SWAPPED=0
COMMITTED=0
ROLLBACK_STATUS="not_required"
DEPS_CHANGED=0
PYPROJECT_CHANGED=0
VENV_REPLACEMENT_REQUIRED=0
CHAT_STOPPED_FOR_UPDATE=0
AUTH_STATE_FILE="$CACHE_ROOT/auth-state-$BEFORE_SHA.json"
AUTH_BACKUP="$CACHE_ROOT/auth-backup-$BEFORE_SHA.sqlite3"
AUTH_GUARD_STATUS="not_applicable"
AUTH_ROLLBACK_STATUS="not_required"
AUTH_GUARD_APPLICABLE=0

write_receipt() {
  local status="$1" final_sha="$2" rollback="$3" failure_stage="${4:-}"
  python3 - "$RECEIPT" "$status" "$BEFORE_SHA" "$TARGET_SHA" "$final_sha" \
    "$GPU_COUNT_BEFORE" "$DEPS_CHANGED" "$PYPROJECT_CHANGED" "$rollback" \
    "$CHAT_WAS_ACTIVE" "$failure_stage" "$AUTH_GUARD_STATUS" "$AUTH_ROLLBACK_STATUS" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
payload = {
    "schema_version": "workspace-linux-update/v4",
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "status": sys.argv[2],
    "from_sha": sys.argv[3],
    "target_sha": sys.argv[4],
    "final_sha": sys.argv[5],
    "gpu_count": int(sys.argv[6]),
    "dependencies_changed": sys.argv[7] == "1",
    "pyproject_changed": sys.argv[8] == "1",
    "rollback": sys.argv[9],
    "chat_was_active": sys.argv[10] == "1",
    "failure_stage": sys.argv[11] or None,
    "credential_guard": sys.argv[12],
    "credential_rollback": sys.argv[13],
    "system_python_mutated": False,
    "driver_or_kernel_mutated": False,
    "runner_service_mutated": False,
}
Path(sys.argv[1]).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
  chmod 600 "$RECEIPT"
}

cleanup_stage() {
  set +e
  if [[ -n "$STAGE_ROOT" && -e "$STAGE_ROOT" ]]; then
    git -C "$ROOT" worktree remove --force "$STAGE_ROOT" >/dev/null 2>&1 || rm -rf "$STAGE_ROOT"
  fi
  if [[ -n "$NEXT_VENV" && -d "$NEXT_VENV" && "$VENV_SWAPPED" == "0" ]]; then
    rm -rf "$NEXT_VENV"
  fi
}

cleanup_auth_artifacts() {
  rm -f "$AUTH_STATE_FILE" "$AUTH_BACKUP"
}

rollback() {
  local rc="$1" failed_stage="$UPDATE_STAGE" final_sha
  trap - EXIT ERR INT TERM
  set +e
  if [[ "$MUTATED" == "1" && "$COMMITTED" == "0" ]]; then
    warn "Update failed at stage '$failed_stage'; rolling back to $BEFORE_SHA."

    if [[ "$CHAT_INSTALLED" == "1" ]]; then
      systemctl --user stop "$CHAT_SERVICE" >/dev/null 2>&1 || true
    fi

    if [[ "$AUTH_GUARD_APPLICABLE" == "1" && -f "$AUTH_STATE_FILE" ]]; then
      AUTH_ROLLBACK_STATUS="failed"
      if [[ -n "$STAGE_ROOT" && -f "$STAGE_ROOT/scripts/workspace_auth_guard.py" ]] \
        && python3 "$STAGE_ROOT/scripts/workspace_auth_guard.py" restore \
          --state "$AUTH_STATE_FILE" --backup "$AUTH_BACKUP" >/dev/null; then
        AUTH_ROLLBACK_STATUS="restored"
      fi
    fi

    cd "$ROOT" || true
    git reset --hard "$BEFORE_SHA" >/dev/null 2>&1 || true
    if [[ "$VENV_SWAPPED" == "1" && -n "$OLD_VENV" && -d "$OLD_VENV" ]]; then
      rm -rf "$ROOT/.venv"
      mv "$OLD_VENV" "$ROOT/.venv" || true
      VENV_SWAPPED=0
    fi
    if [[ "$CHAT_WAS_ACTIVE" == "1" ]]; then
      systemctl --user restart "$CHAT_SERVICE" >/dev/null 2>&1 || true
    fi
    ROLLBACK_STATUS="attempted"
    final_sha="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf '%s' "$BEFORE_SHA")"
    if [[ "$final_sha" == "$BEFORE_SHA" && -x "$ROOT/.venv/bin/python" ]]; then
      if [[ "$AUTH_GUARD_APPLICABLE" == "0" || "$AUTH_ROLLBACK_STATUS" == "restored" ]]; then
        ROLLBACK_STATUS="restored"
      fi
    fi
    write_receipt "rolled_back" "$final_sha" "$ROLLBACK_STATUS" "$failed_stage" || true
    if [[ "$AUTH_ROLLBACK_STATUS" != "failed" ]]; then
      cleanup_auth_artifacts
    fi
  fi
  cleanup_stage
  exit "$rc"
}
trap 'rollback $?' EXIT
trap 'exit 130' INT TERM

if [[ "$TARGET_SHA" == "$BEFORE_SHA" ]]; then
  UPDATE_STAGE="already_current_validation"
  PYTHONPATH="$ROOT/src" "$ROOT/.venv/bin/python" -c 'import three_agent' \
    || die "Existing WorkSpace import check failed."
  write_receipt "already_current" "$BEFORE_SHA" "not_required" ""
  COMMITTED=1
  printf '\nWorkSpace ALREADY CURRENT\nSHA: %s\nGPU count: %s\nReceipt: %s\n' \
    "$BEFORE_SHA" "$GPU_COUNT_BEFORE" "$RECEIPT"
  exit 0
fi

UPDATE_STAGE="staged_source"
STAGE_ROOT="$(mktemp -d "$CACHE_ROOT/source.XXXXXX")"
rmdir "$STAGE_ROOT"
git worktree add --detach "$STAGE_ROOT" "$TARGET_SHA" >/dev/null
[[ -f "$STAGE_ROOT/scripts/workspace_auth_guard.py" ]] \
  || die "Target source is missing the credential transaction guard."
python3 -m py_compile "$STAGE_ROOT/scripts/workspace_auth_guard.py" \
  || die "Credential transaction guard failed syntax validation."

dependency_contract_sha() {
  local ref="$1"
  git show "$ref:pyproject.toml" | python3 -c '
import hashlib, json, sys, tomllib
d = tomllib.loads(sys.stdin.read())
p = d.get("project", {})
b = d.get("build-system", {})
contract = {
    "requires-python": p.get("requires-python"),
    "dependencies": p.get("dependencies", []),
    "build_requires": b.get("requires", []),
    "build_backend": b.get("build-backend"),
}
blob = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(blob).hexdigest())
'
}

UPDATE_STAGE="dependency_contract"
CURRENT_DEP_SHA="$(dependency_contract_sha "$BEFORE_SHA")"
TARGET_DEP_SHA="$(dependency_contract_sha "$TARGET_SHA")"
[[ "$CURRENT_DEP_SHA" == "$TARGET_DEP_SHA" ]] || DEPS_CHANGED=1
CURRENT_PYPROJECT_SHA="$(git show "$BEFORE_SHA:pyproject.toml" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
TARGET_PYPROJECT_SHA="$(git show "$TARGET_SHA:pyproject.toml" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
[[ "$CURRENT_PYPROJECT_SHA" == "$TARGET_PYPROJECT_SHA" ]] || PYPROJECT_CHANGED=1

if [[ "$DEPS_CHANGED" == "1" ]]; then
  UPDATE_STAGE="staged_dependency_install"
  VENV_REPLACEMENT_REQUIRED=1
  log "Dependency contract changed: preparing isolated replacement venv before checkout mutation."
  NEXT_VENV="$ROOT/.venv.next-$TARGET_SHA"
  rm -rf "$NEXT_VENV"
  python3 -m venv "$NEXT_VENV" \
    || die "Unable to create staged venv; python3-venv must already be installed."
  PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
    "$NEXT_VENV/bin/python" -m pip install "$STAGE_ROOT" \
    || die "Target dependency installation failed in staged venv."
  PYTHONPATH="$STAGE_ROOT/src" "$NEXT_VENV/bin/python" -c \
    'import three_agent; import three_agent.chat_gateway_v17' \
    || die "Target source failed staged import validation."
elif [[ "$PYPROJECT_CHANGED" == "1" ]]; then
  UPDATE_STAGE="staged_binding_clone"
  VENV_REPLACEMENT_REQUIRED=1
  log "Dependency contract unchanged but package metadata changed: cloning existing .venv without dependency resolution."
  NEXT_VENV="$ROOT/.venv.next-$TARGET_SHA"
  rm -rf "$NEXT_VENV"
  cp -a --reflink=auto "$ROOT/.venv" "$NEXT_VENV" \
    || die "Unable to stage rollback-safe venv clone."
  PYTHONPATH="$STAGE_ROOT/src" "$NEXT_VENV/bin/python" -c \
    'import three_agent; import three_agent.chat_gateway_v17' \
    || die "Target source failed staged import validation with cloned venv."
else
  UPDATE_STAGE="staged_import_existing_venv"
  log "Dependency and package contracts unchanged: reusing existing .venv with zero install/copy."
  PYTHONPATH="$STAGE_ROOT/src" "$ROOT/.venv/bin/python" -c \
    'import three_agent; import three_agent.chat_gateway_v17' \
    || die "Target source failed staged import validation with the existing venv."
fi
pass "Target SHA staged validation: $TARGET_SHA"

if [[ "$DRY_RUN" == "1" ]]; then
  write_receipt "dry_run_pass" "$BEFORE_SHA" "not_required" ""
  COMMITTED=1
  log "DRY-RUN PASS: no checkout, venv, service, credential, driver, kernel or runner mutation performed."
  exit 0
fi

# Quiesce chat before touching its source or SQLite auth state. This creates a
# deterministic update boundary and prevents bootstrap/login writes mid-transaction.
UPDATE_STAGE="auth_guard_quiesce"
MUTATED=1
if [[ "$CHAT_WAS_ACTIVE" == "1" ]]; then
  log "Temporarily stopping the previously-active WorkSpace chat service for an atomic update."
  systemctl --user stop "$CHAT_SERVICE"
  CHAT_STOPPED_FOR_UPDATE=1
  systemctl --user is-active --quiet "$CHAT_SERVICE" \
    && die "$CHAT_SERVICE remained active after stop request."
fi

UPDATE_STAGE="auth_guard_snapshot"
rm -f "$AUTH_STATE_FILE" "$AUTH_BACKUP"
python3 "$STAGE_ROOT/scripts/workspace_auth_guard.py" snapshot \
  --root "$ROOT" --env "$CHAT_ENV" --backup "$AUTH_BACKUP" --state "$AUTH_STATE_FILE" \
  || die "Unable to snapshot local credential state."
AUTH_GUARD_APPLICABLE="$(python3 - "$AUTH_STATE_FILE" <<'PY'
import json,sys
p=json.load(open(sys.argv[1], encoding='utf-8'))
print('1' if p.get('applicable') else '0')
PY
)"
if [[ "$AUTH_GUARD_APPLICABLE" == "1" ]]; then
  AUTH_GUARD_STATUS="snapshot_verified"
  [[ -f "$AUTH_BACKUP" ]] || die "Credential guard marked applicable without a SQLite backup."
  pass "Local credential state snapshotted without exposing password material."
elif [[ "$CHAT_WAS_ACTIVE" == "1" ]]; then
  die "Active WorkSpace chat has no verifiable credential database; refusing update fail-closed."
else
  AUTH_GUARD_STATUS="not_applicable"
  log "Credential guard not applicable because no active auth database was found."
fi

UPDATE_STAGE="source_fast_forward"
git merge --ff-only "$TARGET_SHA" >/dev/null
[[ "$(git rev-parse HEAD)" == "$TARGET_SHA" ]] || die "Exact target checkout verification failed."

if [[ "$VENV_REPLACEMENT_REQUIRED" == "1" ]]; then
  UPDATE_STAGE="venv_swap"
  OLD_VENV="$ROOT/.venv.rollback-$BEFORE_SHA"
  rm -rf "$OLD_VENV"
  mv "$ROOT/.venv" "$OLD_VENV"
  mv "$NEXT_VENV" "$ROOT/.venv"
  NEXT_VENV=""
  VENV_SWAPPED=1

  UPDATE_STAGE="venv_rebind_after_swap"
  PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
    "$ROOT/.venv/bin/python" -m pip install --no-deps --force-reinstall -e "$ROOT" \
    || die "Unable to rebind replacement venv to committed checkout."
fi

UPDATE_STAGE="entrypoint_validation"
THREE_AGENT_ROOT="$ROOT" PYTHONPATH="$ROOT/src" \
  "$ROOT/.venv/bin/python" "$ROOT/scripts/validate_workspace_runtime.py" \
  || die "WorkSpace runtime or Security Analyst entrypoint validation failed after update."
pass "Runtime entrypoints: workspace-chat and Security Analyst commands are correctly bound."

UPDATE_STAGE="post_update_import"
PYTHONPATH="$ROOT/src" "$ROOT/.venv/bin/python" -c \
  'import three_agent; import three_agent.chat_gateway_v18; import three_agent.security_monitoring_cli; import three_agent.security_reporting_cli; import three_agent.security_pcap_runner' \
  || die "Post-update WorkSpace/Security runtime import validation failed."

if [[ "$CHAT_INSTALLED" == "1" && "$CHAT_WAS_ACTIVE" == "1" ]]; then
  UPDATE_STAGE="service_restart"
  log "Restarting the previously-active WorkSpace chat service only: $CHAT_SERVICE"
  systemctl --user restart "$CHAT_SERVICE"
  CHAT_STOPPED_FOR_UPDATE=0
  sleep 2
  systemctl --user is-active --quiet "$CHAT_SERVICE" \
    || die "$CHAT_SERVICE did not become active after update."
elif [[ "$CHAT_INSTALLED" == "1" ]]; then
  log "Chat service exists but was inactive; preserving inactive state."
else
  log "Chat service is not installed; preserving service topology."
fi

UPDATE_STAGE="credential_invariant_postflight"
if [[ "$AUTH_GUARD_APPLICABLE" == "1" ]]; then
  python3 "$ROOT/scripts/workspace_auth_guard.py" verify \
    --root "$ROOT" --env "$CHAT_ENV" --state "$AUTH_STATE_FILE" >/dev/null \
    || die "WorkSpace admin credential state changed during application update."
  AUTH_GUARD_STATUS="verified"
  pass "Credential invariant: unchanged."
fi

UPDATE_STAGE="gpu_postflight"
GPU_AFTER="$(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader,nounits 2>/dev/null)" \
  || die "nvidia-smi failed after update."
[[ "$GPU_AFTER" == "$GPU_BEFORE" ]] \
  || die "GPU name/driver inventory changed during an application-only update."

UPDATE_STAGE="ollama_postflight"
curl -fsS --max-time 5 "$OLLAMA_URL/api/tags" >/dev/null \
  || die "Local Ollama became unreachable after update."

UPDATE_STAGE="runner_postflight"
RUNNERS_AFTER="$(systemctl list-units --type=service --all 'actions.runner.*' --no-legend --no-pager 2>/dev/null || true)"
[[ "$RUNNERS_AFTER" == "$RUNNERS_BEFORE" ]] \
  || die "GitHub runner service inventory changed during update; refusing to commit transaction."

HOST=""
PORT="8787"
if [[ -f "$CHAT_ENV" ]]; then
  HOST="$(awk -F= '$1=="THREE_AGENT_WEB_HOST" {sub(/^[^=]*=/, ""); print; exit}' "$CHAT_ENV")"
  configured_port="$(awk -F= '$1=="THREE_AGENT_WEB_PORT" {sub(/^[^=]*=/, ""); print; exit}' "$CHAT_ENV")"
  [[ -n "$configured_port" ]] && PORT="$configured_port"
fi
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || die "Invalid chat port in $CHAT_ENV."

if [[ "$CHAT_WAS_ACTIVE" == "1" ]]; then
  UPDATE_STAGE="health_postflight"
  case "$HOST" in
    ""|0.0.0.0|::|"[::]") HEALTH_HOST="127.0.0.1" ;;
    127.0.0.1|localhost) HEALTH_HOST="$HOST" ;;
    *) HEALTH_HOST="$HOST" ;;
  esac
  health="$(curl -fsS --max-time 8 "http://$HEALTH_HOST:$PORT/api/health")" \
    || die "WorkSpace health endpoint did not respond after update."
  printf '%s' "$health" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' \
    || die "WorkSpace health response did not report status=ok."
fi

UPDATE_STAGE="lineage_postflight"
AFTER_SHA="$(git rev-parse HEAD)"
[[ "$AFTER_SHA" == "$TARGET_SHA" ]] || die "Final source lineage mismatch."
write_receipt "updated" "$AFTER_SHA" "not_required" ""
COMMITTED=1

if [[ "$VENV_SWAPPED" == "1" && -n "$OLD_VENV" ]]; then
  rm -rf "$OLD_VENV"
  OLD_VENV=""
fi
cleanup_auth_artifacts
cleanup_stage
trap - EXIT INT TERM

echo
echo "=========================================="
echo "         WorkSpace UPDATE COMPLETE"
echo "=========================================="
printf 'Before SHA:   %s\n' "$BEFORE_SHA"
printf 'After SHA:    %s\n' "$AFTER_SHA"
printf 'GPU count:    %s\n' "$GPU_COUNT_BEFORE"
printf 'Deps changed: %s\n' "$([[ "$DEPS_CHANGED" == "1" ]] && echo yes || echo no)"
printf 'Pyproject:    %s\n' "$([[ "$PYPROJECT_CHANGED" == "1" ]] && echo changed || echo unchanged)"
printf 'Credential:   %s\n' "$AUTH_GUARD_STATUS"
printf 'Chat state:   %s\n' "$(systemctl --user is-active "$CHAT_SERVICE" 2>/dev/null || echo not-installed)"
printf 'Receipt:      %s\n' "$RECEIPT"
printf '%s\n' "NVIDIA driver/kernel and GitHub runner services were not modified."
echo "=========================================="
