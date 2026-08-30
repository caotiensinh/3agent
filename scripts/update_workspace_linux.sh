#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${THREE_AGENT_ROOT:-$HOME/3agent}"
TARGET_REF="${WORKSPACE_UPDATE_REF:-main}"
EXPECTED_GPU_COUNT="${WORKSPACE_EXPECTED_GPU_COUNT:-0}"
CHAT_ENV="${WORKSPACE_CHAT_ENV:-$HOME/.config/3agent/chat.env}"
CHAT_SERVICE="${WORKSPACE_CHAT_SERVICE:-3agent-chat.service}"

log() { printf '[WorkSpace-Update] %s\n' "$*"; }
fail() { printf '[WorkSpace-Update][ERROR] %s\n' "$*" >&2; exit 1; }

[[ -d "$ROOT/.git" ]] || fail "Repository not found: $ROOT"
[[ -x "$ROOT/.venv/bin/python" ]] || fail "Python environment missing: $ROOT/.venv"
command -v git >/dev/null 2>&1 || fail "git is required"

cd "$ROOT"
BEFORE_SHA="$(git rev-parse HEAD)"
CURRENT_BRANCH="$(git branch --show-current)"
[[ "$CURRENT_BRANCH" == "main" ]] || fail "Refusing in-place update from branch '$CURRENT_BRANCH'; checkout main first"

GPU_BEFORE=""
if command -v nvidia-smi >/dev/null 2>&1; then
  GPU_BEFORE="$(nvidia-smi --query-gpu=name,uuid --format=csv,noheader 2>/dev/null || true)"
  if [[ "$EXPECTED_GPU_COUNT" =~ ^[0-9]+$ ]] && (( EXPECTED_GPU_COUNT > 0 )); then
    gpu_count="$(printf '%s\n' "$GPU_BEFORE" | sed '/^[[:space:]]*$/d' | wc -l)"
    [[ "$gpu_count" -eq "$EXPECTED_GPU_COUNT" ]] \
      || fail "Expected $EXPECTED_GPU_COUNT GPUs before update, detected $gpu_count"
  fi
fi

RUNNERS_BEFORE="$(systemctl list-units --type=service --all 'actions.runner.*' --no-legend --no-pager 2>/dev/null || true)"

log "Fetching origin/$TARGET_REF without touching system packages, kernel, driver or runner services"
git fetch --prune origin "$TARGET_REF"
[[ "$(git rev-parse "origin/$TARGET_REF")" != "" ]] || fail "Unable to resolve origin/$TARGET_REF"
git merge --ff-only "origin/$TARGET_REF"
AFTER_SHA="$(git rev-parse HEAD)"

log "Refreshing WorkSpace editable package in the existing virtual environment"
"$ROOT/.venv/bin/python" -m pip install -e .

[[ -x "$ROOT/.venv/bin/workspace-chat" ]] || fail "workspace-chat entrypoint is missing after update"

if systemctl --user cat "$CHAT_SERVICE" >/dev/null 2>&1; then
  log "Restarting WorkSpace chat service only: $CHAT_SERVICE"
  systemctl --user restart "$CHAT_SERVICE"
  sleep 2
  systemctl --user is-active --quiet "$CHAT_SERVICE" || {
    systemctl --user status "$CHAT_SERVICE" --no-pager || true
    journalctl --user -u "$CHAT_SERVICE" -n 80 --no-pager || true
    fail "$CHAT_SERVICE did not become active"
  }
else
  log "Chat service $CHAT_SERVICE is not installed; package update completed without creating a service"
fi

GPU_AFTER=""
if command -v nvidia-smi >/dev/null 2>&1; then
  GPU_AFTER="$(nvidia-smi --query-gpu=name,uuid --format=csv,noheader 2>/dev/null || true)"
  if [[ -n "$GPU_BEFORE" && "$GPU_AFTER" != "$GPU_BEFORE" ]]; then
    fail "GPU inventory changed during an application-only update"
  fi
fi

RUNNERS_AFTER="$(systemctl list-units --type=service --all 'actions.runner.*' --no-legend --no-pager 2>/dev/null || true)"
if [[ "$RUNNERS_AFTER" != "$RUNNERS_BEFORE" ]]; then
  printf '%s\n' "[WorkSpace-Update][WARN] GitHub runner service listing changed. The updater did not mutate runner services; inspect systemctl before continuing." >&2
fi

HOST=""
PORT="8787"
if [[ -f "$CHAT_ENV" ]]; then
  HOST="$(awk -F= '$1=="THREE_AGENT_WEB_HOST" {sub(/^[^=]*=/, ""); print; exit}' "$CHAT_ENV")"
  configured_port="$(awk -F= '$1=="THREE_AGENT_WEB_PORT" {sub(/^[^=]*=/, ""); print; exit}' "$CHAT_ENV")"
  [[ -n "$configured_port" ]] && PORT="$configured_port"
fi

if [[ -n "$HOST" ]] && command -v curl >/dev/null 2>&1 && systemctl --user is-active --quiet "$CHAT_SERVICE" 2>/dev/null; then
  log "Checking WorkSpace health at http://$HOST:$PORT/api/health"
  health="$(curl -fsS --max-time 8 "http://$HOST:$PORT/api/health")" \
    || fail "WorkSpace health endpoint did not respond"
  printf '%s' "$health" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' \
    || fail "WorkSpace health response did not report status=ok"
fi

echo
echo "=========================================="
echo "         WorkSpace UPDATE COMPLETE"
echo "=========================================="
printf 'Before SHA: %s\n' "$BEFORE_SHA"
printf 'After SHA:  %s\n' "$AFTER_SHA"
printf 'Branch:     %s\n' "$CURRENT_BRANCH"
printf 'Chat:       %s\n' "$(systemctl --user is-active "$CHAT_SERVICE" 2>/dev/null || echo not-installed)"
if [[ -n "$GPU_AFTER" ]]; then
  printf 'GPU inventory preserved:\n%s\n' "$GPU_AFTER"
fi
printf '%s\n' "GitHub runner services were not restarted or modified by this script."
echo "=========================================="
