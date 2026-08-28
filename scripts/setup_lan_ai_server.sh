#!/usr/bin/env bash
set -Eeuo pipefail

REPO_REF="${THREE_AGENT_REPO_REF:-main}"
MODEL="${THREE_AGENT_MODEL:-qwen3:30b}"
PORT="${THREE_AGENT_WEB_PORT:-8787}"
ROOT="${THREE_AGENT_ROOT:-$HOME/3agent}"
INSTALL_URL="https://raw.githubusercontent.com/caotiensinh/3agent/${REPO_REF}/scripts/setup_ai_stack_ubuntu2404.sh"
CHAT_INSTALLER_REL="scripts/install_chat_gateway.sh"
ENV_FILE="$HOME/.config/3agent/chat.env"
SELF_TEST=0

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[3Agent-LAN][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[3Agent-LAN] %s\n' "$*"; }
warn() { printf '[3Agent-LAN][WARN] %s\n' "$*" >&2; }
die() { printf '[3Agent-LAN][ERROR] %s\n' "$*" >&2; exit 1; }

if [[ "$SELF_TEST" == "1" ]]; then
  [[ "$PORT" =~ ^[0-9]+$ ]] || die "THREE_AGENT_WEB_PORT must be numeric"
  (( PORT >= 1024 && PORT <= 65535 )) || die "THREE_AGENT_WEB_PORT must be between 1024 and 65535"
  [[ -n "$MODEL" ]] || die "THREE_AGENT_MODEL is empty"
  [[ "$INSTALL_URL" == https://raw.githubusercontent.com/caotiensinh/3agent/* ]] || die "Unexpected installer URL"
  log "LAN AI server bootstrap self-test PASS"
  exit 0
fi

[[ "${EUID}" -ne 0 ]] || die "Run this command as the normal Ubuntu desktop/server user, not root."
command -v sudo >/dev/null 2>&1 || die "sudo is required."
sudo -v

tmp="$(mktemp)"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

log "Stage 1/6: install/update the local AI stack from GitHub."
curl -fsSL --connect-timeout 15 "$INSTALL_URL" -o "$tmp"
chmod 0700 "$tmp"
THREE_AGENT_MODEL="$MODEL" \
THREE_AGENT_REPO_REF="$REPO_REF" \
bash "$tmp"

[[ -d "$ROOT/.git" ]] || die "3Agent repository was not deployed at $ROOT"
[[ -x "$ROOT/.venv/bin/three-agent-chat" ]] || die "three-agent-chat executable is missing after AI-stack setup"

log "Stage 2/6: install/update the LAN chat service."
THREE_AGENT_ROOT="$ROOT" \
THREE_AGENT_MODEL="$MODEL" \
THREE_AGENT_WEB_PORT="$PORT" \
bash "$ROOT/$CHAT_INSTALLER_REL"

[[ -f "$ENV_FILE" ]] || die "Chat environment file was not created: $ENV_FILE"
# shellcheck disable=SC1090
source "$ENV_FILE"
LAN_HOST="${THREE_AGENT_WEB_HOST:-}"
[[ -n "$LAN_HOST" ]] || die "LAN host was not written to $ENV_FILE"
[[ "$LAN_HOST" != "0.0.0.0" && "$LAN_HOST" != "::" ]] || die "LAN server must not bind a wildcard address"

log "Stage 3/6: keep the firewall scoped to the connected LAN."
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q '^Status: active'; then
  LAN_CIDR="$(
    ip -4 route show scope link 2>/dev/null \
      | awk -v host="$LAN_HOST" '$0 ~ ("src " host "($| )") && $1 ~ /\// {print $1; exit}'
  )"
  if [[ -n "$LAN_CIDR" ]]; then
    if ! sudo ufw status | grep -Fq "${PORT}/tcp"; then
      sudo ufw allow from "$LAN_CIDR" to "$LAN_HOST" port "$PORT" proto tcp
      log "UFW: allowed ${LAN_CIDR} -> ${LAN_HOST}:${PORT}/tcp"
    else
      log "UFW already has a rule for ${PORT}/tcp; existing policy was preserved."
    fi
  else
    warn "UFW is active but the connected LAN CIDR could not be determined automatically."
    warn "The service is bound only to ${LAN_HOST}, but UFW may still need a LAN-scoped allow rule."
  fi
else
  log "UFW is inactive/not installed; no firewall mutation was required."
fi

log "Stage 4/6: verify local model and service health."
curl -fsS --connect-timeout 5 http://127.0.0.1:11434/api/tags >/dev/null \
  || die "Ollama is not reachable on 127.0.0.1:11434"

systemctl --user is-active --quiet 3agent-chat.service \
  || die "3agent-chat.service is not active"

health_url="http://${LAN_HOST}:${PORT}/api/health"
for _ in {1..20}; do
  if curl -fsS --connect-timeout 2 "$health_url" | grep -Fq '"status": "ok"'; then
    break
  fi
  sleep 1
done
curl -fsS --connect-timeout 5 "$health_url" | grep -Fq '"status": "ok"' \
  || die "LAN chat health endpoint failed: $health_url"

log "Stage 5/6: verify browser-only LAN reachability."
if command -v ss >/dev/null 2>&1; then
  ss -ltn | awk -v endpoint="${LAN_HOST}:${PORT}" '$4 == endpoint {found=1} END {exit(found ? 0 : 1)}' \
    || die "Expected listener was not found at ${LAN_HOST}:${PORT}"
fi

WEB_TOKEN="$(awk -F= '$1=="THREE_AGENT_WEB_ACCESS_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
[[ ${#WEB_TOKEN} -ge 16 ]] || die "Generated web access key is invalid"

log "Stage 6/6: final smoke."
THREE_AGENT_CONFIG="$ROOT/config/local.json" "$ROOT/.venv/bin/three-agent" smoke >/dev/null

echo
echo "=========================================================="
echo "         3Agent LAN AI Server - FINAL PASS"
echo "=========================================================="
printf 'AI server:   %s\n' "$LAN_HOST"
printf 'Web UI:      http://%s:%s/\n' "$LAN_HOST" "$PORT"
printf 'Access key:  %s\n' "$WEB_TOKEN"
printf 'Model:       %s\n' "$MODEL"
printf 'Repository:  %s\n' "$ROOT"
echo
echo "Client PCs:"
echo "  - Do NOT install Python, Ollama, models or 3Agent."
echo "  - Open the Web UI above in Chrome / Edge / Firefox."
echo "  - Enter the access key when prompted."
echo
echo "Server status:"
echo "  systemctl --user status 3agent-chat.service"
echo "  journalctl --user -u 3agent-chat.service -f"
echo "=========================================================="
