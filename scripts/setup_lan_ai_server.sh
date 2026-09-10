#!/usr/bin/env bash
set -Eeuo pipefail

REPO_REF="${THREE_AGENT_REPO_REF:-main}"
MODEL_OVERRIDE="${THREE_AGENT_MODEL:-}"
FAST_MODEL_OVERRIDE="${THREE_AGENT_FAST_MODEL:-}"
PORT="${THREE_AGENT_WEB_PORT:-8787}"
HOST_OVERRIDE="${THREE_AGENT_WEB_HOST:-}"
ROOT="${THREE_AGENT_ROOT:-$HOME/3agent}"
DEPLOY_URL="https://raw.githubusercontent.com/caotiensinh/3agent/${REPO_REF}/scripts/deploy_ubuntu_pc.sh"
ENV_FILE="$HOME/.config/3agent/chat.env"
SELF_TEST=0
TMP_DEPLOY=""

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[3Agent-LAN][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[3Agent-LAN] %s\n' "$*"; }
warn() { printf '[3Agent-LAN][WARN] %s\n' "$*" >&2; }
die() { printf '[3Agent-LAN][ERROR] %s\n' "$*" >&2; exit 1; }
cleanup() {
  if [[ -n "$TMP_DEPLOY" && -f "$TMP_DEPLOY" ]]; then
    rm -f -- "$TMP_DEPLOY"
  fi
}
trap cleanup EXIT

validate_inputs() {
  [[ "$PORT" =~ ^[0-9]+$ ]] || die "THREE_AGENT_WEB_PORT must be numeric"
  (( PORT >= 1024 && PORT <= 65535 )) || die "THREE_AGENT_WEB_PORT must be between 1024 and 65535"
  [[ -n "$REPO_REF" ]] || die "THREE_AGENT_REPO_REF is empty"
  [[ -n "$ROOT" ]] || die "THREE_AGENT_ROOT is empty"
  [[ "$DEPLOY_URL" == https://raw.githubusercontent.com/caotiensinh/3agent/* ]] || die "Unexpected deployment URL"
  if [[ -n "$HOST_OVERRIDE" ]]; then
    python3 - "$HOST_OVERRIDE" <<'PY'
import ipaddress
import sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or not address.is_private or address.is_loopback:
    raise SystemExit("THREE_AGENT_WEB_HOST must be a private non-loopback IPv4 address")
PY
  fi
}

validate_inputs
if [[ "$SELF_TEST" == "1" ]]; then
  log "LAN AI server bootstrap self-test PASS"
  exit 0
fi

[[ "${EUID}" -ne 0 ]] || die "Run this command as the normal Ubuntu desktop/server user, not root."
command -v sudo >/dev/null 2>&1 || die "sudo is required"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
sudo -v

log "Stage 1/6: deploy the tested portable Ubuntu runtime into ${ROOT}."
TMP_DEPLOY="$(mktemp)"
curl -fsSL --retry 3 --connect-timeout 15 "$DEPLOY_URL" -o "$TMP_DEPLOY"
bash -n "$TMP_DEPLOY" || die "Downloaded Ubuntu deploy entrypoint failed syntax validation"
THREE_AGENT_REPO_REF="$REPO_REF" \
THREE_AGENT_INSTALL_DIR="$ROOT" \
THREE_AGENT_INSTALL_OLLAMA=1 \
THREE_AGENT_PULL_MODEL=0 \
bash "$TMP_DEPLOY"

[[ -d "$ROOT/.git" ]] || die "WorkSpace repository was not deployed at $ROOT"
[[ -x "$ROOT/.venv/bin/three-agent-chat" ]] || die "three-agent-chat executable is missing after portable deployment"
[[ -x "$ROOT/.venv/bin/three-agent" ]] || die "three-agent executable is missing after portable deployment"
[[ -f "$ROOT/config/local.json" ]] || die "Local config is missing after portable deployment"

log "Stage 2/6: select and verify the local model pool from detected hardware capacity."
MODEL_POOL_ENV=(
  "THREE_AGENT_INSTALL_DIR=$ROOT"
  "THREE_AGENT_CONFIG=$ROOT/config/local.json"
)
if [[ -n "$MODEL_OVERRIDE" ]]; then
  MODEL_POOL_ENV+=("THREE_AGENT_RESEARCH_MODEL=$MODEL_OVERRIDE" "THREE_AGENT_DEEP_MODEL=$MODEL_OVERRIDE")
fi
if [[ -n "$FAST_MODEL_OVERRIDE" ]]; then
  MODEL_POOL_ENV+=("THREE_AGENT_FAST_MODEL=$FAST_MODEL_OVERRIDE")
fi
env "${MODEL_POOL_ENV[@]}" bash "$ROOT/scripts/enable_model_pool.sh"

MODEL="$(jq -r '.llm.model // .model_policy.research_model // empty' "$ROOT/config/local.json")"
[[ -n "$MODEL" && "$MODEL" != "null" ]] || die "Adaptive model pool did not write a research model to config/local.json"
log "Adaptive model selected: ${MODEL}"

log "Stage 3/6: install/update the authenticated LAN chat service."
CHAT_ENV=(
  "THREE_AGENT_ROOT=$ROOT"
  "THREE_AGENT_MODEL=$MODEL"
  "THREE_AGENT_WEB_PORT=$PORT"
)
if [[ -n "$HOST_OVERRIDE" ]]; then
  CHAT_ENV+=("THREE_AGENT_WEB_HOST=$HOST_OVERRIDE")
fi
env "${CHAT_ENV[@]}" bash "$ROOT/scripts/install_chat_gateway.sh"

[[ -f "$ENV_FILE" ]] || die "Chat environment file was not created: $ENV_FILE"
# shellcheck disable=SC1090
source "$ENV_FILE"
LAN_HOST="${THREE_AGENT_WEB_HOST:-}"
LAN_PORT="${THREE_AGENT_WEB_PORT:-$PORT}"
[[ -n "$LAN_HOST" ]] || die "LAN host was not written to $ENV_FILE"
[[ "$LAN_HOST" != "0.0.0.0" && "$LAN_HOST" != "::" ]] || die "LAN server must not bind a wildcard address"
[[ "$LAN_PORT" == "$PORT" ]] || die "LAN service port does not match requested port"

log "Stage 4/6: scope firewall access to the connected LAN only."
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

log "Stage 5/6: verify model, service, listener and HTTP health."
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

if command -v ss >/dev/null 2>&1; then
  ss -ltn | awk -v endpoint="${LAN_HOST}:${PORT}" '$4 == endpoint {found=1} END {exit(found ? 0 : 1)}' \
    || die "Expected listener was not found at ${LAN_HOST}:${PORT}"
fi

log "Stage 6/6: final application smoke."
THREE_AGENT_CONFIG="$ROOT/config/local.json" "$ROOT/.venv/bin/three-agent" smoke >/dev/null
WEB_TOKEN="$(awk -F= '$1=="THREE_AGENT_WEB_ACCESS_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
[[ ${#WEB_TOKEN} -ge 16 ]] || die "Generated web access key is invalid"

SOURCE_SHA="$(git -C "$ROOT" rev-parse HEAD)"
echo
echo "=========================================================="
echo "         3Agent LAN AI Server - FINAL PASS"
echo "=========================================================="
printf 'Web UI:      http://%s:%s/\n' "$LAN_HOST" "$PORT"
printf 'Access key:  %s\n' "$WEB_TOKEN"
printf 'Model:       %s\n' "$MODEL"
printf 'Repository:  %s\n' "$ROOT"
printf 'Source SHA:  %s\n' "$SOURCE_SHA"
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
