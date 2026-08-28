#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${THREE_AGENT_ROOT:-$HOME/3agent}"
CONFIG_DIR="$HOME/.config/3agent"
ENV_FILE="$CONFIG_DIR/chat.env"
SYSTEMD_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SYSTEMD_DIR/3agent-chat.service"
PORT="${THREE_AGENT_WEB_PORT:-8787}"
MODEL="${THREE_AGENT_MODEL:-qwen3:30b}"
HOST="${THREE_AGENT_WEB_HOST:-}"

log() { printf '[3Agent-Chat-Setup] %s\n' "$*"; }
fail() { printf '[3Agent-Chat-Setup][ERROR] %s\n' "$*" >&2; exit 1; }

private_ipv4() {
  "$ROOT/.venv/bin/python" - "$1" <<'PY'
import ipaddress
import sys
value = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
try:
    address = ipaddress.ip_address(value)
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 and address.is_private and not address.is_loopback else 1)
PY
}

detect_lan_host() {
  local candidate=""
  if command -v ip >/dev/null 2>&1; then
    candidate="$(
      ip -4 route get 1.1.1.1 2>/dev/null \
        | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
    )"
    if [[ -n "$candidate" ]] && private_ipv4 "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  while read -r candidate; do
    if [[ -n "$candidate" ]] && private_ipv4 "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done < <(hostname -I 2>/dev/null | tr ' ' '\n')

  return 1
}

[[ -d "$ROOT/.git" ]] || fail "Repository not found: $ROOT"
[[ -x "$ROOT/.venv/bin/python" ]] || fail "Python environment missing: $ROOT/.venv"

cd "$ROOT"
"$ROOT/.venv/bin/python" -m pip install -e . >/dev/null
[[ -x "$ROOT/.venv/bin/three-agent-chat" ]] || fail "three-agent-chat command was not installed"

if [[ -z "$HOST" ]]; then
  HOST="$(detect_lan_host || true)"
fi
[[ -n "$HOST" ]] || fail "Unable to detect a private LAN IPv4 address. Set THREE_AGENT_WEB_HOST explicitly."
private_ipv4 "$HOST" || fail "THREE_AGENT_WEB_HOST must be a private non-loopback IPv4 address for LAN mode"

mkdir -p "$CONFIG_DIR" "$SYSTEMD_DIR"
chmod 700 "$CONFIG_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  WEB_TOKEN="$("$ROOT/.venv/bin/python" - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  cat >"$ENV_FILE" <<EOF
THREE_AGENT_CONFIG=$ROOT/config/local.json
LOCAL_LLM_MODEL=$MODEL
THREE_AGENT_WEB_ACCESS_TOKEN=$WEB_TOKEN
THREE_AGENT_WEB_HOST=$HOST
THREE_AGENT_WEB_PORT=$PORT
THREE_AGENT_CHAT_LANGUAGE=ja
THREE_AGENT_TELEGRAM_BOT_TOKEN=
THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS=
EOF
  chmod 600 "$ENV_FILE"
  log "Created local secret/config file: $ENV_FILE"
else
  chmod 600 "$ENV_FILE"
  if grep -q '^THREE_AGENT_WEB_HOST=' "$ENV_FILE"; then
    sed -i "s/^THREE_AGENT_WEB_HOST=.*/THREE_AGENT_WEB_HOST=$HOST/" "$ENV_FILE"
  else
    printf 'THREE_AGENT_WEB_HOST=%s\n' "$HOST" >>"$ENV_FILE"
  fi
  if grep -q '^THREE_AGENT_WEB_PORT=' "$ENV_FILE"; then
    sed -i "s/^THREE_AGENT_WEB_PORT=.*/THREE_AGENT_WEB_PORT=$PORT/" "$ENV_FILE"
  else
    printf 'THREE_AGENT_WEB_PORT=%s\n' "$PORT" >>"$ENV_FILE"
  fi
  log "Preserving existing local secret/config file while refreshing LAN bind settings: $ENV_FILE"
fi

cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=3Agent LAN Chat and Telegram Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
EnvironmentFile=$ENV_FILE
ExecStart=$ROOT/.venv/bin/three-agent-chat
Restart=on-failure
RestartSec=5

# User-service-safe hardening. Do not add ProtectKernelModules=,
# ProtectKernelTunables=, ProtectControlGroups= or ProtectSystem=strict here:
# those options may require namespace/capability operations unavailable to a
# per-user systemd manager and can make Ubuntu exit with 218/CAPABILITIES.
NoNewPrivileges=true
PrivateTmp=true
LockPersonality=true
RestrictSUIDSGID=true
UMask=0077

[Install]
WantedBy=default.target
EOF

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze --user verify "$SERVICE_FILE" >/dev/null \
    || fail "systemd rejected the generated user service. Run: systemd-analyze --user verify $SERVICE_FILE"
fi

if command -v loginctl >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
  sudo loginctl enable-linger "$USER" >/dev/null
fi

systemctl --user daemon-reload
systemctl --user enable 3agent-chat.service >/dev/null
systemctl --user reset-failed 3agent-chat.service >/dev/null 2>&1 || true
systemctl --user restart 3agent-chat.service
sleep 2
systemctl --user is-active --quiet 3agent-chat.service || {
  exec_status="$(systemctl --user show 3agent-chat.service -p ExecMainStatus --value 2>/dev/null || true)"
  result="$(systemctl --user show 3agent-chat.service -p Result --value 2>/dev/null || true)"
  systemctl --user status 3agent-chat.service --no-pager || true
  journalctl --user -u 3agent-chat.service -n 80 --no-pager || true
  if [[ "$exec_status" == "218" ]]; then
    printf '%s\n' "[3Agent-Chat-Setup][DIAG] systemd reported 218/CAPABILITIES; the generated unit intentionally avoids capability-requiring sandbox directives." >&2
  fi
  fail "3agent-chat service did not become active (result=${result:-unknown}, ExecMainStatus=${exec_status:-unknown})"
}

WEB_TOKEN="$(awk -F= '$1=="THREE_AGENT_WEB_ACCESS_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"

echo
echo "=========================================="
echo "       3Agent LAN Chat is READY"
echo "=========================================="
printf 'URL:        http://%s:%s/\n' "$HOST" "$PORT"
printf 'Access key: %s\n' "$WEB_TOKEN"
printf 'Bind:       %s:%s (private LAN IPv4 only)\n' "$HOST" "$PORT"
printf 'Service:    systemctl --user status 3agent-chat.service\n'
printf 'Logs:       journalctl --user -u 3agent-chat.service -f\n'
echo
echo "Telegram is optional. Configure it safely with:"
echo "  bash scripts/configure_telegram.sh"
echo "=========================================="
