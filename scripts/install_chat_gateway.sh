#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${THREE_AGENT_ROOT:-$HOME/3agent}"
CONFIG_DIR="$HOME/.config/3agent"
ENV_FILE="$CONFIG_DIR/chat.env"
SYSTEMD_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SYSTEMD_DIR/3agent-chat.service"
PORT="${THREE_AGENT_WEB_PORT:-8787}"
MODEL="${THREE_AGENT_MODEL:-qwen3:30b}"

log() { printf '[3Agent-Chat-Setup] %s\n' "$*"; }
fail() { printf '[3Agent-Chat-Setup][ERROR] %s\n' "$*" >&2; exit 1; }

[[ -d "$ROOT/.git" ]] || fail "Repository not found: $ROOT"
[[ -x "$ROOT/.venv/bin/python" ]] || fail "Python environment missing: $ROOT/.venv"

cd "$ROOT"
"$ROOT/.venv/bin/python" -m pip install -e . >/dev/null
[[ -x "$ROOT/.venv/bin/three-agent-chat" ]] || fail "three-agent-chat command was not installed"

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
THREE_AGENT_WEB_HOST=0.0.0.0
THREE_AGENT_WEB_PORT=$PORT
THREE_AGENT_CHAT_LANGUAGE=ja
THREE_AGENT_TELEGRAM_BOT_TOKEN=
THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS=
EOF
  chmod 600 "$ENV_FILE"
  log "Created local secret/config file: $ENV_FILE"
else
  chmod 600 "$ENV_FILE"
  log "Preserving existing local secret/config file: $ENV_FILE"
fi

cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=3Agent LAN Chat and Telegram Gateway
After=network-online.target ollama.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
EnvironmentFile=$ENV_FILE
ExecStart=$ROOT/.venv/bin/three-agent-chat
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=default.target
EOF

if command -v loginctl >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
  sudo loginctl enable-linger "$USER" >/dev/null
fi

systemctl --user daemon-reload
systemctl --user enable --now 3agent-chat.service
sleep 2
systemctl --user is-active --quiet 3agent-chat.service || {
  systemctl --user status 3agent-chat.service --no-pager || true
  fail "3agent-chat service did not become active"
}

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
WEB_TOKEN="$(awk -F= '$1=="THREE_AGENT_WEB_ACCESS_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"

echo
echo "=========================================="
echo "       3Agent LAN Chat is READY"
echo "=========================================="
printf 'URL:        http://%s:%s/\n' "${LAN_IP:-<LAN-IP>}" "$PORT"
printf 'Access key: %s\n' "$WEB_TOKEN"
printf 'Service:    systemctl --user status 3agent-chat.service\n'
printf 'Logs:       journalctl --user -u 3agent-chat.service -f\n'
echo
echo "Telegram is optional. Configure it safely with:"
echo "  bash scripts/configure_telegram.sh"
echo "=========================================="
