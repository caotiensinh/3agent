#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="${THREE_AGENT_CHAT_ENV:-$HOME/.config/3agent/chat.env}"
SERVICE="3agent-chat.service"

[[ -f "$ENV_FILE" ]] || {
  echo "[ERROR] Chat environment not found: $ENV_FILE" >&2
  echo "Run: bash scripts/install_chat_gateway.sh" >&2
  exit 1
}
chmod 600 "$ENV_FILE"

CURRENT_TOKEN="$(awk -F= '$1=="THREE_AGENT_TELEGRAM_BOT_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
CURRENT_IDS="$(awk -F= '$1=="THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"

TOKEN="$CURRENT_TOKEN"
if [[ -n "$CURRENT_TOKEN" ]]; then
  printf 'A Telegram bot token is already stored locally. Reuse it? [Y/n]: '
  read -r REUSE
  if [[ "${REUSE:-Y}" =~ ^[Nn]$ ]]; then
    read -r -s -p 'Paste new BotFather token: ' TOKEN
    echo
  fi
else
  read -r -s -p 'Paste BotFather token (input is hidden): ' TOKEN
  echo
fi

[[ "$TOKEN" =~ ^[0-9]{5,}:[A-Za-z0-9_-]{20,}$ ]] || {
  echo "[ERROR] Token format does not look like a Telegram bot token." >&2
  exit 1
}

printf 'Allowed Telegram user IDs (comma-separated).\n'
printf 'Current: %s\n' "${CURRENT_IDS:-<none>}"
printf 'Leave blank to keep current value; use NONE to clear allow-list: '
read -r IDS_INPUT
if [[ -z "$IDS_INPUT" ]]; then
  IDS="$CURRENT_IDS"
elif [[ "$IDS_INPUT" == "NONE" ]]; then
  IDS=""
else
  IDS="$(printf '%s' "$IDS_INPUT" | tr -d ' ')"
  [[ "$IDS" =~ ^[0-9]+(,[0-9]+)*$ ]] || {
    echo "[ERROR] User IDs must be comma-separated integers." >&2
    exit 1
  }
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
awk -v token="$TOKEN" -v ids="$IDS" '
  BEGIN { seen_token=0; seen_ids=0 }
  /^THREE_AGENT_TELEGRAM_BOT_TOKEN=/ {
    print "THREE_AGENT_TELEGRAM_BOT_TOKEN=" token
    seen_token=1
    next
  }
  /^THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS=/ {
    print "THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS=" ids
    seen_ids=1
    next
  }
  { print }
  END {
    if (!seen_token) print "THREE_AGENT_TELEGRAM_BOT_TOKEN=" token
    if (!seen_ids) print "THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS=" ids
  }
' "$ENV_FILE" >"$TMP"
install -m 600 "$TMP" "$ENV_FILE"

systemctl --user restart "$SERVICE"
systemctl --user is-active --quiet "$SERVICE" || {
  systemctl --user status "$SERVICE" --no-pager || true
  exit 1
}

echo
echo "Telegram configuration saved locally and service restarted."
if [[ -z "$IDS" ]]; then
  echo "No workflow user is authorized yet. Send /id to your bot, then run this script again and enter that numeric ID."
else
  echo "Authorized Telegram user IDs: $IDS"
fi
