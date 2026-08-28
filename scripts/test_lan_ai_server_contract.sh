#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/setup_lan_ai_server.sh"

bash -n "$SCRIPT"
bash "$SCRIPT" --self-test

grep -Fq 'setup_ai_stack_ubuntu2404.sh' "$SCRIPT"
grep -Fq 'install_chat_gateway.sh' "$SCRIPT"
grep -Fq '/api/health' "$SCRIPT"
grep -Fq 'systemctl --user is-active --quiet 3agent-chat.service' "$SCRIPT"
grep -Fq 'Client PCs:' "$SCRIPT"
grep -Fq 'Do NOT install Python, Ollama, models or 3Agent.' "$SCRIPT"
grep -Fq "ufw allow from \"\$LAN_CIDR\" to \"\$LAN_HOST\" port \"\$PORT\" proto tcp" "$SCRIPT"
grep -Fq 'LAN server must not bind a wildcard address' "$SCRIPT"

if grep -Eq 'ufw allow ([0-9]+/tcp|[0-9]+)' "$SCRIPT"; then
  echo "LAN server bootstrap must not add a broad world-accessible UFW rule" >&2
  exit 1
fi

echo "LAN AI server contract PASS"
