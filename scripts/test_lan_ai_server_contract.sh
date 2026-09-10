#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/setup_lan_ai_server.sh"

bash -n "$SCRIPT"
bash "$SCRIPT" --self-test

grep -Fq 'deploy_ubuntu_pc.sh' "$SCRIPT"
grep -Fq 'enable_model_pool.sh' "$SCRIPT"
grep -Fq 'install_chat_gateway.sh' "$SCRIPT"
grep -Fq 'THREE_AGENT_INSTALL_OLLAMA=1' "$SCRIPT"
grep -Fq 'Adaptive model selected:' "$SCRIPT"
grep -Fq '/api/health' "$SCRIPT"
grep -Fq 'systemctl --user is-active --quiet 3agent-chat.service' "$SCRIPT"
grep -Fq 'Client PCs:' "$SCRIPT"
grep -Fq 'Do NOT install Python, Ollama, models or 3Agent.' "$SCRIPT"
grep -Fq "ufw allow from \"\$LAN_CIDR\" to \"\$LAN_HOST\" port \"\$PORT\" proto tcp" "$SCRIPT"
grep -Fq 'LAN server must not bind a wildcard address' "$SCRIPT"
grep -Fq 'THREE_AGENT_WEB_HOST must be a private non-loopback IPv4 address' "$SCRIPT"

if grep -Fq 'setup_ai_stack_ubuntu2404.sh' "$SCRIPT"; then
  echo "LAN server bootstrap must not depend on the legacy RTX5090-specific AI-stack installer" >&2
  exit 1
fi
if grep -Eq 'THREE_AGENT_MIN_DRIVER_MAJOR|THREE_AGENT_REQUIRED_RTX5090_COUNT|Need at least .*RTX 5090' "$SCRIPT"; then
  echo "LAN server bootstrap must not impose a fixed NVIDIA model/driver profile" >&2
  exit 1
fi
if grep -Eq 'ufw allow ([0-9]+/tcp|[0-9]+)' "$SCRIPT"; then
  echo "LAN server bootstrap must not add a broad world-accessible UFW rule" >&2
  exit 1
fi

echo "LAN AI server contract PASS"
