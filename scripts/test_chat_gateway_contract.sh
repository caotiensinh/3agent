#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install_chat_gateway.sh
bash -n scripts/configure_telegram.sh

grep -Fq 'three-agent-chat' pyproject.toml
grep -Fq 'THREE_AGENT_WEB_ACCESS_TOKEN' scripts/install_chat_gateway.sh
grep -Fq 'chmod 600' scripts/install_chat_gateway.sh
grep -Fq 'NoNewPrivileges=true' scripts/install_chat_gateway.sh
grep -Fq 'PrivateTmp=true' scripts/install_chat_gateway.sh
grep -Fq 'UMask=0077' scripts/install_chat_gateway.sh
grep -Fq 'systemd-analyze --user verify' scripts/install_chat_gateway.sh
grep -Fq 'journalctl --user -u 3agent-chat.service -n 80' scripts/install_chat_gateway.sh
grep -Fq 'private_ipv4' scripts/install_chat_gateway.sh
grep -Fq 'THREE_AGENT_WEB_HOST must be a private non-loopback IPv4 address' scripts/install_chat_gateway.sh

# Capability-/namespace-heavy directives are intentionally forbidden in this
# per-user service. They can fail before ExecStart with status=218/CAPABILITIES
# on Ubuntu hosts where unprivileged user namespaces/capability operations are restricted.
! grep -Eq '^[[:space:]]*ProtectKernelModules=' scripts/install_chat_gateway.sh
! grep -Eq '^[[:space:]]*ProtectKernelTunables=' scripts/install_chat_gateway.sh
! grep -Eq '^[[:space:]]*ProtectControlGroups=' scripts/install_chat_gateway.sh
! grep -Eq '^[[:space:]]*ProtectSystem=' scripts/install_chat_gateway.sh
! grep -Eq '^[[:space:]]*(AmbientCapabilities|CapabilityBoundingSet)=' scripts/install_chat_gateway.sh

grep -Fq 'THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS' scripts/configure_telegram.sh
grep -Fq 'read -r -s' scripts/configure_telegram.sh
grep -Fq 'getUpdates' src/three_agent/chat_gateway.py
grep -Fq 'user_id not in self.allowed_user_ids' src/three_agent/chat_gateway.py
grep -Fq 'post_json' src/three_agent/chat_gateway.py
grep -Fq 'REDACTED_TELEGRAM_BOT_TOKEN' src/three_agent/privacy.py

echo "chat gateway contract PASS"
