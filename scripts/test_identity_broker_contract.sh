#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install_workspace_identity_broker.sh
python3 -m py_compile \
  src/three_agent/workspace_identity_broker.py \
  src/three_agent/workspace_external_identity.py \
  src/three_agent/chat_gateway.py \
  src/three_agent/workspace_frontend.py

grep -Fq 'User=workspace-auth' scripts/install_workspace_identity_broker.sh
grep -Fq 'ProtectHome=true' scripts/install_workspace_identity_broker.sh
grep -Fq 'ProtectSystem=strict' scripts/install_workspace_identity_broker.sh
grep -Fq 'NoNewPrivileges=true' scripts/install_workspace_identity_broker.sh
grep -Fq 'CapabilityBoundingSet=' scripts/install_workspace_identity_broker.sh
grep -Fq 'RestrictAddressFamilies=AF_INET AF_INET6' scripts/install_workspace_identity_broker.sh
grep -Fq 'http://127.0.0.1:' scripts/install_workspace_identity_broker.sh

grep -Fq 'scope": "openid profile"' src/three_agent/workspace_identity_broker.py
grep -Fq 'scope": "read:user"' src/three_agent/workspace_identity_broker.py
if grep -Eq 'scope"[[:space:]]*:[[:space:]]*"[^"]*(repo|user:email|offline_access)' src/three_agent/workspace_identity_broker.py; then
  echo 'identity broker requests forbidden OAuth scope' >&2
  exit 1
fi

for forbidden in \
  'from .config import load_config' \
  'from .orchestrator import' \
  'workspace_auth' \
  'chat_history' \
  'knowledge_gateway' \
  '/var/lib/workspace'
do
  if grep -Fq "$forbidden" src/three_agent/workspace_identity_broker.py; then
    echo "identity broker contains forbidden confidential dependency: $forbidden" >&2
    exit 1
  fi
done

grep -Fq 'WORKSPACE_EXTERNAL_AUTH_REDEEM_URL' src/three_agent/workspace_external_identity.py
grep -Fq 'redeem.hostname not in {"127.0.0.1", "localhost", "::1"}' src/three_agent/workspace_external_identity.py
grep -Fq 'external_authority": "identity_only"' src/three_agent/chat_gateway.py

echo "identity broker contract PASS"
