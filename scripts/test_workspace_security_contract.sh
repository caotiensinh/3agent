#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install_workspace_secure_boundary.sh
bash -n scripts/setup_workspace_secure.sh
python3 -m json.tool config/workspace.secure.json >/dev/null
python3 -m json.tool config/workspace.public-research.json >/dev/null

grep -Fq '"product_name": "WorkSpace"' config/workspace.secure.json
grep -Fq '"confidentiality_mode": "confidential"' config/workspace.secure.json
grep -Fq '"public_search_enabled": false' config/workspace.secure.json
grep -Fq '"direct_egress": false' config/workspace.secure.json

grep -Fq '"confidentiality_mode": "public-research"' config/workspace.public-research.json
grep -Fq '"database_path": "/var/lib/workspace-public/tasks.db"' config/workspace.public-research.json
grep -Fq '"public_search_enabled": true' config/workspace.public-research.json

grep -Fq 'workspace-core' scripts/install_workspace_secure_boundary.sh
grep -Fq 'workspace-public' scripts/install_workspace_secure_boundary.sh
grep -Fq 'workspace-egress' scripts/install_workspace_secure_boundary.sh
grep -Fq 'Deliberately do NOT add workspace-core to the egress IPC group' scripts/install_workspace_secure_boundary.sh
if grep -Eq 'usermod .*CORE_USER.*IPC_GROUP' scripts/install_workspace_secure_boundary.sh; then
  echo 'workspace-core must never join the egress IPC group' >&2
  exit 1
fi
grep -Fq 'InaccessiblePaths=/var/lib/workspace /var/lib/workspace-public' scripts/install_workspace_secure_boundary.sh
grep -Fq -- '--allow-uid ${PUBLIC_UID}' scripts/install_workspace_secure_boundary.sh
grep -Fq "meta skuid \${CORE_UID} counter reject" scripts/install_workspace_secure_boundary.sh
grep -Fq "meta skuid \${PUBLIC_UID} counter reject" scripts/install_workspace_secure_boundary.sh
grep -Fq '127.0.0.1 tcp dport 11434-11436 accept' scripts/install_workspace_secure_boundary.sh
grep -Fq '127.0.0.53 udp dport 53 accept' scripts/install_workspace_secure_boundary.sh
grep -Fq '192.168.0.0/16' scripts/install_workspace_secure_boundary.sh
grep -Fq "meta skuid \${EGRESS_UID} tcp dport 443 accept" scripts/install_workspace_secure_boundary.sh
grep -Fq "meta skuid \${EGRESS_UID} counter reject" scripts/install_workspace_secure_boundary.sh
grep -Fq '/usr/local/bin/workspace-secure' scripts/install_workspace_secure_boundary.sh
grep -Fq '/usr/local/bin/workspace-public' scripts/install_workspace_secure_boundary.sh

grep -Fq 'workspace = "three_agent.cli:main"' pyproject.toml
grep -Fq 'workspace-egressd = "three_agent.egress_broker:main"' pyproject.toml

echo 'WorkSpace security contract PASS'
