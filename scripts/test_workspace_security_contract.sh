#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install_workspace_secure_boundary.sh
bash -n scripts/setup_workspace_secure.sh
python3 -m json.tool config/workspace.secure.json >/dev/null

grep -Fq '"product_name": "WorkSpace"' config/workspace.secure.json
grep -Fq '"confidentiality_mode": "confidential"' config/workspace.secure.json
grep -Fq '"public_search_enabled": false' config/workspace.secure.json
grep -Fq '"direct_egress": false' config/workspace.secure.json
grep -Fq '/run/workspace/egress.sock' config/workspace.secure.json
grep -Fq 'workspace-core' scripts/install_workspace_secure_boundary.sh
grep -Fq 'Public search remains disabled by default' scripts/setup_workspace_secure.sh
grep -Fq 'workspace-egress' scripts/install_workspace_secure_boundary.sh
grep -Fq 'meta skuid' scripts/install_workspace_secure_boundary.sh
grep -Fq '127.0.0.1 tcp dport 11434-11436 accept' scripts/install_workspace_secure_boundary.sh
grep -Fq '127.0.0.53 udp dport 53 accept' scripts/install_workspace_secure_boundary.sh
grep -Fq '192.168.0.0/16' scripts/install_workspace_secure_boundary.sh
grep -Fq "meta skuid \${EGRESS_UID} tcp dport 443 accept" scripts/install_workspace_secure_boundary.sh
grep -Fq "meta skuid \${EGRESS_UID} counter reject" scripts/install_workspace_secure_boundary.sh
grep -Fq 'counter reject' scripts/install_workspace_secure_boundary.sh
grep -Fq 'workspace = "three_agent.cli:main"' pyproject.toml
grep -Fq 'workspace-egressd = "three_agent.egress_broker:main"' pyproject.toml

echo 'WorkSpace security contract PASS'
