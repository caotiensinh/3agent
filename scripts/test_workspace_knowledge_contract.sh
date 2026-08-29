#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install_workspace_knowledge_plane.sh
bash -n scripts/setup_workspace_secure.sh
python3 -m json.tool config/workspace.secure.json >/dev/null
python3 -m json.tool config/workspace.public-research.json >/dev/null

grep -Fq 'workspace-knowledge = "three_agent.knowledge_cli:main"' pyproject.toml
grep -Fq 'WORKSPACE_PUBLIC_KNOWLEDGE_ROOT' scripts/install_workspace_knowledge_plane.sh
grep -Fq 'workspace-import' scripts/install_workspace_knowledge_plane.sh
grep -Fq "meta skuid \${IMPORT_UID} counter reject" scripts/install_workspace_knowledge_plane.sh
grep -Fq '/var/spool/workspace-public-export' scripts/install_workspace_knowledge_plane.sh
grep -Fq '/var/lib/workspace-knowledge-public' scripts/install_workspace_knowledge_plane.sh
grep -Fq "InaccessiblePaths=\${EXPORT_ROOT} \${KNOWLEDGE_ROOT}" scripts/install_workspace_knowledge_plane.sh
grep -Fq 'install_workspace_knowledge_plane.sh' scripts/setup_workspace_secure.sh
grep -Fq '"network_direction": "inbound_only"' config/workspace.secure.json
grep -Fq '"direction": "inbound_only"' config/workspace.public-research.json

echo 'WorkSpace knowledge-plane contract PASS'
