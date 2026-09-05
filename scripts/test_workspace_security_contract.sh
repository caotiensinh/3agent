#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install_workspace_secure_boundary.sh
bash -n scripts/setup_workspace_secure.sh
python3 -m json.tool config/workspace.secure.json >/dev/null
python3 -m json.tool config/workspace.public-research.json >/dev/null

python3 - <<'PY'
import json
from pathlib import Path

secure = json.loads(Path("config/workspace.secure.json").read_text(encoding="utf-8"))
public = json.loads(Path("config/workspace.public-research.json").read_text(encoding="utf-8"))

assert secure["product_name"] == "WorkSpace"
assert secure["confidentiality_mode"] == "confidential"
assert secure["test_mode_full_access"] is False

secure_gateway = secure["internet_gateway"]
assert secure_gateway["enabled"] is True
assert secure_gateway["mode"] == "strict"
assert secure_gateway["public_search_enabled"] is False
assert secure_gateway["egress_policy"] == "workspace.internet-egress/v1"
assert secure_gateway["egress_mode"] == "sanitized"
assert secure_gateway["user_warning_on_transform"] is True
assert secure_gateway["allow_all_outbound_in_test"] is False
assert secure_gateway["direct_egress"] is False
assert secure_gateway["allowed_search_hosts"]

assert public["product_name"] == "WorkSpace"
assert public["confidentiality_mode"] == "public-research"
assert public["test_mode_full_access"] is False
assert public["database_path"] == "/var/lib/workspace-public/tasks.db"
assert public["artifact_root"] == "/var/lib/workspace-public/data"
assert public["internet_gateway"]["public_search_enabled"] is True
assert public["internet_gateway"]["direct_egress"] is False
assert public["execution_gateway"]["enabled"] is False
assert public["github"]["enabled"] is False
PY

grep -Fq 'workspace-core' scripts/install_workspace_secure_boundary.sh
grep -Fq 'workspace-public' scripts/install_workspace_secure_boundary.sh
grep -Fq 'workspace-egress' scripts/install_workspace_secure_boundary.sh
grep -Fq 'Deliberately do NOT add workspace-core to the egress IPC group' scripts/install_workspace_secure_boundary.sh
if grep -Eq 'usermod .*CORE_USER.*IPC_GROUP' scripts/install_workspace_secure_boundary.sh; then
  echo 'workspace-core must never join the egress IPC group' >&2
  exit 1
fi
grep -Fq 'InaccessiblePaths=/var/lib/workspace /var/lib/workspace-public' scripts/install_workspace_secure_boundary.sh
grep -Fq -- "--allow-uid \${PUBLIC_UID}" scripts/install_workspace_secure_boundary.sh
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
