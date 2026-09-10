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

# Secure bootstrap must be hardware-adaptive by default. GPU/driver requirements are
# opt-in policy, not universal deployment requirements.
# shellcheck disable=SC2016
grep -Fq 'HARDWARE_PROFILE="${WORKSPACE_HARDWARE_PROFILE:-auto}"' scripts/setup_workspace_secure.sh
# shellcheck disable=SC2016
grep -Fq 'MIN_DRIVER_MAJOR="${WORKSPACE_MIN_DRIVER_MAJOR:-}"' scripts/setup_workspace_secure.sh
# shellcheck disable=SC2016
grep -Fq 'REQUIRED_RTX5090_COUNT="${WORKSPACE_REQUIRED_RTX5090_COUNT:-}"' scripts/setup_workspace_secure.sh
grep -Fq 'dual-rtx5090)' scripts/setup_workspace_secure.sh
grep -Fq 'No healthy NVIDIA runtime detected; continuing with CPU/system-RAM model profile' scripts/setup_workspace_secure.sh
grep -Fq 'Reusing installed Ollama model' scripts/setup_workspace_secure.sh
grep -Fq 'WORKSPACE_SECURE_CONFIG_SOURCE=' scripts/setup_workspace_secure.sh
grep -Fq 'WORKSPACE_PUBLIC_CONFIG_SOURCE=' scripts/setup_workspace_secure.sh

if grep -Fq 'WORKSPACE_MIN_DRIVER_MAJOR:-590' scripts/setup_workspace_secure.sh; then
  echo 'secure installer must not force driver 590 by default' >&2
  exit 1
fi
if grep -Fq 'WORKSPACE_REQUIRED_RTX5090_COUNT:-2' scripts/setup_workspace_secure.sh; then
  echo 'secure installer must not force two RTX 5090 GPUs by default' >&2
  exit 1
fi

check_profile() {
  local expected="$1"
  shift
  local output
  output="$(env "$@" bash scripts/setup_workspace_secure.sh --self-test)"
  printf '%s\n' "$output" | grep -Fq "$expected" || {
    printf 'adaptive model selection mismatch\nexpected fragment: %s\nactual: %s\n' "$expected" "$output" >&2
    exit 1
  }
}

check_profile 'model=qwen3:1.7b fast_model=qwen3:0.6b' WORKSPACE_TEST_VRAM_MIB=0 WORKSPACE_TEST_RAM_MIB=8192
check_profile 'model=qwen3:4b fast_model=qwen3:1.7b' WORKSPACE_TEST_VRAM_MIB=0 WORKSPACE_TEST_RAM_MIB=16384
check_profile 'model=qwen3:8b fast_model=qwen3:4b' WORKSPACE_TEST_VRAM_MIB=0 WORKSPACE_TEST_RAM_MIB=32768
check_profile 'model=qwen3:4b fast_model=qwen3:1.7b' WORKSPACE_TEST_VRAM_MIB=4096 WORKSPACE_TEST_RAM_MIB=8192
check_profile 'model=qwen3:8b fast_model=qwen3:4b' WORKSPACE_TEST_VRAM_MIB=8192 WORKSPACE_TEST_RAM_MIB=8192
check_profile 'model=qwen3:14b fast_model=qwen3:8b' WORKSPACE_TEST_VRAM_MIB=16384 WORKSPACE_TEST_RAM_MIB=8192
check_profile 'model=qwen3:14b fast_model=qwen3:8b' WORKSPACE_TEST_VRAM_MIB=24576 WORKSPACE_TEST_RAM_MIB=8192
check_profile 'model=qwen3:30b fast_model=qwen3:14b' WORKSPACE_TEST_VRAM_MIB=28672 WORKSPACE_TEST_RAM_MIB=8192
check_profile 'model=operator-main fast_model=operator-fast' WORKSPACE_TEST_VRAM_MIB=4096 WORKSPACE_TEST_RAM_MIB=8192 WORKSPACE_LLM_MODEL=operator-main WORKSPACE_FAST_MODEL=operator-fast

grep -Fq 'workspace-core' scripts/install_workspace_secure_boundary.sh
grep -Fq 'workspace-public' scripts/install_workspace_secure_boundary.sh
grep -Fq 'workspace-egress' scripts/install_workspace_secure_boundary.sh

# Core may reach the constrained Unix-domain broker, but must retain no direct
# Internet/LAN egress capability. Both invariants are required together.
grep -Fq "usermod -a -G \"\$IPC_GROUP\" \"\$CORE_USER\"" scripts/install_workspace_secure_boundary.sh
grep -Fq "usermod -a -G \"\$IPC_GROUP\" \"\$PUBLIC_USER\"" scripts/install_workspace_secure_boundary.sh
grep -Fq 'InaccessiblePaths=/var/lib/workspace /var/lib/workspace-public' scripts/install_workspace_secure_boundary.sh
grep -Fq -- "--allow-uid \${PUBLIC_UID} --allow-uid \${CORE_UID}" scripts/install_workspace_secure_boundary.sh
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
