#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/measure_ram_baseline.sh"

bash -n "$SCRIPT"

# Must run cleanly with no GPU/systemd present (e.g. a CI runner or review sandbox) and
# never mutate system state.
OUTPUT="$(bash "$SCRIPT" ci-contract-check)"
grep -q '"schema": "workspace-ram-baseline/v1"' <<<"$OUTPUT"
grep -q '"label": "ci-contract-check"' <<<"$OUTPUT"
grep -q '"ram":' <<<"$OUTPUT"
grep -q '"gpus":' <<<"$OUTPUT"
grep -q '"services":' <<<"$OUTPUT"
grep -q '"resident_model_counts":' <<<"$OUTPUT"

python3 -c "import json,sys; json.loads(sys.argv[1])" "$OUTPUT"

# Privacy: this is metadata-only, matching evaluation/representative_hardware_closure_*.json.
# Assert on the actual runtime JSON output, not script prose, so explanatory comments
# about what NOT to capture cannot trip this check.
python3 -c "
import json, sys
doc = json.loads(sys.argv[1])
forbidden = {'hostname', 'uuid', 'serial', 'command', 'model_name', 'model'}
def walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in forbidden:
                sys.exit(f'RAM baseline output must not carry a {key!r} field')
            walk(value)
    elif isinstance(node, list):
        for item in node:
            walk(item)
walk(doc)
" "$OUTPUT"

if grep -E -- '--query-gpu=' "$SCRIPT" | grep -Eiq 'uuid|serial'; then
  echo "RAM baseline snapshot must not query GPU uuid/serial fields" >&2
  exit 1
fi

# Exercise the has-GPU branch with a mock nvidia-smi, since this review sandbox has no
# real GPU and a hand-rolled-JSON version of this branch previously shipped broken: it
# parsed fine here (gpus: null) but produced invalid JSON once real nvidia-smi CSV output
# (with its leading spaces and occasional "[N/A]" fields) reached it on the actual
# dual-RTX5090 workstation. Cover both the numeric case and the "[N/A]" case.
MOCK_BIN_DIR="$(mktemp -d)"
trap 'rm -rf "$MOCK_BIN_DIR"' EXIT
cat >"$MOCK_BIN_DIR/nvidia-smi" <<'MOCK'
#!/usr/bin/env bash
if [[ "$*" == *"--query-gpu"* ]]; then
  printf '0, 32607, 1067, 0, 51\n'
  printf '1, 32607, 1171, [N/A], [N/A]\n'
else
  echo "mock nvidia-smi"
fi
MOCK
chmod +x "$MOCK_BIN_DIR/nvidia-smi"

GPU_OUTPUT="$(PATH="$MOCK_BIN_DIR:$PATH" bash "$SCRIPT" gpu-mock-check)"
python3 -c "
import json, sys
doc = json.loads(sys.argv[1])
gpus = doc['gpus']
assert isinstance(gpus, list) and len(gpus) == 2, gpus
assert gpus[0] == {'index': 0, 'memory_total_mib': 32607, 'memory_used_mib': 1067, 'util_percent': 0, 'temp_c': 51}, gpus[0]
assert gpus[1]['util_percent'] is None and gpus[1]['temp_c'] is None, gpus[1]
" "$GPU_OUTPUT"

# Read-only: must never call systemctl start/stop/restart/enable/disable, nvidia-smi -pm,
# or any other mutating command.
if grep -Eq 'systemctl (start|stop|restart|enable|disable)|nvidia-smi[^|]*-pm|sudo ' "$SCRIPT"; then
  echo "RAM baseline snapshot script must be strictly read-only" >&2
  exit 1
fi

echo "RAM baseline snapshot contract PASS"
