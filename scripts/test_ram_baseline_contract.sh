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

# Read-only: must never call systemctl start/stop/restart/enable/disable, nvidia-smi -pm,
# or any other mutating command.
if grep -Eq 'systemctl (start|stop|restart|enable|disable)|nvidia-smi[^|]*-pm|sudo ' "$SCRIPT"; then
  echo "RAM baseline snapshot script must be strictly read-only" >&2
  exit 1
fi

echo "RAM baseline snapshot contract PASS"
