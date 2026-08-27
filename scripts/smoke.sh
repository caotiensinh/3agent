#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-}:src"
export THREE_AGENT_CONFIG="${THREE_AGENT_CONFIG:-config/test.example.json}"
python3 -m three_agent.cli smoke
