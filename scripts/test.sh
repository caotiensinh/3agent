#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-}:src"
python3 scripts/scan_skills.py
python3 -m compileall -q src tests
python3 -m unittest discover -s tests -v
