#!/usr/bin/env python3
"""Canonical execution-governance entrypoint with CI evidence compatibility."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

_CORE_PATH = Path(__file__).with_name("_execution_governance_core.py")
_CORE_SPEC = importlib.util.spec_from_file_location("workspace_execution_governance_core", _CORE_PATH)
if _CORE_SPEC is None or _CORE_SPEC.loader is None:
    raise RuntimeError(f"unable to load execution governance core: {_CORE_PATH}")
_core = importlib.util.module_from_spec(_CORE_SPEC)
sys.modules[_CORE_SPEC.name] = _core
_CORE_SPEC.loader.exec_module(_core)

# Preserve the canonical module API used by unit tests and internal callers.
for _name in dir(_core):
    if _name.startswith("__") or _name == "main":
        continue
    globals()[_name] = getattr(_core, _name)


def _write_json_output(raw_path: str | None, payload: dict[str, Any]) -> None:
    if not raw_path:
        return
    path = Path(raw_path).resolve()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--json-output")
    compatibility, remaining = parser.parse_known_args(argv)

    try:
        rc = int(_core.main(remaining))
    except SystemExit:
        raise
    except Exception as exc:
        payload = {
            "valid": False,
            "classification": "VALIDATOR_ERROR",
            "violations": [
                {
                    "rule_id": "GOV-VALIDATOR-EXCEPTION",
                    "severity": "error",
                    "message": f"{type(exc).__name__}: {exc}",
                }
            ],
        }
        try:
            _write_json_output(compatibility.json_output, payload)
        except OSError as output_exc:
            print(f"EXECUTION_GOVERNANCE: FAIL: {output_exc}", file=sys.stderr)
        raise

    payload = {
        "valid": rc == 0,
        "classification": "PASS" if rc == 0 else "VALIDATOR_ERROR",
        "violations": []
        if rc == 0
        else [
            {
                "rule_id": "GOV-VALIDATOR-FAILED",
                "severity": "error",
                "message": "canonical execution governance validation failed; read validator log",
            }
        ],
    }
    try:
        _write_json_output(compatibility.json_output, payload)
    except OSError as exc:
        print(f"EXECUTION_GOVERNANCE: FAIL: {exc}", file=sys.stderr)
        return 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
