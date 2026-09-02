#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

CONFIRMATION = "READ_ONLY_SECURITY_PILOT"
PILOT_SCHEMA = "workspace-security-monitoring/readonly-physical-pilot-v1"
_REQUIRED_POLICY = {
    "network_scope": "approved_inventory_only",
    "read_only": True,
    "production_safety_profile": "non_disruptive_v1",
    "allow_active_liveness": False,
    "bandwidth_measurement_mode": "counter_only",
    "packet_analysis_mode": "passive_only",
}


class PilotError(RuntimeError):
    pass


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _load_json_object(text: str, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PilotError(f"{label}_INVALID_JSON") from exc
    if not isinstance(payload, dict):
        raise PilotError(f"{label}_NOT_OBJECT")
    return payload


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_host_local_config(config_path: Path, installed_dir: Path) -> dict[str, Any]:
    if config_path.is_symlink() or not config_path.is_file():
        raise PilotError("HOST_LOCAL_CONFIG_REQUIRED")
    resolved_config = config_path.resolve()
    resolved_install = installed_dir.resolve()
    if _is_within(resolved_config, resolved_install):
        raise PilotError("HOST_LOCAL_CONFIG_MUST_BE_OUTSIDE_INSTALL")

    payload = _load_json_object(config_path.read_text(encoding="utf-8"), label="CONFIG")
    if payload.get("enabled") is not True:
        raise PilotError("MONITORING_MUST_BE_ENABLED")
    if payload.get("allow_real_network") is not True:
        raise PilotError("REAL_NETWORK_MUST_BE_EXPLICITLY_ALLOWED")
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        raise PilotError("POLICY_REQUIRED")
    for key, expected in _REQUIRED_POLICY.items():
        if policy.get(key) != expected:
            raise PilotError(f"UNSAFE_POLICY_{key.upper()}")
    assets = payload.get("assets")
    if not isinstance(assets, list) or not assets:
        raise PilotError("APPROVED_ASSETS_REQUIRED")
    if not any(isinstance(asset, dict) and asset.get("enabled", True) is True for asset in assets):
        raise PilotError("ENABLED_APPROVED_ASSET_REQUIRED")
    return payload


def write_ephemeral_runtime_config(payload: dict[str, Any], directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    derived = dict(payload)
    derived["database_path"] = str((directory / "monitoring.db").resolve())
    runtime_config = directory / "runtime-config.json"
    runtime_config.write_text(json.dumps(derived, sort_keys=True) + "\n", encoding="utf-8")
    runtime_config.chmod(0o600)
    return runtime_config


def verify_installed_sha(installed_dir: Path, expected_sha: str) -> str:
    expected = str(expected_sha or "").strip().lower()
    if len(expected) != 40 or any(ch not in "0123456789abcdef" for ch in expected):
        raise PilotError("EXPECTED_SHA_INVALID")
    proc = subprocess.run(
        ["git", "-C", str(installed_dir), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise PilotError("INSTALLED_SHA_UNAVAILABLE")
    installed = proc.stdout.strip().lower()
    if installed != expected:
        raise PilotError("INSTALLED_SHA_MISMATCH")
    return installed


def _run_security_cli(security_bin: Path, config_path: Path, command: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        [str(security_bin), "--config", str(config_path), *command],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise PilotError("SECURITY_MONITOR_COMMAND_FAILED")
    return _load_json_object(proc.stdout, label="SECURITY_MONITOR_OUTPUT")


def validate_installed_runtime(security_bin: Path, config_path: Path) -> dict[str, Any]:
    if security_bin.is_symlink() or not security_bin.is_file() or not os.access(security_bin, os.X_OK):
        raise PilotError("INSTALLED_SECURITY_MONITOR_REQUIRED")
    summary = _run_security_cli(security_bin, config_path, ["validate-config"])
    if summary.get("enabled") is not True:
        raise PilotError("INSTALLED_RUNTIME_MONITORING_NOT_ENABLED")
    if summary.get("allow_real_network") is not True:
        raise PilotError("INSTALLED_RUNTIME_NETWORK_NOT_ALLOWED")
    if summary.get("contains_raw_credentials") is not False:
        raise PilotError("INSTALLED_RUNTIME_RAW_CREDENTIAL_BOUNDARY_FAILED")
    if int(summary.get("enabled_asset_count", 0)) < 1:
        raise PilotError("INSTALLED_RUNTIME_NO_ENABLED_ASSETS")
    return summary


def sanitize_run_receipt(
    run_payload: dict[str, Any],
    *,
    target_sha: str,
    config_fingerprint: str,
    policy_fingerprint: str,
) -> dict[str, Any]:
    failure_codes = run_payload.get("failure_codes")
    if not isinstance(failure_codes, list):
        failure_codes = []
    expected_assets = int(run_payload.get("expected_assets", 0))
    observed_assets = int(run_payload.get("observed_assets", 0))
    coverage_pct = float(run_payload.get("coverage_pct", 0.0))
    status = str(run_payload.get("status", "unknown"))
    accepted = (
        status == "completed"
        and expected_assets > 0
        and observed_assets == expected_assets
        and coverage_pct == 100.0
        and not failure_codes
    )
    run_id = str(run_payload.get("run_id", ""))
    return {
        "schema": PILOT_SCHEMA,
        "target_sha": target_sha,
        "config_fingerprint": config_fingerprint,
        "policy_fingerprint": policy_fingerprint,
        "run_id_fingerprint": _sha256_bytes(run_id.encode("utf-8")) if run_id else None,
        "status": status,
        "expected_assets": expected_assets,
        "observed_assets": observed_assets,
        "coverage_pct": coverage_pct,
        "failure_count": len(failure_codes),
        "readonly_collector_invoked": True,
        "fresh_ephemeral_store": True,
        "persistent_monitoring_store_modified": False,
        "real_network_authorized": True,
        "active_liveness_allowed": False,
        "packet_capture_executed": False,
        "network_mutation_executed": False,
        "remediation_executed": False,
        "raw_config_included": False,
        "raw_failure_codes_included": False,
        "result": "PASS" if accepted else "FAIL",
    }


def _failure_receipt(*, target_sha: str, reason_code: str) -> dict[str, Any]:
    return {
        "schema": PILOT_SCHEMA,
        "target_sha": target_sha,
        "result": "FAIL",
        "reason_code": reason_code,
        "readonly_collector_invoked": False,
        "fresh_ephemeral_store": False,
        "persistent_monitoring_store_modified": False,
        "packet_capture_executed": False,
        "network_mutation_executed": False,
        "remediation_executed": False,
        "raw_config_included": False,
    }


def _write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_pilot(*, config_path: Path, installed_dir: Path, expected_sha: str, confirmation: str) -> dict[str, Any]:
    if confirmation != CONFIRMATION:
        raise PilotError("EXPLICIT_CONFIRMATION_REQUIRED")
    host_payload = validate_host_local_config(config_path, installed_dir)
    installed_sha = verify_installed_sha(installed_dir, expected_sha)
    security_bin = installed_dir / ".venv" / "bin" / "workspace-security-monitor"
    config_fingerprint = _sha256_bytes(config_path.read_bytes())

    # Each physical pilot gets a clean local DB so an already-finalized hourly slot
    # can never be replayed as evidence for a new exact-head execution.
    with TemporaryDirectory(prefix="workspace-security-pilot-") as temp_dir:
        runtime_config = write_ephemeral_runtime_config(host_payload, Path(temp_dir))
        runtime_summary = validate_installed_runtime(security_bin, runtime_config)
        run_payload = _run_security_cli(security_bin, runtime_config, ["run-hourly", "--execute-readonly"])

    return sanitize_run_receipt(
        run_payload,
        target_sha=installed_sha,
        config_fingerprint=config_fingerprint,
        policy_fingerprint=str(runtime_summary.get("policy_fingerprint", "")),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the explicit, read-only physical security monitoring pilot.")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--installed-dir", required=True, type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target_sha = str(args.expected_sha or "").strip().lower()
    try:
        receipt = run_pilot(
            config_path=args.config,
            installed_dir=args.installed_dir,
            expected_sha=target_sha,
            confirmation=args.confirmation,
        )
    except PilotError as exc:
        _write_receipt(args.output, _failure_receipt(target_sha=target_sha, reason_code=str(exc)))
        return 2
    _write_receipt(args.output, receipt)
    return 0 if receipt["result"] == "PASS" else 3


if __name__ == "__main__":
    raise SystemExit(main())
