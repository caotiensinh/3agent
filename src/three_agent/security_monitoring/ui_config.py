from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .contracts import MonitoringContractError
from .runtime_config import MonitoringRuntimeConfig, load_runtime_config

CONFIG_SCHEMA = "workspace-security-monitoring/ui-config-v1"
ENV_CONFIG = "WORKSPACE_SECURITY_MONITORING_CONFIG"
MAX_CONFIG_BYTES = 256 * 1024


def default_config_path() -> Path:
    return Path.home() / ".config" / "workspace" / "security_monitoring.json"


def resolve_config_path(env: Mapping[str, str] | None = None) -> tuple[Path, str]:
    source = os.environ if env is None else env
    raw = str(source.get(ENV_CONFIG) or "").strip()
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            raise MonitoringContractError(f"{ENV_CONFIG} must be an absolute path")
        return path, "environment"
    return default_config_path(), "workspace_default"


def safe_default_payload(path: Path | None = None) -> dict[str, Any]:
    config_path = path or default_config_path()
    home = config_path.parent
    return {
        "enabled": False,
        "allow_real_network": False,
        "database_path": str((home / "monitoring.sqlite3").resolve()),
        "secret_directory": str((home / "secrets").resolve()),
        "policy": {
            "profile_id": "default",
            "network_scope": "approved_inventory_only",
            "read_only": True,
            "production_safety_profile": "non_disruptive_v1",
            "allow_active_liveness": False,
            "bandwidth_measurement_mode": "counter_only",
            "packet_analysis_mode": "passive_only",
            "max_workers": 4,
            "timeout_seconds": 3.0,
            "max_retries": 1,
            "max_catch_up_runs": 1,
            "allowed_capabilities": ["snmpv3_read", "local_net_read"],
        },
        "assets": [],
    }


def _load_payload(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise MonitoringContractError("monitoring configuration is too large")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise MonitoringContractError("monitoring config must be a JSON object")
    return payload


def _validate_payload(payload: dict[str, Any]) -> MonitoringRuntimeConfig:
    encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise MonitoringContractError("monitoring configuration is too large")
    fd, name = tempfile.mkstemp(prefix="workspace-monitoring-", suffix=".json")
    temp_path = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        return load_runtime_config(temp_path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _config_summary(config: MonitoringRuntimeConfig) -> dict[str, Any]:
    policy = config.policy
    return {
        "enabled": config.enabled,
        "allow_real_network": config.allow_real_network,
        "asset_count": len(config.assets),
        "enabled_asset_count": sum(1 for item in config.assets if item.enabled),
        "policy_fingerprint": policy.fingerprint,
        "safety": {
            "network_scope": policy.network_scope,
            "read_only": policy.read_only,
            "production_safety_profile": policy.production_safety_profile,
            "packet_analysis_mode": policy.packet_analysis_mode,
            "bandwidth_measurement_mode": policy.bandwidth_measurement_mode,
            "allow_active_liveness": policy.allow_active_liveness,
        },
    }


class SecurityMonitoringUIConfigManager:
    """Admin configuration boundary for monitoring.

    This manager only validates and atomically stores the existing monitoring
    contract. It never executes collectors, probes, packet capture, remediation,
    shell commands, or secret retrieval.
    """

    def __init__(self, path: Path, *, path_source: str) -> None:
        if not path.is_absolute():
            raise MonitoringContractError("monitoring config path must be absolute")
        self.path = path
        self.path_source = path_source

    @classmethod
    def from_environment(
        cls, env: Mapping[str, str] | None = None
    ) -> "SecurityMonitoringUIConfigManager":
        path, source = resolve_config_path(env)
        return cls(path, path_source=source)

    def _path_safe(self) -> None:
        if self.path.exists() and self.path.is_symlink():
            raise MonitoringContractError("monitoring config path must not be a symlink")
        parent = self.path.parent
        if parent.exists() and parent.is_symlink():
            raise MonitoringContractError("monitoring config directory must not be a symlink")

    def get(self) -> dict[str, Any]:
        self._path_safe()
        exists = self.path.is_file()
        payload = _load_payload(self.path) if exists else safe_default_payload(self.path)
        config = _validate_payload(payload)
        return {
            "schema_version": CONFIG_SCHEMA,
            "state": "configured" if exists else "safe_default_not_saved",
            "path_source": self.path_source,
            "config_path": str(self.path),
            "config": payload,
            "summary": _config_summary(config),
            "authority": {
                "admin_required": True,
                "collectors_executed": False,
                "packet_capture_executed": False,
                "remediation_executed": False,
                "raw_secrets_accepted": False,
            },
        }

    def validate(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise MonitoringContractError("monitoring config must be a JSON object")
        config = _validate_payload(payload)
        readiness = self._readiness_for(config)
        return {
            "schema_version": CONFIG_SCHEMA,
            "valid": True,
            "summary": _config_summary(config),
            "readiness": readiness,
        }

    def save(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise MonitoringContractError("monitoring config must be a JSON object")
        config = _validate_payload(payload)
        self._path_safe()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd, name = tempfile.mkstemp(prefix=".security-monitoring-", suffix=".tmp", dir=self.path.parent)
        temp = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            os.chmod(self.path, 0o600)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
        return {
            "schema_version": CONFIG_SCHEMA,
            "saved": True,
            "config_path": str(self.path),
            "summary": _config_summary(config),
            "readiness": self._readiness_for(config),
        }

    def readiness(self) -> dict[str, Any]:
        self._path_safe()
        if not self.path.is_file():
            payload = safe_default_payload(self.path)
            config = _validate_payload(payload)
            return self._readiness_for(config, config_saved=False)
        return self._readiness_for(load_runtime_config(self.path), config_saved=True)

    def _readiness_for(
        self, config: MonitoringRuntimeConfig, *, config_saved: bool | None = None
    ) -> dict[str, Any]:
        issues: list[dict[str, str]] = []
        warnings: list[dict[str, str]] = []
        saved = self.path.is_file() if config_saved is None else config_saved
        if not saved:
            issues.append({"code": "CONFIG_NOT_SAVED", "message": "Save configuration before monitoring can run."})
        if not config.enabled:
            warnings.append({"code": "MONITORING_DISABLED", "message": "Monitoring is currently disabled."})
        if config.enabled and not config.allow_real_network:
            issues.append({"code": "REAL_NETWORK_NOT_ALLOWED", "message": "Enable approved real-network reads before running the collector."})
        if not config.assets:
            warnings.append({"code": "NO_ASSETS", "message": "No approved monitoring assets are configured."})
        secret_dir = config.secret_directory
        for asset in config.assets:
            if not asset.enabled:
                continue
            if "snmpv3_read" in asset.collector_capabilities:
                if secret_dir is None:
                    issues.append({"code": "SECRET_DIRECTORY_REQUIRED", "message": f"{asset.asset_id}: SNMPv3 requires a secret directory."})
                    continue
                if asset.credential_ref is None:
                    issues.append({"code": "CREDENTIAL_REF_REQUIRED", "message": f"{asset.asset_id}: SNMPv3 requires an opaque credential reference."})
                    continue
                secret_name = asset.credential_ref.handle.removeprefix("secret-ref:")
                secret_file = secret_dir / secret_name
                if not secret_file.is_file() or secret_file.is_symlink():
                    warnings.append({"code": "SECRET_REF_UNRESOLVED", "message": f"{asset.asset_id}: credential reference is not present in the local secret boundary."})
        return {
            "ready": not issues,
            "config_saved": saved,
            "issues": issues,
            "warnings": warnings,
            "network_test_executed": False,
            "secret_values_read": False,
            "packet_capture_executed": False,
            "remediation_executed": False,
        }
