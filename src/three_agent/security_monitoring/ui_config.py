from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .contracts import MonitoringContractError
from .readiness import evaluate_monitoring_readiness
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
            "mode": "operator-configured" if exists else "safe-default",
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
        if os.name == "posix":
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd, name = tempfile.mkstemp(prefix=".security-monitoring-", suffix=".tmp", dir=self.path.parent)
        temp = Path(name)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            handle = os.fdopen(fd, "wb")
            fd = -1
            with handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
        return {
            "schema_version": CONFIG_SCHEMA,
            "saved": True,
            "mode": "operator-configured",
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
        saved = self.path.is_file() if config_saved is None else config_saved
        return evaluate_monitoring_readiness(config, config_saved=saved)


# Hardened confirmation, audit, and rollback layer for the canonical UI config boundary.
import hashlib
from datetime import datetime, timezone

REAL_NETWORK_CONFIRMATION = "ENABLE_APPROVED_REAL_NETWORK_MONITORING"
AUDIT_SCHEMA = "workspace-security-monitoring/config-audit-v1"
MAX_AUDIT_BYTES = 256 * 1024
MAX_AUDIT_RESULTS = 200


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _active_liveness(payload: dict[str, Any] | None) -> bool:
    if not payload:
        return False
    policy = payload.get("policy")
    return bool(isinstance(policy, dict) and policy.get("allow_active_liveness"))


def _changed_sections(
    previous: dict[str, Any] | None,
    desired: dict[str, Any],
) -> list[str]:
    if previous is None:
        return sorted(desired)
    keys = set(previous) | set(desired)
    return sorted(key for key in keys if previous.get(key) != desired.get(key))


class SecurityMonitoringUIConfigManagerV2(SecurityMonitoringUIConfigManager):
    """Harden the existing UI config manager without adding execution authority.

    The manager validates and stores configuration only. It never starts collectors,
    probes a network, captures packets, restarts services, retrieves secrets, or
    performs remediation.
    """

    @property
    def audit_path(self) -> Path:
        return Path(str(self.path) + ".audit.jsonl")

    def get(self) -> dict[str, Any]:
        payload = super().get()
        authority = payload.setdefault("authority", {})
        authority.update(
            {
                "strong_confirmation_required": True,
                "strong_confirmation_phrase": REAL_NETWORK_CONFIRMATION,
                "configuration_audit": True,
                "save_executes_network": False,
                "save_restarts_services": False,
            }
        )
        return payload

    def _current_payload(self) -> dict[str, Any] | None:
        self._path_safe()
        if not self.path.is_file():
            return None
        try:
            payload = _load_payload(self.path)
            _validate_payload(payload)
            return payload
        except (MonitoringContractError, OSError, ValueError, json.JSONDecodeError):
            # An invalid previous file must not weaken the confirmation gate. A
            # replacement that enables real-network authority is treated as a
            # transition from the safest possible state.
            return None

    def _confirmation_reasons(
        self,
        previous: dict[str, Any] | None,
        desired: dict[str, Any],
    ) -> list[str]:
        reasons: set[str] = set()
        previous_real = bool(previous and previous.get("allow_real_network"))
        desired_real = bool(desired.get("allow_real_network"))
        previous_enabled = bool(previous and previous.get("enabled"))
        desired_enabled = bool(desired.get("enabled"))

        if desired_real and not previous_real:
            reasons.add("real_network_enable")
        if _active_liveness(desired) and not _active_liveness(previous):
            reasons.add("active_liveness_enable")
        if desired_real:
            if previous is None or previous.get("assets") != desired.get("assets"):
                reasons.add("approved_inventory_change")
            if previous is None or previous.get("policy") != desired.get("policy"):
                reasons.add("real_network_policy_change")
            if desired_enabled and not previous_enabled:
                reasons.add("real_network_monitoring_enable")
        return sorted(reasons)

    def save(
        self,
        payload: Any,
        *,
        actor_id: str,
        confirmation: str = "",
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise MonitoringContractError("monitoring config must be a JSON object")

        # Reuse the authoritative production contract before examining transitions.
        config = _validate_payload(payload)
        previous = self._current_payload()
        reasons = self._confirmation_reasons(previous, payload)
        if reasons and str(confirmation or "") != REAL_NETWORK_CONFIRMATION:
            raise PermissionError("REAL_NETWORK_CONFIRMATION_REQUIRED")

        self._path_safe()
        previous_bytes = self.path.read_bytes() if self.path.is_file() else None
        result = super().save(payload)
        record = {
            "schema_version": AUDIT_SCHEMA,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "actor_ref": "sha256:" + hashlib.sha256(str(actor_id).encode("utf-8")).hexdigest()[:24],
            "previous_config_sha256": _fingerprint(previous) if previous is not None else None,
            "config_sha256": _fingerprint(payload),
            "changed_sections": _changed_sections(previous, payload),
            "enabled": bool(config.enabled),
            "allow_real_network": bool(config.allow_real_network),
            "allow_active_liveness": bool(config.policy.allow_active_liveness),
            "asset_count": len(config.assets),
            "policy_fingerprint": config.policy.fingerprint,
            "confirmation_reasons": reasons,
        }
        try:
            self._append_audit(record)
        except (OSError, MonitoringContractError):
            self._restore(previous_bytes)
            raise

        result.update(
            {
                "schema_version": CONFIG_SCHEMA,
                "confirmation_required": bool(reasons),
                "confirmation_reasons": reasons,
                "audit_recorded": True,
                "save_executes_network": False,
                "save_restarts_services": False,
            }
        )
        return result

    def _append_audit(self, record: dict[str, Any]) -> None:
        path = self.audit_path
        if path.exists() and path.is_symlink():
            raise MonitoringContractError("monitoring configuration audit path must not be a symlink")
        line = _canonical_bytes(record) + b"\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "ab", closefd=False) as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(fd)

    def _restore(self, previous_bytes: bytes | None) -> None:
        if previous_bytes is None:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            return
        fd, name = tempfile.mkstemp(
            prefix=".security-monitoring-restore-",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temp = Path(name)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(previous_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def audit(self, *, limit: int = 50) -> dict[str, Any]:
        try:
            size = int(limit)
        except (TypeError, ValueError) as exc:
            raise MonitoringContractError("audit limit must be an integer") from exc
        if not 1 <= size <= MAX_AUDIT_RESULTS:
            raise MonitoringContractError(
                f"audit limit must be within 1..{MAX_AUDIT_RESULTS}"
            )

        path = self.audit_path
        if path.exists() and path.is_symlink():
            raise MonitoringContractError("monitoring configuration audit path must not be a symlink")
        if not path.is_file():
            return {"schema_version": AUDIT_SCHEMA, "items": []}

        file_size = path.stat().st_size
        with path.open("rb") as handle:
            if file_size > MAX_AUDIT_BYTES:
                handle.seek(-MAX_AUDIT_BYTES, os.SEEK_END)
                handle.readline()
            lines = handle.readlines()

        items: list[dict[str, Any]] = []
        for raw in reversed(lines):
            if len(items) >= size:
                break
            try:
                item = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(item, dict) and item.get("schema_version") == AUDIT_SCHEMA:
                items.append(item)
        return {"schema_version": AUDIT_SCHEMA, "items": items}
