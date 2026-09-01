from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .contracts import MonitoringContractError
from .runtime_config import load_runtime_config

MONITORING_CONFIG_ENV = "WORKSPACE_SECURITY_MONITORING_CONFIG"
REAL_NETWORK_CONFIRMATION = "ENABLE_APPROVED_REAL_NETWORK_MONITORING"
CONFIG_SCHEMA = "workspace-security-monitoring/config-center-v1"
AUDIT_SCHEMA = "workspace-security-monitoring/config-audit-v1"
MAX_CONFIG_BYTES = 64 * 1024
MAX_AUDIT_RESULTS = 200

_DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "allow_real_network": False,
    "database_path": "/var/lib/workspace-monitor/monitoring.sqlite3",
    "secret_directory": "/etc/workspace-monitor/secrets",
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


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MonitoringContractError("monitoring configuration must be JSON serializable") from exc
    if len(encoded) > MAX_CONFIG_BYTES:
        raise MonitoringContractError("monitoring configuration exceeds bounded size")
    return encoded


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _editable_default() -> dict[str, Any]:
    return json.loads(json.dumps(_DEFAULT_CONFIG))


def _top_level_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    keys = sorted(set(before) | set(after))
    return [key for key in keys if before.get(key) != after.get(key)]


def _requires_network_confirmation(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    new_real = bool(after.get("allow_real_network", False))
    old_real = bool(before.get("allow_real_network", False))
    old_policy = before.get("policy") if isinstance(before.get("policy"), dict) else {}
    new_policy = after.get("policy") if isinstance(after.get("policy"), dict) else {}
    active_enabled = bool(new_policy.get("allow_active_liveness", False)) and not bool(old_policy.get("allow_active_liveness", False))
    inventory_changed = before.get("assets", []) != after.get("assets", [])
    policy_changed = old_policy != new_policy
    return active_enabled or (new_real and (not old_real or inventory_changed or policy_changed))


class SecurityConfigurationStore:
    """Admin-only atomic configuration store; saving never executes network activity."""

    def __init__(self, path: Path | None, *, state: str, reason_code: str | None = None) -> None:
        self.path = path
        self.state = state
        self.reason_code = reason_code

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> "SecurityConfigurationStore":
        source = os.environ if env is None else env
        raw = str(source.get(MONITORING_CONFIG_ENV) or "").strip()
        if not raw:
            return cls(None, state="not_configured", reason_code="MONITORING_CONFIG_PATH_NOT_SET")
        path = Path(raw)
        if not path.is_absolute() or path.is_symlink():
            return cls(None, state="configuration_error", reason_code="MONITORING_CONFIG_PATH_UNSAFE")
        parent = path.parent
        if not parent.exists() or not parent.is_dir() or parent.is_symlink():
            return cls(path, state="configuration_error", reason_code="MONITORING_CONFIG_PARENT_UNAVAILABLE")
        if path.exists() and not path.is_file():
            return cls(path, state="configuration_error", reason_code="MONITORING_CONFIG_NOT_FILE")
        return cls(path, state="configured" if path.is_file() else "not_created")

    @property
    def audit_path(self) -> Path | None:
        if self.path is None:
            return None
        return self.path.with_name(self.path.name + ".audit.jsonl")

    def _require_writable_path(self) -> Path:
        if self.path is None:
            raise MonitoringContractError("MONITORING_CONFIG_PATH_NOT_SET")
        path = self.path
        if not path.is_absolute() or path.is_symlink():
            raise MonitoringContractError("MONITORING_CONFIG_PATH_UNSAFE")
        parent = path.parent
        if not parent.exists() or not parent.is_dir() or parent.is_symlink():
            raise MonitoringContractError("MONITORING_CONFIG_PARENT_UNAVAILABLE")
        if path.exists() and not path.is_file():
            raise MonitoringContractError("MONITORING_CONFIG_NOT_FILE")
        return path

    def _load_existing_payload(self) -> dict[str, Any]:
        path = self._require_writable_path()
        if not path.is_file():
            return {}
        load_runtime_config(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise MonitoringContractError("monitoring config must be a JSON object")
        return payload

    def public_state(self) -> dict[str, Any]:
        base = {
            "schema_version": CONFIG_SCHEMA,
            "config_state": self.state,
            "reason_code": self.reason_code,
            "writable": False,
            "raw_secrets_accepted": False,
            "save_executes_network": False,
            "save_restarts_services": False,
            "real_network_confirmation": REAL_NETWORK_CONFIRMATION,
            "config": _editable_default(),
            "config_fingerprint": None,
        }
        if self.path is None:
            return base
        try:
            path = self._require_writable_path()
            base["writable"] = True
            if path.is_file():
                payload = self._load_existing_payload()
                base["config_state"] = "configured"
                base["reason_code"] = None
                base["config"] = payload
                base["config_fingerprint"] = _fingerprint(payload)
            else:
                base["config_state"] = "not_created"
                base["reason_code"] = "MONITORING_CONFIG_NOT_CREATED"
        except (OSError, json.JSONDecodeError, MonitoringContractError):
            base["config_state"] = "configuration_error"
            base["reason_code"] = "MONITORING_CONFIG_INVALID_OR_UNAVAILABLE"
        return base

    def _append_audit(self, record: Mapping[str, Any]) -> None:
        path = self.audit_path
        if path is None:
            raise MonitoringContractError("MONITORING_CONFIG_PATH_NOT_SET")
        if path.is_symlink():
            raise MonitoringContractError("CONFIG_AUDIT_PATH_UNSAFE")
        encoded = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _restore(self, path: Path, previous: bytes | None) -> None:
        if previous is None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            return
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.rollback.", dir=str(path.parent))
        temp = Path(name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(previous)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def save(self, payload: Mapping[str, Any], *, actor_user_id: str, confirmation: str = "") -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise MonitoringContractError("monitoring configuration must be an object")
        path = self._require_writable_path()
        candidate = dict(payload)
        canonical = _canonical_bytes(candidate)
        try:
            before = self._load_existing_payload()
        except (OSError, json.JSONDecodeError, MonitoringContractError):
            before = {}
        if _requires_network_confirmation(before, candidate) and confirmation != REAL_NETWORK_CONFIRMATION:
            raise PermissionError("REAL_NETWORK_MONITORING_CONFIRMATION_REQUIRED")
        previous_bytes = path.read_bytes() if path.is_file() else None
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        temp = Path(name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                pretty = json.dumps(candidate, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False).encode("utf-8") + b"\n"
                handle.write(pretty)
                handle.flush()
                os.fsync(handle.fileno())
            load_runtime_config(temp)
            old_fingerprint = _fingerprint(before) if before else None
            new_fingerprint = "sha256:" + hashlib.sha256(canonical).hexdigest()
            audit_record = {
                "schema_version": AUDIT_SCHEMA,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "actor_user_id": str(actor_user_id)[:160],
                "action": "security_monitoring_config_saved",
                "changed_fields": _top_level_changes(before, candidate),
                "previous_fingerprint": old_fingerprint,
                "new_fingerprint": new_fingerprint,
                "enabled": bool(candidate.get("enabled", False)),
                "allow_real_network": bool(candidate.get("allow_real_network", False)),
                "allow_active_liveness": bool((candidate.get("policy") or {}).get("allow_active_liveness", False) if isinstance(candidate.get("policy"), dict) else False),
                "asset_count": len(candidate.get("assets") or []) if isinstance(candidate.get("assets"), list) else 0,
                "network_confirmation_required": _requires_network_confirmation(before, candidate),
                "raw_secret_material_recorded": False,
            }
            os.replace(temp, path)
            try:
                os.chmod(path, 0o600)
                self._append_audit(audit_record)
            except Exception:
                self._restore(path, previous_bytes)
                raise
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
        self.state = "configured"
        self.reason_code = None
        return self.public_state()

    def audit(self, *, limit: int = 50) -> dict[str, Any]:
        try:
            count = int(limit)
        except (TypeError, ValueError) as exc:
            raise MonitoringContractError("audit limit must be integer") from exc
        if not 1 <= count <= MAX_AUDIT_RESULTS:
            raise MonitoringContractError(f"audit limit must be within 1..{MAX_AUDIT_RESULTS}")
        path = self.audit_path
        if path is None or not path.is_file():
            return {"schema_version": AUDIT_SCHEMA, "items": []}
        if path.is_symlink():
            raise MonitoringContractError("CONFIG_AUDIT_PATH_UNSAFE")
        max_tail_bytes = 256 * 1024
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - max_tail_bytes)
            handle.seek(start)
            raw = handle.read(max_tail_bytes)
        lines = raw.decode("utf-8", errors="replace").splitlines()
        if start > 0 and lines:
            lines = lines[1:]
        items: list[dict[str, Any]] = []
        for line in reversed(lines[-count:]):
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                items.append(item)
        return {"schema_version": AUDIT_SCHEMA, "items": items}
