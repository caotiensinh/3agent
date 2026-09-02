from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import MonitoringContractError
from .ui_config import (
    CONFIG_SCHEMA,
    SecurityMonitoringUIConfigManager,
    _load_payload,
    _validate_payload,
)

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
