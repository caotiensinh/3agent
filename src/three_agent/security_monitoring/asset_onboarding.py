from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import (
    AssetInventoryRecord,
    MonitoringContractError,
    SecretReference,
    sha256_fingerprint,
)
from .ui_config_v2 import SecurityMonitoringUIConfigManagerV2

ASSET_ONBOARDING_SCHEMA = "workspace-security-monitoring/asset-onboarding-v1"
MAX_APPROVED_ASSETS = 256
_ALLOWED_ASSET_FIELDS = frozenset(
    {
        "asset_id",
        "role",
        "management_host",
        "collector_capabilities",
        "allowed_tcp_ports",
        "data_class",
        "enabled",
        "credential_ref",
    }
)
_FORBIDDEN_SECRET_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "community",
        "community_string",
        "auth_key",
        "priv_key",
        "token",
        "secret",
        "api_key",
    }
)


class SecurityAssetOnboardingConflict(RuntimeError):
    """The caller attempted to mutate a stale configuration snapshot."""


@dataclass(frozen=True)
class ApprovedAssetMutation:
    action: str
    asset_id: str
    config_fingerprint: str
    asset_count: int
    enabled_asset_count: int
    confirmation_required: bool
    confirmation_reasons: tuple[str, ...]
    network_executed: bool = False
    schema_version: str = ASSET_ONBOARDING_SCHEMA

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "action": self.action,
            "asset_id": self.asset_id,
            "config_fingerprint": self.config_fingerprint,
            "asset_count": self.asset_count,
            "enabled_asset_count": self.enabled_asset_count,
            "confirmation_required": self.confirmation_required,
            "confirmation_reasons": list(self.confirmation_reasons),
            "network_executed": self.network_executed,
        }


def _normalize_asset(raw: Any) -> tuple[AssetInventoryRecord, dict[str, object]]:
    if not isinstance(raw, dict):
        raise MonitoringContractError("approved asset must be an object")
    normalized_keys = {str(key).strip().lower() for key in raw}
    forbidden = sorted(normalized_keys & _FORBIDDEN_SECRET_FIELDS)
    if forbidden:
        raise MonitoringContractError(f"raw secret fields are forbidden: {forbidden}")
    unknown = set(raw) - _ALLOWED_ASSET_FIELDS
    if unknown:
        raise MonitoringContractError(f"unknown approved asset keys: {sorted(unknown)}")

    raw_caps = raw.get("collector_capabilities", [])
    if not isinstance(raw_caps, (list, tuple)):
        raise MonitoringContractError("collector_capabilities must be an array")
    raw_ports = raw.get("allowed_tcp_ports", [])
    if not isinstance(raw_ports, (list, tuple)):
        raise MonitoringContractError("allowed_tcp_ports must be an array")
    raw_enabled = raw.get("enabled", True)
    if not isinstance(raw_enabled, bool):
        raise MonitoringContractError("enabled must be a boolean")

    credential_raw = raw.get("credential_ref")
    if credential_raw is not None and not isinstance(credential_raw, str):
        raise MonitoringContractError("credential_ref must be an opaque secret-ref string")
    credential = SecretReference(credential_raw).validate() if credential_raw else None

    record = AssetInventoryRecord(
        asset_id=str(raw.get("asset_id") or ""),
        role=str(raw.get("role") or ""),
        management_host=str(raw.get("management_host") or ""),
        collector_capabilities=tuple(str(item) for item in raw_caps),
        allowed_tcp_ports=tuple(int(item) for item in raw_ports),
        data_class=str(raw.get("data_class") or "confidential"),
        enabled=raw_enabled,
        credential_ref=credential,
    ).validate()
    payload: dict[str, object] = {
        "asset_id": record.asset_id,
        "role": record.role,
        "management_host": record.management_host,
        "collector_capabilities": list(record.collector_capabilities),
        "allowed_tcp_ports": list(record.allowed_tcp_ports),
        "data_class": record.data_class,
        "enabled": record.enabled,
    }
    if record.credential_ref is not None:
        payload["credential_ref"] = record.credential_ref.handle
    return record, payload


class SecurityMonitoringAssetOnboarding:
    """Typed admin-only asset mutations over the production config validator.

    This boundary edits approved inventory only. It never discovers targets, probes a
    host, resolves a credential, starts a collector, captures packets, opens a socket,
    restarts a service, or performs remediation. Every write is delegated to the
    hardened V2 configuration manager so strong-confirmation and metadata-only audit
    semantics remain authoritative.
    """

    def __init__(self, manager: SecurityMonitoringUIConfigManagerV2) -> None:
        self.manager = manager

    @classmethod
    def from_environment(cls) -> "SecurityMonitoringAssetOnboarding":
        return cls(SecurityMonitoringUIConfigManagerV2.from_environment())

    def snapshot(self) -> dict[str, object]:
        envelope = self.manager.get()
        config = dict(envelope["config"])
        assets = config.get("assets") or []
        if not isinstance(assets, list):
            raise MonitoringContractError("assets must be an array")
        return {
            "schema_version": ASSET_ONBOARDING_SCHEMA,
            "config_fingerprint": sha256_fingerprint(config),
            "assets": assets,
            "asset_count": len(assets),
            "enabled_asset_count": sum(
                1 for item in assets if isinstance(item, dict) and item.get("enabled", True) is True
            ),
            "authority": {
                "admin_required": True,
                "approved_inventory_only": True,
                "raw_secrets_accepted": False,
                "network_executed": False,
                "service_restart_executed": False,
                "remediation_executed": False,
            },
        }

    def upsert(
        self,
        raw_asset: Any,
        *,
        actor_id: str,
        expected_config_fingerprint: str,
        confirmation: str = "",
    ) -> ApprovedAssetMutation:
        record, normalized = _normalize_asset(raw_asset)
        envelope, config = self._mutable_config(expected_config_fingerprint)
        assets = config.get("assets") or []
        if not isinstance(assets, list):
            raise MonitoringContractError("assets must be an array")

        output: list[dict[str, object]] = []
        found = False
        for item in assets:
            if not isinstance(item, dict):
                raise MonitoringContractError("each asset must be an object")
            if str(item.get("asset_id") or "") == record.asset_id:
                if found:
                    raise MonitoringContractError(f"duplicate asset_id: {record.asset_id}")
                output.append(normalized)
                found = True
            else:
                output.append(dict(item))
        if not found:
            if len(output) >= MAX_APPROVED_ASSETS:
                raise MonitoringContractError("approved asset limit exceeded")
            output.append(normalized)
        config["assets"] = output
        result = self.manager.save(
            config,
            actor_id=actor_id,
            confirmation=confirmation,
        )
        return self._result(
            action="updated" if found else "created",
            asset_id=record.asset_id,
            result=result,
        )

    def disable(
        self,
        asset_id: str,
        *,
        actor_id: str,
        expected_config_fingerprint: str,
        confirmation: str = "",
    ) -> ApprovedAssetMutation:
        wanted = str(asset_id or "").strip()
        if not wanted:
            raise MonitoringContractError("asset_id is required")
        _envelope, config = self._mutable_config(expected_config_fingerprint)
        assets = config.get("assets") or []
        if not isinstance(assets, list):
            raise MonitoringContractError("assets must be an array")

        output: list[dict[str, object]] = []
        found = False
        for item in assets:
            if not isinstance(item, dict):
                raise MonitoringContractError("each asset must be an object")
            current = dict(item)
            if str(current.get("asset_id") or "") == wanted:
                if found:
                    raise MonitoringContractError(f"duplicate asset_id: {wanted}")
                current["enabled"] = False
                found = True
            output.append(current)
        if not found:
            raise MonitoringContractError("approved asset does not exist")
        config["assets"] = output
        result = self.manager.save(
            config,
            actor_id=actor_id,
            confirmation=confirmation,
        )
        return self._result(action="disabled", asset_id=wanted, result=result)

    def _mutable_config(
        self, expected_config_fingerprint: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        envelope = self.manager.get()
        config = dict(envelope["config"])
        current = sha256_fingerprint(config)
        expected = str(expected_config_fingerprint or "").strip()
        if expected != current:
            raise SecurityAssetOnboardingConflict("SECURITY_ASSET_CONFIG_STALE")
        return envelope, config

    def _result(
        self,
        *,
        action: str,
        asset_id: str,
        result: dict[str, Any],
    ) -> ApprovedAssetMutation:
        current = self.manager.get()
        config = dict(current["config"])
        summary = current.get("summary") or {}
        return ApprovedAssetMutation(
            action=action,
            asset_id=asset_id,
            config_fingerprint=sha256_fingerprint(config),
            asset_count=int(summary.get("asset_count") or 0),
            enabled_asset_count=int(summary.get("enabled_asset_count") or 0),
            confirmation_required=bool(result.get("confirmation_required")),
            confirmation_reasons=tuple(str(item) for item in result.get("confirmation_reasons") or ()),
        )
