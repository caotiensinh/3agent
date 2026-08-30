from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import AssetInventoryRecord, MonitoringContractError, SecretReference
from .policy import MonitoringPolicy

_FORBIDDEN_SECRET_KEYS = {
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
_TOP_LEVEL_KEYS = {"enabled", "allow_real_network", "database_path", "policy", "assets"}
_ASSET_KEYS = {
    "asset_id",
    "role",
    "management_host",
    "collector_capabilities",
    "allowed_tcp_ports",
    "data_class",
    "enabled",
    "credential_ref",
}
_POLICY_KEYS = {
    "profile_id",
    "network_scope",
    "read_only",
    "max_workers",
    "timeout_seconds",
    "max_retries",
    "max_catch_up_runs",
    "allowed_capabilities",
}


def _reject_secret_fields(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().strip()
            if normalized in _FORBIDDEN_SECRET_KEYS:
                raise MonitoringContractError(f"raw secret field is forbidden: {path}.{key}")
            _reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, f"{path}[{index}]")


@dataclass(frozen=True)
class MonitoringRuntimeConfig:
    enabled: bool
    allow_real_network: bool
    database_path: Path
    policy: MonitoringPolicy
    assets: tuple[AssetInventoryRecord, ...]

    def validate(self) -> "MonitoringRuntimeConfig":
        if not self.database_path.is_absolute():
            raise MonitoringContractError("database_path must be absolute")
        self.policy.validate()
        asset_ids: set[str] = set()
        for asset in self.assets:
            asset.validate()
            if asset.asset_id in asset_ids:
                raise MonitoringContractError(f"duplicate asset_id: {asset.asset_id}")
            asset_ids.add(asset.asset_id)
        return self


def load_runtime_config(path: str | Path) -> MonitoringRuntimeConfig:
    config_path = Path(path)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise MonitoringContractError("monitoring config must be a JSON object")
    _reject_secret_fields(payload)
    unknown_top = set(payload) - _TOP_LEVEL_KEYS
    if unknown_top:
        raise MonitoringContractError(f"unknown monitoring config keys: {sorted(unknown_top)}")

    raw_policy = payload.get("policy") or {}
    if not isinstance(raw_policy, dict):
        raise MonitoringContractError("policy must be an object")
    unknown_policy = set(raw_policy) - _POLICY_KEYS
    if unknown_policy:
        raise MonitoringContractError(f"unknown monitoring policy keys: {sorted(unknown_policy)}")
    if "allowed_capabilities" in raw_policy:
        raw_policy = dict(raw_policy)
        raw_policy["allowed_capabilities"] = tuple(raw_policy["allowed_capabilities"])
    policy = MonitoringPolicy(**raw_policy).validate()

    raw_assets = payload.get("assets") or []
    if not isinstance(raw_assets, list):
        raise MonitoringContractError("assets must be an array")
    assets: list[AssetInventoryRecord] = []
    for raw in raw_assets:
        if not isinstance(raw, dict):
            raise MonitoringContractError("each asset must be an object")
        unknown_asset = set(raw) - _ASSET_KEYS
        if unknown_asset:
            raise MonitoringContractError(f"unknown asset keys: {sorted(unknown_asset)}")
        credential = SecretReference(raw["credential_ref"]) if raw.get("credential_ref") else None
        assets.append(
            AssetInventoryRecord(
                asset_id=raw.get("asset_id", ""),
                role=raw.get("role", ""),
                management_host=raw.get("management_host", ""),
                collector_capabilities=tuple(raw.get("collector_capabilities") or ()),
                allowed_tcp_ports=tuple(raw.get("allowed_tcp_ports") or ()),
                data_class=raw.get("data_class", "confidential"),
                enabled=bool(raw.get("enabled", True)),
                credential_ref=credential,
            ).validate()
        )

    database_path = Path(str(payload.get("database_path") or ""))
    return MonitoringRuntimeConfig(
        enabled=bool(payload.get("enabled", False)),
        allow_real_network=bool(payload.get("allow_real_network", False)),
        database_path=database_path,
        policy=policy,
        assets=tuple(assets),
    ).validate()
