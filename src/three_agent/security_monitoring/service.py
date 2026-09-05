from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .dispatch import DefaultCollectorDispatcher
from .hourly import HourlyMonitoringRunner
from .policy import MonitoringPolicyEngine
from .readiness import evaluate_monitoring_readiness
from .runtime_config import MonitoringRuntimeConfig, load_runtime_config
from .snmp_backend import FileSecretResolver, PySnmpV3Backend
from .storage import MonitoringStore

TOKYO = ZoneInfo("Asia/Tokyo")


def sync_inventory(config: MonitoringRuntimeConfig, store: MonitoringStore) -> None:
    """Make configured assets authoritative without silently trusting stale DB state."""
    store.initialize()
    with store.connect() as conn:
        conn.execute("UPDATE approved_assets SET enabled=0")
    for asset in config.assets:
        store.upsert_asset(asset)


def safe_config_summary(config: MonitoringRuntimeConfig) -> dict[str, object]:
    snmp_assets = sum(
        1
        for asset in config.assets
        if "snmpv3_read" in asset.collector_capabilities and asset.enabled
    )
    return {
        "enabled": config.enabled,
        "allow_real_network": config.allow_real_network,
        "profile_id": config.policy.profile_id,
        "policy_fingerprint": config.policy.fingerprint,
        "asset_count": len(config.assets),
        "enabled_asset_count": sum(1 for asset in config.assets if asset.enabled),
        "snmpv3_asset_count": snmp_assets,
        "snmpv3_secret_boundary_configured": bool(config.secret_directory),
        "database_parent": str(config.database_path.parent),
        "contains_raw_credentials": False,
    }


def build_snmp_backend(config: MonitoringRuntimeConfig):
    has_snmp_assets = any(
        asset.enabled and "snmpv3_read" in asset.collector_capabilities
        for asset in config.assets
    )
    if not has_snmp_assets or config.secret_directory is None:
        return None
    return PySnmpV3Backend(FileSecretResolver(config.secret_directory))


class SecurityMonitoringService:
    """Shared application service for CLI and local UI monitoring entrypoints.

    The service accepts the configuration path only at construction time. User-facing
    adapters therefore cannot submit arbitrary filesystem paths, targets, credentials,
    shell commands, or collector selectors per request.
    """

    def __init__(self, config_path: Path | str) -> None:
        self.config_path = Path(config_path)

    def load_config(self) -> MonitoringRuntimeConfig:
        return load_runtime_config(self.config_path)

    def summary(self) -> dict[str, object]:
        return safe_config_summary(self.load_config())

    def readiness(self) -> dict[str, object]:
        config = self.load_config()
        return evaluate_monitoring_readiness(
            config,
            config_saved=self.config_path.is_file(),
        )

    def initialize(self) -> dict[str, object]:
        config = self.load_config()
        config.database_path.parent.mkdir(parents=True, exist_ok=True)
        store = MonitoringStore(config.database_path)
        sync_inventory(config, store)
        return {"status": "initialized", **safe_config_summary(config)}

    def run_hourly(self, *, execute_readonly: bool) -> dict[str, object]:
        config = self.load_config()
        if not config.enabled:
            raise RuntimeError("MONITORING_DISABLED")
        if not config.allow_real_network:
            raise RuntimeError("REAL_NETWORK_NOT_ALLOWED_BY_CONFIG")
        if not execute_readonly:
            raise RuntimeError("EXPLICIT_READONLY_EXECUTION_FLAG_REQUIRED")

        readiness = evaluate_monitoring_readiness(
            config,
            config_saved=self.config_path.is_file(),
        )
        if not readiness["ready"]:
            reason_codes = sorted({str(item["code"]) for item in readiness["issues"]})
            raise RuntimeError(f"MONITORING_READINESS_BLOCKED:{','.join(reason_codes)}")

        config.database_path.parent.mkdir(parents=True, exist_ok=True)
        store = MonitoringStore(config.database_path)
        sync_inventory(config, store)
        policy_engine = MonitoringPolicyEngine(config.policy)
        dispatcher = DefaultCollectorDispatcher(
            policy_engine,
            snmp_backend=build_snmp_backend(config),
        )
        runner = HourlyMonitoringRunner(
            store=store,
            policy=config.policy,
            execute_work_item=dispatcher,
        )
        scheduled_at = datetime.now(TOKYO).isoformat()
        receipt = runner.run(scheduled_at=scheduled_at)
        payload = asdict(receipt)
        payload["failure_codes"] = list(receipt.failure_codes)
        return payload
