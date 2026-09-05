from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .contracts import APPROVED_DATA_CLASSES, COLLECTOR_CAPABILITIES
from .dispatch import DefaultCollectorDispatcher
from .hourly import HourlyMonitoringRunner
from .policy import MonitoringPolicyEngine
from .readiness import evaluate_monitoring_readiness
from .runtime_config import MonitoringRuntimeConfig, load_runtime_config
from .snmp_backend import FileSecretResolver, PySnmpV3Backend
from .storage import MonitoringStore
from .ui_read_model import SecurityMonitoringUIReadModel

TOKYO = ZoneInfo("Asia/Tokyo")
ASSET_INTELLIGENCE_SUMMARY_SCHEMA = "workspace-security-monitoring/asset-intelligence-summary-v1"
RECENT_EVIDENCE_SUMMARY_SCHEMA = "workspace-security-monitoring/recent-evidence-summary-v1"
RECENT_EVIDENCE_SAMPLE_LIMIT = 100


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


def safe_asset_intelligence_summary(config: MonitoringRuntimeConfig) -> dict[str, object]:
    """Return privacy-safe inventory intelligence without exposing asset addressing.

    The authoritative configuration is the only input. This function does not read the
    monitoring database, resolve credentials, probe targets, execute collectors, capture
    packets, or perform remediation. Only aggregate counts over constrained contract
    enums are returned.
    """

    assets = tuple(config.assets)
    enabled_assets = tuple(asset for asset in assets if asset.enabled)
    capability_counts = {
        capability: sum(
            1
            for asset in enabled_assets
            if capability in asset.collector_capabilities
        )
        for capability in sorted(COLLECTOR_CAPABILITIES)
    }
    data_class_counts = {
        data_class: sum(
            1 for asset in enabled_assets if asset.data_class == data_class
        )
        for data_class in sorted(APPROVED_DATA_CLASSES)
    }
    return {
        "schema_version": ASSET_INTELLIGENCE_SUMMARY_SCHEMA,
        "count_scope": "enabled_assets",
        "asset_count": len(assets),
        "enabled_asset_count": len(enabled_assets),
        "disabled_asset_count": len(assets) - len(enabled_assets),
        "unique_role_count": len({asset.role for asset in enabled_assets}),
        "capability_counts": {
            key: value for key, value in capability_counts.items() if value > 0
        },
        "data_class_counts": {
            key: value for key, value in data_class_counts.items() if value > 0
        },
        "credential_ref_asset_count": sum(
            1 for asset in enabled_assets if asset.credential_ref is not None
        ),
        "explicit_tcp_port_binding_count": sum(
            len(asset.allowed_tcp_ports) for asset in enabled_assets
        ),
        "contains_raw_credentials": False,
        "authority": {
            "aggregate_only": True,
            "config_is_authoritative": True,
            "asset_ids_exposed": False,
            "management_hosts_exposed": False,
            "credential_refs_exposed": False,
            "allowed_tcp_ports_exposed": False,
            "database_write": False,
            "network_execution": False,
            "collector_execution": False,
            "packet_capture_execution": False,
            "remediation_execution": False,
        },
    }


def _read_model_items(payload: dict[str, object]) -> list[dict[str, object]]:
    items = payload.get("items")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)][
        :RECENT_EVIDENCE_SAMPLE_LIMIT
    ]


def safe_recent_evidence_summary(config: MonitoringRuntimeConfig) -> dict[str, object]:
    """Return a bounded privacy-safe projection of recent monitoring evidence.

    Detailed UI read-model rows may contain internal identifiers and evidence references.
    This service projection deliberately reduces those rows to counts before returning to
    user-facing adapters. It never writes the monitoring database and never triggers
    network, collector, packet-capture, credential, or remediation execution.
    """

    read_model = SecurityMonitoringUIReadModel(config, config_state="configured")
    overview = read_model.summary()
    admin = read_model.admin_status()
    observations = _read_model_items(
        read_model.network(limit=RECENT_EVIDENCE_SAMPLE_LIMIT, offset=0)
    )
    events = _read_model_items(
        read_model.events(limit=RECENT_EVIDENCE_SAMPLE_LIMIT, offset=0)
    )
    findings = _read_model_items(
        read_model.findings(limit=RECENT_EVIDENCE_SAMPLE_LIMIT, offset=0)
    )
    reports = _read_model_items(
        read_model.reports(limit=RECENT_EVIDENCE_SAMPLE_LIMIT, offset=0)
    )

    raw_latest = overview.get("latest_hourly")
    latest_hourly = None
    if isinstance(raw_latest, dict):
        latest_hourly = {
            key: raw_latest.get(key)
            for key in (
                "status",
                "coverage_pct",
                "expected_assets",
                "observed_assets",
                "observed_at",
                "age_seconds",
            )
        }

    raw_reasons = overview.get("reason_codes")
    reason_codes = (
        [str(item)[:96] for item in raw_reasons[:16]]
        if isinstance(raw_reasons, list)
        else []
    )
    health = overview.get("health")

    return {
        "schema_version": RECENT_EVIDENCE_SUMMARY_SCHEMA,
        "count_scope": "recent_bounded_records",
        "max_records_per_stream": RECENT_EVIDENCE_SAMPLE_LIMIT,
        "database_available": admin.get("database_available") is True,
        "health": str(health)[:64] if health is not None else "unknown",
        "reason_codes": reason_codes,
        "observation_sample_count": len(observations),
        "observation_evidence_linked_count": sum(
            1 for item in observations if bool(item.get("evidence_ref"))
        ),
        "event_sample_count": len(events),
        "event_evidence_linked_count": sum(
            1 for item in events if bool(item.get("evidence_ref"))
        ),
        "finding_sample_count": len(findings),
        "finding_evidence_linked_count": sum(
            1
            for item in findings
            if isinstance(item.get("evidence_refs"), list)
            and bool(item.get("evidence_refs"))
        ),
        "report_sample_count": len(reports),
        "open_finding_count": int(overview.get("open_finding_count") or 0),
        "high_critical_count": int(overview.get("high_critical_count") or 0),
        "latest_hourly": latest_hourly,
        "contains_raw_evidence": False,
        "contains_raw_credentials": False,
        "authority": {
            "aggregate_only": True,
            "database_read_only": True,
            "raw_evidence_exposed": False,
            "asset_ids_exposed": False,
            "source_ids_exposed": False,
            "finding_ids_exposed": False,
            "evidence_refs_exposed": False,
            "bundle_refs_exposed": False,
            "database_write": False,
            "network_execution": False,
            "collector_execution": False,
            "packet_capture_execution": False,
            "remediation_execution": False,
        },
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

    def asset_intelligence(self) -> dict[str, object]:
        return safe_asset_intelligence_summary(self.load_config())

    def evidence_summary(self) -> dict[str, object]:
        return safe_recent_evidence_summary(self.load_config())

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
