from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contracts import (
    AssetInventoryRecord,
    CanonicalEvent,
    FindingRecord,
    HourlyRunReceipt,
    ObservationRecord,
    sha256_fingerprint,
)
from .entity_context import EventEntityContext, EventEntityReference
from .entity_context_storage import EventEntityContextStore
from .runtime_config import load_runtime_config
from .storage import MonitoringStore

DEMO_SCHEMA = "workspace-security-monitoring/demo-v1"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _message_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_demo_environment(root: Path | None = None) -> Path:
    """Create a synthetic, network-disabled monitoring environment for UI testing.

    The generated dataset never executes collectors or touches the configured production
    database. Addresses are documentation-only TEST-NET values and sensitive correlation
    entities are stored as typed hashes by the canonical entity-context contract.
    """

    base = root or Path(tempfile.mkdtemp(prefix="workspace-security-demo-"))
    base.mkdir(parents=True, exist_ok=True)
    database_path = (base / "monitoring-demo.sqlite3").resolve()
    config_path = (base / "security-monitoring-demo.json").resolve()

    assets = [
        {
            "asset_id": "demo-router-01",
            "role": "router",
            "management_host": "192.0.2.10",
            "collector_capabilities": ["local_net_read"],
            "allowed_tcp_ports": [],
            "data_class": "internal",
            "enabled": True,
        },
        {
            "asset_id": "demo-switch-01",
            "role": "switch",
            "management_host": "192.0.2.20",
            "collector_capabilities": ["local_net_read"],
            "allowed_tcp_ports": [],
            "data_class": "internal",
            "enabled": True,
        },
        {
            "asset_id": "demo-camera-01",
            "role": "camera",
            "management_host": "192.0.2.30",
            "collector_capabilities": ["local_net_read"],
            "allowed_tcp_ports": [],
            "data_class": "confidential",
            "enabled": True,
        },
        {
            "asset_id": "demo-workstation-01",
            "role": "workstation",
            "management_host": "192.0.2.40",
            "collector_capabilities": ["local_net_read"],
            "allowed_tcp_ports": [],
            "data_class": "confidential",
            "enabled": True,
        },
    ]
    dependencies = [
        {
            "upstream_asset_id": "demo-router-01",
            "downstream_asset_id": "demo-switch-01",
            "relation": "network_path",
            "declaration_sha256": _message_hash("demo-dependency-router-switch"),
        },
        {
            "upstream_asset_id": "demo-switch-01",
            "downstream_asset_id": "demo-camera-01",
            "relation": "network_path",
            "declaration_sha256": _message_hash("demo-dependency-switch-camera"),
        },
    ]
    payload = {
        "enabled": True,
        "allow_real_network": False,
        "database_path": str(database_path),
        "secret_directory": None,
        "policy": {
            "profile_id": "demo-readonly",
            "network_scope": "approved_inventory_only",
            "read_only": True,
            "production_safety_profile": "non_disruptive_v1",
            "allow_active_liveness": False,
            "bandwidth_measurement_mode": "counter_only",
            "packet_analysis_mode": "passive_only",
            "max_workers": 2,
            "timeout_seconds": 1.0,
            "max_retries": 0,
            "max_catch_up_runs": 1,
            "allowed_capabilities": ["local_net_read"],
        },
        "assets": assets,
        "dependencies": dependencies,
    }
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    config = load_runtime_config(config_path)

    store = MonitoringStore(database_path)
    store.initialize()
    for item in config.assets:
        store.upsert_asset(item)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    run_id = "demo-run-001"
    receipt = HourlyRunReceipt(
        run_id=run_id,
        slot_key="demo-slot-001",
        attempt=1,
        scheduled_at=_iso(now - timedelta(minutes=5)),
        started_at=_iso(now - timedelta(minutes=5)),
        completed_at=_iso(now - timedelta(minutes=4)),
        status="completed",
        inventory_fingerprint=sha256_fingerprint({"demo": "inventory"}),
        policy_fingerprint=config.policy.fingerprint,
        expected_assets=4,
        observed_assets=4,
        coverage_pct=100.0,
        failure_codes=(),
    )
    store.put_hourly_receipt(receipt)

    for index, asset in enumerate(config.assets, start=1):
        store.add_observation(
            ObservationRecord(
                run_id=run_id,
                asset_id=asset.asset_id,
                collector="local_net_read",
                observed_at=_iso(now - timedelta(minutes=4, seconds=index)),
                metric="device_health",
                status="ok" if index < 4 else "discontinuity",
                value=True if index < 4 else False,
                unit=None,
                evidence_ref=f"evidence-demo-observation-{index:02d}",
            )
        )

    event_specs = [
        ("demo-event-dns", "suricata_eve", "suricata.dns", "medium", 210),
        ("demo-event-flow", "suricata_eve", "suricata.flow", "medium", 180),
        ("demo-event-auth", "workspace_audit", "workspace_audit.auth_failure", "high", 150),
        ("demo-event-process", "workspace_audit", "workspace_audit.process_start", "high", 120),
        ("demo-event-ids", "suricata_eve", "suricata.alert", "critical", 90),
    ]
    for event_id, source_type, category, severity, age_seconds in event_specs:
        store.add_event(
            CanonicalEvent(
                event_id=event_id,
                source_id="demo-source",
                source_type=source_type,
                observed_at=_iso(now - timedelta(seconds=age_seconds)),
                category=category,
                severity=severity,
                message_sha256=_message_hash(event_id),
                parser_version="demo-v1",
                evidence_ref=f"evidence-{event_id}",
            )
        )

    context_store = EventEntityContextStore(store)
    context_store.initialize()
    source_ip = EventEntityReference.opaque(kind="ip", role="source_ip", value="198.51.100.10")
    destination_ip = EventEntityReference.opaque(kind="ip", role="destination_ip", value="198.51.100.20")
    dns_answer = EventEntityReference.opaque(kind="ip", role="dns_answer", value="198.51.100.20")
    dns_query = EventEntityReference.opaque(kind="dns", role="dns_query", value="demo.example.test")
    service_ref = EventEntityReference.opaque(kind="service", role="service", value="ssh")
    user_ref = EventEntityReference.opaque(kind="user", role="auth_user", value="demo-user")
    process_ref = EventEntityReference.opaque(kind="process", role="process_image", value="demo-process")
    asset_ref = EventEntityReference.approved_asset(role="asset", asset_id="demo-workstation-01")

    contexts = {
        "demo-event-dns": (source_ip, dns_query, dns_answer),
        "demo-event-flow": (source_ip, destination_ip, service_ref),
        "demo-event-auth": (source_ip, destination_ip, service_ref, asset_ref, user_ref),
        "demo-event-process": (asset_ref, user_ref, process_ref),
        "demo-event-ids": (source_ip, destination_ip, asset_ref),
    }
    for event_id, references in contexts.items():
        context_store.put(EventEntityContext(event_id=event_id, references=references))

    findings = [
        FindingRecord(
            finding_id="demo-finding-critical",
            category="correlated_multi_stage_activity",
            severity="critical",
            status="investigating",
            first_seen=_iso(now - timedelta(minutes=4)),
            last_seen=_iso(now - timedelta(minutes=1)),
            asset_refs=("demo-router-01", "demo-workstation-01"),
            evidence_refs=("evidence-demo-event-ids", "evidence-demo-event-auth"),
            correlation_key="demo-correlation-critical",
            rule_id="demo-rule-multi-stage",
        ),
        FindingRecord(
            finding_id="demo-finding-medium",
            category="asset_health_discontinuity",
            severity="medium",
            status="open",
            first_seen=_iso(now - timedelta(minutes=4)),
            last_seen=_iso(now - timedelta(minutes=3)),
            asset_refs=("demo-workstation-01",),
            evidence_refs=("evidence-demo-observation-04",),
            correlation_key="demo-correlation-health",
            rule_id="demo-rule-health",
        ),
    ]
    for finding in findings:
        store.add_finding(finding)

    (base / "DEMO_MARKER.json").write_text(
        json.dumps(
            {
                "schema_version": DEMO_SCHEMA,
                "network_execution": False,
                "packet_capture_execution": False,
                "remediation_execution": False,
                "synthetic_only": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return config_path
