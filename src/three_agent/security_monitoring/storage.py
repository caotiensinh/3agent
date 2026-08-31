from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .contracts import (
    AssetInventoryRecord,
    CanonicalEvent,
    FindingRecord,
    HourlyRunReceipt,
    ObservationRecord,
    SecretReference,
)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approved_assets (
    asset_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    management_host TEXT NOT NULL,
    collector_capabilities_json TEXT NOT NULL,
    allowed_tcp_ports_json TEXT NOT NULL,
    data_class TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    credential_ref TEXT,
    asset_fingerprint TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hourly_runs (
    run_id TEXT PRIMARY KEY,
    slot_key TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    scheduled_at TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    inventory_fingerprint TEXT NOT NULL,
    policy_fingerprint TEXT NOT NULL,
    expected_assets INTEGER NOT NULL,
    observed_assets INTEGER NOT NULL,
    coverage_pct REAL NOT NULL,
    failure_codes_json TEXT NOT NULL,
    UNIQUE(slot_key, attempt)
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metric TEXT NOT NULL,
    status TEXT NOT NULL,
    value_json TEXT,
    unit TEXT,
    evidence_ref TEXT,
    FOREIGN KEY(run_id) REFERENCES hourly_runs(run_id),
    FOREIGN KEY(asset_id) REFERENCES approved_assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_observations_asset_time ON observations(asset_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id);
CREATE TABLE IF NOT EXISTS canonical_events (
    event_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    message_sha256 TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    evidence_ref TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON canonical_events(source_id, observed_at);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    asset_refs_json TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    correlation_key TEXT NOT NULL,
    rule_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON findings(status, severity);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS archive_receipts (
    archive_id TEXT PRIMARY KEY,
    period_kind TEXT NOT NULL,
    period_key TEXT NOT NULL,
    status TEXT NOT NULL,
    bundle_ref TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(period_kind, period_key, attempt)
);
"""


class MonitoringStore:
    """Small SQLite metadata store; raw/high-volume evidence belongs in bounded files."""

    def __init__(self, path: str | Path):
        self.path = str(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT INTO schema_meta(key,value) VALUES('schema_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def schema_version(self) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
            if row is None:
                raise RuntimeError("monitoring schema is not initialized")
            return int(row["value"])

    def upsert_asset(self, asset: AssetInventoryRecord) -> None:
        asset.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO approved_assets(
                    asset_id,role,management_host,collector_capabilities_json,
                    allowed_tcp_ports_json,data_class,enabled,credential_ref,asset_fingerprint
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    role=excluded.role,
                    management_host=excluded.management_host,
                    collector_capabilities_json=excluded.collector_capabilities_json,
                    allowed_tcp_ports_json=excluded.allowed_tcp_ports_json,
                    data_class=excluded.data_class,
                    enabled=excluded.enabled,
                    credential_ref=excluded.credential_ref,
                    asset_fingerprint=excluded.asset_fingerprint,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    asset.asset_id,
                    asset.role,
                    asset.management_host,
                    json.dumps(list(asset.collector_capabilities), separators=(",", ":")),
                    json.dumps(list(asset.allowed_tcp_ports), separators=(",", ":")),
                    asset.data_class,
                    1 if asset.enabled else 0,
                    asset.credential_ref.handle if asset.credential_ref else None,
                    asset.fingerprint,
                ),
            )

    def get_asset(self, asset_id: str) -> AssetInventoryRecord | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM approved_assets WHERE asset_id=?", (asset_id,)).fetchone()
        if row is None:
            return None
        credential = SecretReference(row["credential_ref"]) if row["credential_ref"] else None
        return AssetInventoryRecord(
            asset_id=row["asset_id"],
            role=row["role"],
            management_host=row["management_host"],
            collector_capabilities=tuple(json.loads(row["collector_capabilities_json"])),
            allowed_tcp_ports=tuple(json.loads(row["allowed_tcp_ports_json"])),
            data_class=row["data_class"],
            enabled=bool(row["enabled"]),
            credential_ref=credential,
        ).validate()

    def list_enabled_assets(self) -> tuple[AssetInventoryRecord, ...]:
        with self.connect() as conn:
            ids = [row["asset_id"] for row in conn.execute(
                "SELECT asset_id FROM approved_assets WHERE enabled=1 ORDER BY asset_id"
            ).fetchall()]
        return tuple(asset for asset_id in ids if (asset := self.get_asset(asset_id)) is not None)

    def put_hourly_receipt(self, receipt: HourlyRunReceipt) -> None:
        receipt.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO hourly_runs(
                    run_id,slot_key,attempt,scheduled_at,started_at,completed_at,status,
                    inventory_fingerprint,policy_fingerprint,expected_assets,observed_assets,
                    coverage_pct,failure_codes_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(run_id) DO UPDATE SET
                    completed_at=excluded.completed_at,
                    status=excluded.status,
                    observed_assets=excluded.observed_assets,
                    coverage_pct=excluded.coverage_pct,
                    failure_codes_json=excluded.failure_codes_json
                """,
                (
                    receipt.run_id, receipt.slot_key, receipt.attempt, receipt.scheduled_at,
                    receipt.started_at, receipt.completed_at, receipt.status,
                    receipt.inventory_fingerprint, receipt.policy_fingerprint,
                    receipt.expected_assets, receipt.observed_assets, receipt.coverage_pct,
                    json.dumps(list(receipt.failure_codes), separators=(",", ":")),
                ),
            )

    def add_observation(self, observation: ObservationRecord) -> None:
        observation.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO observations(
                    run_id,asset_id,collector,observed_at,metric,status,value_json,unit,evidence_ref
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    observation.run_id, observation.asset_id, observation.collector,
                    observation.observed_at, observation.metric, observation.status,
                    json.dumps(observation.value, ensure_ascii=False, separators=(",", ":")),
                    observation.unit, observation.evidence_ref,
                ),
            )

    def add_event(self, event: CanonicalEvent) -> None:
        event.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO canonical_events(
                    event_id,source_id,source_type,observed_at,category,severity,
                    message_sha256,parser_version,evidence_ref
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.event_id, event.source_id, event.source_type, event.observed_at,
                    event.category, event.severity, event.message_sha256,
                    event.parser_version, event.evidence_ref,
                ),
            )

    def add_finding(self, finding: FindingRecord) -> None:
        finding.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO findings(
                    finding_id,category,severity,status,first_seen,last_seen,asset_refs_json,
                    evidence_refs_json,correlation_key,rule_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    severity=excluded.severity,status=excluded.status,last_seen=excluded.last_seen,
                    asset_refs_json=excluded.asset_refs_json,evidence_refs_json=excluded.evidence_refs_json
                """,
                (
                    finding.finding_id, finding.category, finding.severity, finding.status,
                    finding.first_seen, finding.last_seen,
                    json.dumps(list(finding.asset_refs), separators=(",", ":")),
                    json.dumps(list(finding.evidence_refs), separators=(",", ":")),
                    finding.correlation_key, finding.rule_id,
                ),
            )

    def add_quarantine(self, record: object) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO quarantine(
                    source_id,source_type,parser_version,reason_code,payload_sha256,observed_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    getattr(record, "source_id"), getattr(record, "source_type"),
                    getattr(record, "parser_version"), getattr(record, "reason_code"),
                    getattr(record, "payload_sha256"), getattr(record, "observed_at"),
                ),
            )

    def count(self, table: str) -> int:
        allowed = {"approved_assets", "hourly_runs", "observations", "canonical_events", "findings", "quarantine", "archive_receipts"}
        if table not in allowed:
            raise ValueError("unsupported table")
        with self.connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
