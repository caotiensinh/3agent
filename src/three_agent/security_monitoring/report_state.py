from __future__ import annotations

import json
from dataclasses import dataclass

from .receipts import ArchiveReceipt, ReportReceipt
from .storage import MonitoringStore

_REPORT_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS report_receipts (
    report_id TEXT PRIMARY KEY,
    period_kind TEXT NOT NULL,
    period_key TEXT NOT NULL,
    cutoff_at TEXT NOT NULL,
    status TEXT NOT NULL,
    coverage_pct REAL NOT NULL,
    bundle_ref TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    ai_status TEXT NOT NULL,
    archive_status TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_report_receipts_period ON report_receipts(period_kind, period_key);
"""


@dataclass(frozen=True)
class ReportingReceiptStore:
    store: MonitoringStore

    def initialize(self) -> None:
        self.store.initialize()
        with self.store.connect() as conn:
            conn.executescript(_REPORT_STATE_SCHEMA)

    def put_report(self, receipt: ReportReceipt) -> None:
        receipt.validate()
        self.initialize()
        with self.store.connect() as conn:
            conn.execute(
                """
                INSERT INTO report_receipts(
                    report_id,period_kind,period_key,cutoff_at,status,coverage_pct,bundle_ref,
                    manifest_sha256,evidence_refs_json,ai_status,archive_status
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(report_id) DO UPDATE SET
                    status=excluded.status,
                    coverage_pct=excluded.coverage_pct,
                    bundle_ref=excluded.bundle_ref,
                    manifest_sha256=excluded.manifest_sha256,
                    evidence_refs_json=excluded.evidence_refs_json,
                    ai_status=excluded.ai_status,
                    archive_status=excluded.archive_status,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    receipt.report_id,
                    receipt.period_kind,
                    receipt.period_key,
                    receipt.cutoff_at,
                    receipt.status,
                    receipt.coverage_pct,
                    receipt.bundle_ref,
                    receipt.manifest_sha256,
                    json.dumps(list(receipt.evidence_refs), separators=(",", ":")),
                    receipt.ai_status,
                    receipt.archive_status,
                ),
            )

    def put_archive(self, receipt: ArchiveReceipt) -> None:
        receipt.validate()
        self.initialize()
        with self.store.connect() as conn:
            conn.execute(
                """
                INSERT INTO archive_receipts(
                    archive_id,period_kind,period_key,status,bundle_ref,manifest_sha256,
                    attempt,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(archive_id) DO UPDATE SET
                    status=excluded.status,
                    bundle_ref=excluded.bundle_ref,
                    manifest_sha256=excluded.manifest_sha256,
                    updated_at=excluded.updated_at
                """,
                (
                    receipt.archive_id,
                    receipt.period_kind,
                    receipt.period_key,
                    receipt.status,
                    receipt.bundle_ref,
                    receipt.manifest_sha256,
                    receipt.attempt,
                    receipt.updated_at,
                ),
            )
