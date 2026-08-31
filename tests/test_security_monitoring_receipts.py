import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.receipts import ArchiveReceipt, ReportReceipt

SHA = "sha256:" + "a" * 64


class MonitoringReceiptTests(unittest.TestCase):
    def test_report_receipt_requires_explicit_coverage_and_archive_state(self):
        receipt = ReportReceipt(
            report_id="report-20260830",
            period_kind="daily",
            period_key="2026-08-30",
            cutoff_at="2026-08-30T17:30:00+09:00",
            status="pending_nas",
            coverage_pct=96.5,
            bundle_ref="spool/report-20260830",
            manifest_sha256=SHA,
            evidence_refs=("finding:F-1", "run:R-1"),
            ai_status="fallback",
            archive_status="pending_nas",
        ).validate()
        self.assertEqual(receipt.coverage_pct, 96.5)
        self.assertEqual(receipt.archive_status, "pending_nas")

    def test_failed_archive_requires_failure_code(self):
        with self.assertRaises(MonitoringContractError):
            ArchiveReceipt(
                archive_id="archive-1",
                period_kind="daily",
                period_key="2026-08-30",
                status="failed",
                bundle_ref="spool/report-20260830",
                manifest_sha256=SHA,
                attempt=1,
                updated_at="2026-08-30T17:31:00+09:00",
            ).validate()

    def test_archive_receipt_accepts_pending_nas_without_rerun_semantics(self):
        receipt = ArchiveReceipt(
            archive_id="archive-1",
            period_kind="daily",
            period_key="2026-08-30",
            status="pending_nas",
            bundle_ref="spool/report-20260830",
            manifest_sha256=SHA,
            attempt=1,
            updated_at="2026-08-30T17:31:00+09:00",
        ).validate()
        self.assertEqual(receipt.status, "pending_nas")


if __name__ == "__main__":
    unittest.main()
