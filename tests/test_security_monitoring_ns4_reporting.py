import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from three_agent.security_monitoring.contracts import (
    AssetInventoryRecord,
    CanonicalEvent,
    FindingRecord,
    HourlyRunReceipt,
    MonitoringContractError,
    ObservationRecord,
)
from three_agent.security_monitoring.nas_archive import NasArchiveConfig, archive_existing_bundle
from three_agent.security_monitoring.report_orchestrator import (
    ReportingConfig,
    load_reporting_config,
    retry_pending_archive,
    run_reporting_cycle,
)
from three_agent.security_monitoring.reporting import (
    ReportAlreadyLocked,
    ReportRunLock,
    build_deterministic_report,
    is_canonical_monthly,
    is_canonical_weekly,
    write_report_bundle,
)
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_reporting_cli import latest_canonical_cutoff

SHA = "sha256:" + "a" * 64


class ReportingFixtureMixin:
    def populate_store(self, root: Path) -> MonitoringStore:
        db = root / "state" / "monitoring.sqlite3"
        db.parent.mkdir(parents=True, exist_ok=True)
        store = MonitoringStore(db)
        store.initialize()
        asset = AssetInventoryRecord(
            asset_id="monitor-1",
            role="monitor",
            management_host="localhost",
            collector_capabilities=("local_net_read",),
        ).validate()
        store.upsert_asset(asset)
        receipt = HourlyRunReceipt(
            run_id="run-20260829-1605",
            slot_key="slot-20260829T1605",
            attempt=1,
            scheduled_at="2026-08-29T16:05:00+09:00",
            started_at="2026-08-29T16:05:01+09:00",
            completed_at="2026-08-29T16:05:02+09:00",
            status="completed",
            inventory_fingerprint=asset.fingerprint,
            policy_fingerprint=SHA,
            expected_assets=1,
            observed_assets=1,
            coverage_pct=100.0,
        ).validate()
        store.put_hourly_receipt(receipt)
        store.add_observation(
            ObservationRecord(
                run_id=receipt.run_id,
                asset_id=asset.asset_id,
                collector="local_net_read",
                observed_at="2026-08-29T16:05:01+09:00",
                metric="if_eth0_rx_bytes",
                status="ok",
                value=123456,
                unit="bytes",
                evidence_ref="obs:rx-1",
            ).validate()
        )
        store.add_event(
            CanonicalEvent(
                event_id="evt-1",
                source_id="sensor-1",
                source_type="suricata_eve",
                observed_at="2026-08-29T16:10:00+09:00",
                category="suricata.alert",
                severity="high",
                message_sha256=SHA,
                parser_version="parser-v1",
                evidence_ref="event:evt-1",
            ).validate()
        )
        store.add_finding(
            FindingRecord(
                finding_id="finding-1",
                category="network_instability",
                severity="high",
                status="open",
                first_seen="2026-08-29T16:10:00+09:00",
                last_seen="2026-08-29T16:15:00+09:00",
                asset_refs=(asset.asset_id,),
                evidence_refs=("event:evt-1", "obs:rx-1"),
                correlation_key="asset:monitor-1:network",
                rule_id="rule-network-instability",
            ).validate()
        )
        return store


class DeterministicReportingTests(ReportingFixtureMixin, unittest.TestCase):
    def test_current_day_7d_30d_and_bundle_outputs_are_bounded_and_evidence_backed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = self.populate_store(root)
            report = build_deterministic_report(store, cutoff_at="2026-08-29T17:30:00+09:00")
            self.assertEqual(report.report_id, "report-20260829-1730")
            self.assertEqual(report.today.starts_at, "2026-08-29T00:00:00+09:00")
            self.assertEqual(report.today.ends_at, "2026-08-29T17:30:00+09:00")
            self.assertEqual(report.rolling_7d.starts_at, "2026-08-22T17:30:00+09:00")
            self.assertEqual(report.rolling_30d.starts_at, "2026-07-30T17:30:00+09:00")
            self.assertEqual(report.today.average_coverage_pct, 100.0)
            self.assertEqual(report.today.event_count, 1)
            self.assertEqual(report.today.open_high_critical, 1)
            self.assertEqual(set(report.evidence_refs), {"event:evt-1", "obs:rx-1"})

            bundle = write_report_bundle(report, spool_root=root / "reports")
            names = {path.name for path in bundle.path.iterdir()}
            self.assertEqual(
                names,
                {"report.md", "report.json", "metrics-summary.csv", "findings.jsonl.gz", "manifest.sha256"},
            )
            manifest_lines = (bundle.path / "manifest.sha256").read_text(encoding="ascii").splitlines()
            self.assertEqual(len(manifest_lines), 4)
            self.assertTrue(bundle.manifest_sha256.startswith("sha256:"))

    def test_weekly_and_monthly_canonical_archive_boundaries_are_exact(self):
        self.assertTrue(is_canonical_weekly("2026-08-30T17:30:00+09:00"))
        self.assertFalse(is_canonical_weekly("2026-08-29T17:30:00+09:00"))
        self.assertTrue(is_canonical_monthly("2026-08-31T17:30:00+09:00"))
        self.assertFalse(is_canonical_monthly("2026-08-30T17:30:00+09:00"))

    def test_report_slot_lock_rejects_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with ReportRunLock(root, "daily-2026-08-29"):
                with self.assertRaises(ReportAlreadyLocked):
                    with ReportRunLock(root, "daily-2026-08-29"):
                        pass

    def test_persistent_timer_cutoff_never_fabricates_future_1730_slot(self):
        before = latest_canonical_cutoff(datetime.fromisoformat("2026-08-30T10:00:00+09:00"))
        after = latest_canonical_cutoff(datetime.fromisoformat("2026-08-30T18:00:00+09:00"))
        self.assertEqual(before.isoformat(), "2026-08-29T17:30:00+09:00")
        self.assertEqual(after.isoformat(), "2026-08-30T17:30:00+09:00")


class NasArchiveRecoveryTests(ReportingFixtureMixin, unittest.TestCase):
    def test_missing_or_unmounted_nas_is_pending_and_exact_bundle_recovers_without_reanalysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = self.populate_store(root)
            report = build_deterministic_report(store, cutoff_at="2026-08-29T17:30:00+09:00")
            bundle = write_report_bundle(report, spool_root=root / "reports")
            nas_root = root / "nas"
            config = NasArchiveConfig(nas_root)

            pending = archive_existing_bundle(
                bundle,
                config=config,
                period_kind="daily",
                period_key="2026-08-29",
                attempt=1,
            )
            self.assertEqual(pending.status, "pending_nas")
            self.assertEqual(pending.failure_code, "NAS_UNAVAILABLE")
            original_report = (bundle.path / "report.json").read_bytes()

            nas_root.mkdir()
            with patch("three_agent.security_monitoring.nas_archive.os.path.ismount", return_value=True):
                archived = archive_existing_bundle(
                    bundle,
                    config=config,
                    period_kind="daily",
                    period_key="2026-08-29",
                    attempt=2,
                )
            self.assertEqual(archived.status, "archived")
            self.assertEqual((bundle.path / "report.json").read_bytes(), original_report)
            archived_report = nas_root / "daily" / "2026-08-29" / bundle.report_id / "report.json"
            self.assertEqual(archived_report.read_bytes(), original_report)

    def test_local_bundle_is_verified_before_nas_availability_state_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = self.populate_store(root)
            report = build_deterministic_report(store, cutoff_at="2026-08-29T17:30:00+09:00")
            bundle = write_report_bundle(report, spool_root=root / "reports")
            (bundle.path / "report.md").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(MonitoringContractError, "hash verification failed"):
                archive_existing_bundle(
                    bundle,
                    config=NasArchiveConfig(root / "missing-nas"),
                    period_kind="daily",
                    period_key="2026-08-29",
                )

    def test_orchestrator_keeps_local_bundle_then_retries_only_existing_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = self.populate_store(root)
            spool = root / "reports"
            nas_root = root / "nas"
            config = ReportingConfig(
                enabled=True,
                database_path=Path(store.path),
                spool_root=spool,
                nas_root=nas_root,
                max_archive_attempts_per_run=2,
            ).validate()
            receipts = run_reporting_cycle(config, cutoff_at="2026-08-29T17:30:00+09:00")
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0].status, "pending_nas")
            report_id = "report-20260829-1730"
            original = (spool / report_id / "report.json").read_bytes()

            nas_root.mkdir()
            with patch("three_agent.security_monitoring.nas_archive.os.path.ismount", return_value=True):
                archive = retry_pending_archive(
                    config,
                    report_id=report_id,
                    period_kind="daily",
                    period_key="2026-08-29",
                    attempt=2,
                )
            self.assertEqual(archive.status, "archived")
            self.assertEqual((spool / report_id / "report.json").read_bytes(), original)
            with self.assertRaises(MonitoringContractError):
                retry_pending_archive(
                    config,
                    report_id=report_id,
                    period_kind="daily",
                    period_key="2026-08-29",
                    attempt=3,
                )


class ReportingConfigTests(unittest.TestCase):
    def test_config_is_fail_closed_and_cannot_store_nas_credentials_or_mount_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = {
                "enabled": False,
                "database_path": str(root / "monitoring.sqlite3"),
                "spool_root": str(root / "reports"),
                "nas_root": str(root / "nas"),
                "timezone": "Asia/Tokyo",
                "report_hour": 17,
                "report_minute": 30,
            }
            path = root / "reporting.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            self.assertFalse(load_reporting_config(path).enabled)
            for key in ("username", "password", "token", "mount_command"):
                payload = dict(base)
                payload[key] = "forbidden"
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(key=key), self.assertRaises(MonitoringContractError):
                    load_reporting_config(path)


if __name__ == "__main__":
    unittest.main()
