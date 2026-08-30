import tempfile
import threading
import time
import unittest
from pathlib import Path

from three_agent.security_monitoring.collectors import CollectorResult
from three_agent.security_monitoring.contracts import AssetInventoryRecord, ObservationRecord
from three_agent.security_monitoring.hourly import HourlyMonitoringRunner, hourly_slot_key
from three_agent.security_monitoring.locking import HourlyRunLockManager, MonitoringRunAlreadyLocked
from three_agent.security_monitoring.policy import MonitoringPolicy
from three_agent.security_monitoring.storage import MonitoringStore


class HourlyRunnerTests(unittest.TestCase):
    def _store(self, tmp):
        store = MonitoringStore(Path(tmp) / "monitoring.sqlite3")
        store.initialize()
        store.upsert_asset(
            AssetInventoryRecord(
                asset_id="router-1",
                role="router",
                management_host="192.0.2.1",
                collector_capabilities=("icmp_echo", "tcp_connect"),
                allowed_tcp_ports=(443,),
            ).validate()
        )
        store.upsert_asset(
            AssetInventoryRecord(
                asset_id="router-2",
                role="router",
                management_host="192.0.2.2",
                collector_capabilities=("icmp_echo",),
            ).validate()
        )
        return store

    def test_hourly_run_persists_receipt_and_full_coverage_without_llm(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            calls = []

            def execute(item, asset, run_id, observed_at):
                calls.append((item.work_id, item.asset_id, item.capability, observed_at))
                return CollectorResult(
                    (
                        ObservationRecord(
                            run_id=run_id,
                            asset_id=asset.asset_id,
                            collector=item.capability,
                            observed_at=observed_at,
                            metric="synthetic_reachable",
                            status="ok",
                            value=True,
                            unit="bool",
                        ).validate(),
                    )
                )

            runner = HourlyMonitoringRunner(
                store=store,
                policy=MonitoringPolicy(
                    profile_id="rnd", max_workers=2, max_retries=1, allow_active_liveness=True
                ),
                execute_work_item=execute,
            )
            receipt = runner.run(scheduled_at="2020-01-01T00:05:00+09:00")
            self.assertEqual(receipt.status, "completed")
            self.assertEqual(receipt.coverage_pct, 100.0)
            self.assertEqual(receipt.expected_assets, 2)
            self.assertEqual(receipt.observed_assets, 2)
            self.assertEqual(len(calls), 3)
            self.assertEqual(store.count("hourly_runs"), 1)
            self.assertEqual(store.count("observations"), 3)
            self.assertTrue(all(call[3] != receipt.scheduled_at for call in calls))

    def test_retry_is_bounded_to_one_and_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MonitoringStore(Path(tmp) / "monitoring.sqlite3")
            store.initialize()
            store.upsert_asset(
                AssetInventoryRecord(
                    asset_id="router-retry",
                    role="router",
                    management_host="192.0.2.8",
                    collector_capabilities=("icmp_echo",),
                ).validate()
            )
            count = 0

            def execute(item, asset, run_id, observed_at):
                nonlocal count
                count += 1
                if count == 1:
                    return CollectorResult((), "ICMP_TIMEOUT")
                return CollectorResult(
                    (
                        ObservationRecord(
                            run_id=run_id,
                            asset_id=asset.asset_id,
                            collector=item.capability,
                            observed_at=observed_at,
                            metric="icmp_reachable",
                            status="ok",
                            value=True,
                            unit="bool",
                        ).validate(),
                    )
                )

            receipt = HourlyMonitoringRunner(
                store=store,
                policy=MonitoringPolicy(max_retries=1, allow_active_liveness=True),
                execute_work_item=execute,
            ).run(scheduled_at="2026-08-30T21:05:00+09:00")
            self.assertEqual(count, 2)
            self.assertIn("COLLECTOR_RETRIED", receipt.failure_codes)
            self.assertEqual(receipt.status, "completed")

    def test_data_gap_is_explicit_when_collector_returns_no_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)

            def execute(item, asset, run_id, observed_at):
                if asset.asset_id == "router-2":
                    return CollectorResult((), "ICMP_TIMEOUT")
                return CollectorResult(
                    (
                        ObservationRecord(
                            run_id=run_id,
                            asset_id=asset.asset_id,
                            collector=item.capability,
                            observed_at=observed_at,
                            metric="synthetic_reachable",
                            status="ok",
                            value=True,
                            unit="bool",
                        ).validate(),
                    )
                )

            receipt = HourlyMonitoringRunner(
                store=store,
                policy=MonitoringPolicy(max_retries=0, allow_active_liveness=True),
                execute_work_item=execute,
            ).run(scheduled_at="2026-08-30T21:05:00+09:00")
            self.assertEqual(receipt.status, "partial")
            self.assertEqual(receipt.coverage_pct, 50.0)
            self.assertIn("DATA_GAP_ROUTER_2", receipt.failure_codes)

    def test_single_run_lock_blocks_overlapping_same_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            policy = MonitoringPolicy(profile_id="rnd")
            slot = hourly_slot_key("rnd", "2026-08-30T21:05:00+09:00")
            manager = HourlyRunLockManager(store)
            held = manager.acquire(slot_key=slot, owner_id="test-owner", acquired_at="2026-08-30T12:05:00+00:00")
            runner = HourlyMonitoringRunner(
                store=store,
                policy=policy,
                execute_work_item=lambda *args: CollectorResult(()),
            )
            with self.assertRaises(MonitoringRunAlreadyLocked):
                runner.run(scheduled_at="2026-08-30T21:05:00+09:00")
            self.assertTrue(manager.release(held))

    def test_worker_concurrency_never_exceeds_policy_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MonitoringStore(Path(tmp) / "monitoring.sqlite3")
            store.initialize()
            for index in range(6):
                store.upsert_asset(
                    AssetInventoryRecord(
                        asset_id=f"router-{index}",
                        role="router",
                        management_host=f"192.0.2.{20 + index}",
                        collector_capabilities=("icmp_echo",),
                    ).validate()
                )
            state = {"active": 0, "max": 0}
            mutex = threading.Lock()

            def execute(item, asset, run_id, observed_at):
                with mutex:
                    state["active"] += 1
                    state["max"] = max(state["max"], state["active"])
                time.sleep(0.02)
                with mutex:
                    state["active"] -= 1
                return CollectorResult(
                    (
                        ObservationRecord(
                            run_id=run_id,
                            asset_id=asset.asset_id,
                            collector=item.capability,
                            observed_at=observed_at,
                            metric="reachable",
                            status="ok",
                            value=True,
                            unit="bool",
                        ).validate(),
                    )
                )

            HourlyMonitoringRunner(
                store=store,
                policy=MonitoringPolicy(max_workers=2, max_retries=0, allow_active_liveness=True),
                execute_work_item=execute,
            ).run(scheduled_at="2026-08-30T21:05:00+09:00")
            self.assertLessEqual(state["max"], 2)
            self.assertGreaterEqual(state["max"], 1)


if __name__ == "__main__":
    unittest.main()
