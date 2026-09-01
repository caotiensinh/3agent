from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import AssetInventoryRecord
from three_agent.security_monitoring.hourly import HourlyMonitoringRunner
from three_agent.security_monitoring.plan import compile_collection_plan
from three_agent.security_monitoring.policy import MonitoringPolicy
from three_agent.security_monitoring.storage import MonitoringStore


class SecurityMonitoringPlanPolicyGateTests(unittest.TestCase):
    def _asset(self) -> AssetInventoryRecord:
        return AssetInventoryRecord(
            asset_id="router-01",
            role="router",
            management_host="192.0.2.1",
            collector_capabilities=("local_net_read", "tcp_connect"),
            allowed_tcp_ports=(443,),
        ).validate()

    def test_policy_disallowed_capability_is_not_scheduled(self) -> None:
        policy = MonitoringPolicy(
            allow_active_liveness=True,
            allowed_capabilities=("local_net_read",),
        ).validate()
        plan = compile_collection_plan((self._asset(),), policy=policy)
        self.assertEqual([item.capability for item in plan], ["local_net_read"])

    def test_policy_disallowed_capability_never_reaches_hourly_executor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = MonitoringStore(Path(td) / "monitoring.sqlite3")
            store.initialize()
            asset = AssetInventoryRecord(
                asset_id="router-01",
                role="router",
                management_host="192.0.2.1",
                collector_capabilities=("local_net_read",),
            ).validate()
            store.upsert_asset(asset)
            calls = []

            def execute(item, approved_asset, run_id, observed_at):
                calls.append(item)
                raise AssertionError("policy-disallowed work reached executor")

            runner = HourlyMonitoringRunner(
                store=store,
                policy=MonitoringPolicy(allowed_capabilities=()).validate(),
                execute_work_item=execute,
            )
            receipt = runner.run(scheduled_at="2026-09-02T00:00:00+09:00")

            self.assertEqual(calls, [])
            self.assertEqual(receipt.status, "partial")
            self.assertIn("DATA_GAP_ROUTER_01", receipt.failure_codes)


if __name__ == "__main__":
    unittest.main()
