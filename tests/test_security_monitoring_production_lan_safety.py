import unittest

from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError
from three_agent.security_monitoring.plan import compile_collection_plan
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine
from three_agent.security_monitoring.rates import calculate_octet_bandwidth


class ProductionLanSafetyTests(unittest.TestCase):
    def _active_asset(self, ports=(443,)):
        return AssetInventoryRecord(
            asset_id="router-safe",
            role="router",
            management_host="192.0.2.20",
            collector_capabilities=("icmp_echo", "tcp_connect"),
            allowed_tcp_ports=tuple(ports),
        ).validate()

    def test_default_policy_is_non_disruptive_counter_and_passive_only(self):
        policy = MonitoringPolicy().validate()
        self.assertEqual(policy.production_safety_profile, "non_disruptive_v1")
        self.assertFalse(policy.allow_active_liveness)
        self.assertEqual(policy.bandwidth_measurement_mode, "counter_only")
        self.assertEqual(policy.packet_analysis_mode, "passive_only")
        self.assertLessEqual(policy.max_workers, 4)
        self.assertLessEqual(policy.timeout_seconds, 5.0)

    def test_default_plan_does_not_compile_icmp_or_tcp_work(self):
        plan = compile_collection_plan((self._active_asset(),), policy=MonitoringPolicy())
        self.assertEqual(plan, ())

    def test_policy_denies_active_probe_before_collector_execution_by_default(self):
        asset = self._active_asset()
        engine = MonitoringPolicyEngine(MonitoringPolicy())
        for capability, port in (("icmp_echo", None), ("tcp_connect", 443)):
            decision = engine.authorize(
                asset,
                capability=capability,
                effect="network_read",
                target_host=asset.management_host,
                target_port=port,
            )
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason_code, "ACTIVE_LIVENESS_DISABLED")

    def test_explicit_active_liveness_is_still_exact_and_hard_capped(self):
        policy = MonitoringPolicy(allow_active_liveness=True).validate()
        plan = compile_collection_plan((self._active_asset(),), policy=policy)
        self.assertEqual({item.capability for item in plan}, {"icmp_echo", "tcp_connect"})
        self.assertEqual(len(plan), 2)
        with self.assertRaises(MonitoringContractError):
            compile_collection_plan((self._active_asset(ports=(443, 8443)),), policy=policy)

    def test_disruptive_or_load_generating_capabilities_are_not_in_vocabulary(self):
        forbidden = (
            "nmap_scan",
            "masscan",
            "iperf",
            "speedtest",
            "packet_inject",
            "packet_replay",
            "arp_poison",
            "syn_flood",
            "interface_down",
            "vlan_write",
            "firewall_write",
            "reboot",
            "firmware_update",
            "credential_change",
        )
        for capability in forbidden:
            with self.subTest(capability=capability), self.assertRaises(MonitoringContractError):
                AssetInventoryRecord(
                    asset_id="forbidden-test",
                    role="router",
                    management_host="192.0.2.30",
                    collector_capabilities=(capability,),
                ).validate()

    def test_bandwidth_is_derived_from_counters_not_generated_traffic(self):
        result = calculate_octet_bandwidth(
            previous=10_000,
            current=20_000,
            elapsed_seconds=10,
            interface_speed_bps=1_000_000,
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.rate_per_second, 8_000.0)
        self.assertAlmostEqual(result.utilization_pct, 0.8)


if __name__ == "__main__":
    unittest.main()
