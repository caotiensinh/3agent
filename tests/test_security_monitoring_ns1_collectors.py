import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.security_monitoring.collectors import (
    IcmpCollector,
    LocalProcNetCollector,
    SnmpV3Collector,
    TcpConnectCollector,
)
from three_agent.security_monitoring.contracts import AssetInventoryRecord, SecretReference
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine
from three_agent.security_monitoring.rates import calculate_octet_bandwidth


class FakeConnection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeSnmpBackend:
    def __init__(self):
        self.calls = []

    def read_interface_counters(self, *, target_host, credential_ref, timeout_seconds):
        self.calls.append((target_host, credential_ref.handle, timeout_seconds))
        return [
            {
                "interface": "Gi1/0/1",
                "rx_bytes": 1000,
                "tx_bytes": 2000,
                "rx_errors": 0,
                "tx_errors": 1,
                "speed_bps": 1_000_000_000,
            }
        ]


class CollectorTests(unittest.TestCase):
    def setUp(self):
        # Synthetic unit tests explicitly opt into the bounded liveness exception.
        self.engine = MonitoringPolicyEngine(
            MonitoringPolicy(
                max_workers=2,
                timeout_seconds=2,
                max_retries=1,
                allow_active_liveness=True,
            )
        )

    def test_tcp_connect_uses_exact_asset_target_and_timeout(self):
        calls = []
        connection = FakeConnection()

        def dialer(address, timeout):
            calls.append((address, timeout))
            return connection

        asset = AssetInventoryRecord(
            asset_id="router-1",
            role="router",
            management_host="192.0.2.1",
            collector_capabilities=("tcp_connect",),
            allowed_tcp_ports=(443,),
        ).validate()
        result = TcpConnectCollector(self.engine, dialer=dialer).collect(
            asset=asset,
            port=443,
            run_id="run-1",
            observed_at="2026-08-30T12:00:00+00:00",
        )
        self.assertEqual(calls, [(('192.0.2.1', 443), 2)])
        self.assertTrue(connection.closed)
        self.assertEqual(result.observations[0].status, "ok")

    def test_icmp_uses_fixed_argv_shell_false_and_never_free_form_command(self):
        calls = []

        def executor(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            return SimpleNamespace(returncode=0, stdout="64 bytes time=1.25 ms", stderr="")

        asset = AssetInventoryRecord(
            asset_id="router-2",
            role="router",
            management_host="192.0.2.2",
            collector_capabilities=("icmp_echo",),
        ).validate()
        result = IcmpCollector(self.engine, executor=executor).collect(
            asset=asset,
            run_id="run-2",
            observed_at="2026-08-30T12:00:00+00:00",
        )
        argv, kwargs = calls[0]
        self.assertEqual(argv[-1], "192.0.2.2")
        self.assertEqual(argv[:4], ["ping", "-n", "-c", "1"])
        self.assertIs(kwargs["shell"], False)
        self.assertNotIn(";", " ".join(argv))
        self.assertEqual(result.observations[1].value, 1.25)

    def test_local_proc_collector_has_no_external_dependency(self):
        proc = """Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netdev"
            path.write_text(proc, encoding="utf-8")
            asset = AssetInventoryRecord(
                asset_id="local-host",
                role="monitor",
                management_host="localhost",
                collector_capabilities=("local_net_read",),
            ).validate()
            result = LocalProcNetCollector(self.engine, proc_path=path).collect(
                asset=asset,
                run_id="run-local",
                observed_at="2026-08-30T12:00:00+00:00",
            )
        metrics = {obs.metric: obs.value for obs in result.observations}
        self.assertEqual(metrics["if_eth0_rx_bytes"], 1000)
        self.assertEqual(metrics["if_eth0_tx_errors"], 3)

    def test_snmp_adapter_passes_only_opaque_reference_to_backend(self):
        backend = FakeSnmpBackend()
        asset = AssetInventoryRecord(
            asset_id="switch-1",
            role="switch",
            management_host="192.0.2.10",
            collector_capabilities=("snmpv3_read",),
            credential_ref=SecretReference("secret-ref:snmp-switch-1"),
        ).validate()
        result = SnmpV3Collector(self.engine, backend).collect(
            asset=asset,
            run_id="run-snmp",
            observed_at="2026-08-30T12:00:00+00:00",
        )
        self.assertEqual(backend.calls, [("192.0.2.10", "secret-ref:snmp-switch-1", 2)])
        self.assertGreaterEqual(len(result.observations), 5)


class CounterRateTests(unittest.TestCase):
    def test_octet_counter_converts_to_bps_and_utilization(self):
        result = calculate_octet_bandwidth(
            previous=1000,
            current=2000,
            elapsed_seconds=10,
            interface_speed_bps=1000,
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.delta, 1000)
        self.assertEqual(result.rate_per_second, 800.0)
        self.assertAlmostEqual(result.utilization_pct, 80.0)

    def test_counter_reset_is_not_fabricated_as_wrap(self):
        result = calculate_octet_bandwidth(previous=5000, current=10, elapsed_seconds=60)
        self.assertEqual(result.status, "discontinuity")
        self.assertEqual(result.reason_code, "COUNTER_RESET")
        self.assertIsNone(result.rate_per_second)

    def test_32bit_near_boundary_wrap_is_supported(self):
        modulus = 1 << 32
        result = calculate_octet_bandwidth(
            previous=modulus - 100,
            current=50,
            elapsed_seconds=10,
            counter_bits=32,
        )
        self.assertEqual(result.delta, 150)
        self.assertEqual(result.status, "ok")

    def test_reboot_missing_interval_and_speed_change_are_discontinuities(self):
        cases = [
            dict(previous=None, current=1, elapsed_seconds=1),
            dict(previous=1, current=2, elapsed_seconds=0),
            dict(previous=1, current=2, elapsed_seconds=1, rebooted=True),
            dict(previous=1, current=2, elapsed_seconds=1, interface_speed_bps=1000, previous_interface_speed_bps=100),
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(calculate_octet_bandwidth(**kwargs).status, "discontinuity")


if __name__ == "__main__":
    unittest.main()
