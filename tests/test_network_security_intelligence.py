from __future__ import annotations

import ast
import inspect
import unittest
from datetime import datetime, timedelta

import three_agent.network_security_intelligence as intelligence_module
from three_agent.network_corpus_adapter import EvidenceRecord
from three_agent.network_security_intelligence import (
    NetworkSecurityIntelligenceAnalyzer,
    NetworkSecurityIntelligenceConfig,
    NetworkSecurityIntelligenceError,
)

SOURCE_SHA = "sha256:" + "a" * 64


def flow(
    ordinal: int,
    timestamp: datetime,
    *,
    src: str = "10.0.0.10",
    dst: str = "10.0.0.20",
    sport: str = "50000",
    dport: str = "443",
    proto: str = "tcp",
    total_bytes: int = 1000,
    source_bytes: int = 500,
) -> EvidenceRecord:
    return EvidenceRecord.build(
        dataset_id="ctu-13",
        source_domain="network_flow",
        source_object_ref="ctu13/fixture.binetflow",
        source_sha256=SOURCE_SHA,
        adapter_version="ctu-13-bidirectional-netflow/0.1",
        record_ordinal=ordinal,
        timestamp=timestamp.isoformat(),
        asset_refs=[src, dst],
        account_refs=[],
        network_refs=[f"src={src}", f"dst={dst}", f"dport={dport}"],
        event_family="network_flow",
        event_type="ctu13_bidirectional_flow",
        observation_fields={
            "source_address": src,
            "destination_address": dst,
            "source_port": sport,
            "destination_port": dport,
            "protocol": proto,
            "total_bytes": total_bytes,
            "source_bytes": source_bytes,
        },
        provenance_ref="prov://fixture/ctu13",
    )


class NetworkSecurityIntelligenceSignalTests(unittest.TestCase):
    def setUp(self):
        self.base = datetime(2026, 9, 1, 0, 0, 0)

    def test_vertical_port_fanout_is_evidence_backed_and_advisory(self):
        records = [
            flow(index, self.base + timedelta(seconds=index), dst="10.0.0.20", dport=str(1000 + index))
            for index in range(4)
        ]
        analyzer = NetworkSecurityIntelligenceAnalyzer(
            NetworkSecurityIntelligenceConfig(
                port_scan_distinct_ports=4,
                host_fanout_distinct_destinations=99,
                burst_flow_count=99,
                beacon_min_samples=99,
            )
        )
        signals = analyzer.analyze(records)
        vertical = [item for item in signals if item.signal_type == "VERTICAL_PORT_FANOUT"]
        self.assertEqual(len(vertical), 1)
        self.assertEqual(vertical[0].severity, "HIGH")
        self.assertEqual(vertical[0].authority, "advisory")
        self.assertFalse(vertical[0].ground_truth_used)
        self.assertEqual(vertical[0].metrics["distinct_destination_ports"], 4)
        self.assertEqual(set(vertical[0].evidence_ids), {item.evidence_id for item in records})

    def test_horizontal_host_fanout_detects_same_service_across_hosts(self):
        records = [
            flow(index, self.base + timedelta(seconds=index), dst=f"10.0.1.{index + 1}", dport="445")
            for index in range(5)
        ]
        analyzer = NetworkSecurityIntelligenceAnalyzer(
            NetworkSecurityIntelligenceConfig(
                port_scan_distinct_ports=99,
                host_fanout_distinct_destinations=5,
                burst_flow_count=99,
                beacon_min_samples=99,
            )
        )
        signals = analyzer.analyze(records)
        horizontal = [item for item in signals if item.signal_type == "HORIZONTAL_HOST_FANOUT"]
        self.assertEqual(len(horizontal), 1)
        self.assertEqual(horizontal[0].metrics["destination_port"], "445")
        self.assertEqual(horizontal[0].metrics["distinct_destinations"], 5)

    def test_flow_burst_is_bounded_window_signal_not_attack_verdict(self):
        records = [flow(index, self.base + timedelta(seconds=index)) for index in range(6)]
        analyzer = NetworkSecurityIntelligenceAnalyzer(
            NetworkSecurityIntelligenceConfig(
                port_scan_distinct_ports=99,
                host_fanout_distinct_destinations=99,
                burst_flow_count=6,
                beacon_min_samples=99,
            )
        )
        burst = [item for item in analyzer.analyze(records) if item.signal_type == "FLOW_BURST"]
        self.assertEqual(len(burst), 1)
        self.assertEqual(burst[0].metrics["flow_count"], 6)
        self.assertNotIn("confirmed", burst[0].rationale.casefold())

    def test_periodic_flow_pattern_detects_low_variance_timing(self):
        records = [
            flow(index, self.base + timedelta(seconds=30 * index), dst="198.51.100.10", dport="8080")
            for index in range(6)
        ]
        analyzer = NetworkSecurityIntelligenceAnalyzer(
            NetworkSecurityIntelligenceConfig(
                port_scan_distinct_ports=99,
                host_fanout_distinct_destinations=99,
                burst_flow_count=99,
                beacon_min_samples=6,
                beacon_min_period_seconds=10,
                beacon_max_period_seconds=60,
                beacon_max_cv=0.01,
            )
        )
        periodic = [item for item in analyzer.analyze(records) if item.signal_type == "PERIODIC_FLOW_PATTERN"]
        self.assertEqual(len(periodic), 1)
        self.assertEqual(periodic[0].metrics["mean_period_seconds"], 30.0)
        self.assertEqual(periodic[0].metrics["period_cv"], 0.0)
        self.assertIn("not proof", periodic[0].rationale)

    def test_jitter_above_threshold_is_not_beacon_signal(self):
        offsets = (0, 10, 70, 80, 170, 180)
        records = [flow(index, self.base + timedelta(seconds=seconds)) for index, seconds in enumerate(offsets)]
        analyzer = NetworkSecurityIntelligenceAnalyzer(
            NetworkSecurityIntelligenceConfig(
                port_scan_distinct_ports=99,
                host_fanout_distinct_destinations=99,
                burst_flow_count=99,
                beacon_min_samples=6,
                beacon_min_period_seconds=5,
                beacon_max_period_seconds=100,
                beacon_max_cv=0.1,
            )
        )
        self.assertFalse(any(item.signal_type == "PERIODIC_FLOW_PATTERN" for item in analyzer.analyze(records)))

    def test_large_outbound_is_transfer_signal_not_exfiltration_verdict(self):
        record = flow(
            0,
            self.base,
            total_bytes=120 * 1024 * 1024,
            source_bytes=110 * 1024 * 1024,
        )
        analyzer = NetworkSecurityIntelligenceAnalyzer(
            NetworkSecurityIntelligenceConfig(
                port_scan_distinct_ports=99,
                host_fanout_distinct_destinations=99,
                burst_flow_count=99,
                beacon_min_samples=99,
                large_outbound_bytes=100 * 1024 * 1024,
                large_outbound_source_ratio=0.85,
            )
        )
        signals = analyzer.analyze([record])
        transfer = [item for item in signals if item.signal_type == "LARGE_OUTBOUND_TRANSFER"]
        self.assertEqual(len(transfer), 1)
        self.assertIn("not a confirmed exfiltration", transfer[0].rationale)

    def test_same_evidence_replays_to_same_signal_ids(self):
        records = [
            flow(index, self.base + timedelta(seconds=index), dst="10.0.0.20", dport=str(index + 1))
            for index in range(4)
        ]
        config = NetworkSecurityIntelligenceConfig(
            port_scan_distinct_ports=4,
            host_fanout_distinct_destinations=99,
            burst_flow_count=99,
            beacon_min_samples=99,
        )
        first = NetworkSecurityIntelligenceAnalyzer(config).analyze(records)
        second = NetworkSecurityIntelligenceAnalyzer(config).analyze(reversed(records))
        self.assertEqual([item.as_dict() for item in first], [item.as_dict() for item in second])

    def test_naive_time_window_axis_is_explicitly_host_timezone_independent(self):
        source = inspect.getsource(intelligence_module)
        self.assertIn("_stable_epoch_seconds", source)
        self.assertNotIn("item.timestamp.timestamp()", source)

    def test_record_budget_fails_closed(self):
        analyzer = NetworkSecurityIntelligenceAnalyzer(NetworkSecurityIntelligenceConfig(max_records=2))
        with self.assertRaises(NetworkSecurityIntelligenceError):
            analyzer.analyze([flow(0, self.base), flow(1, self.base), flow(2, self.base)])


class NetworkSecurityIntelligenceAuthorityTests(unittest.TestCase):
    def test_analyzer_has_no_truth_network_model_subprocess_or_remediation_authority(self):
        text = inspect.getsource(intelligence_module)
        tree = ast.parse(text)
        banned_roots = {"requests", "urllib", "socket", "subprocess", "openai", "ollama"}
        imported: set[str] = set()
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
                imported_names.update(alias.name for alias in node.names)
        self.assertFalse(imported & banned_roots)
        self.assertNotIn("TruthRecord", imported_names)
        self.assertNotIn("TruthRecord", text)
        for forbidden in ("remediate", "execute_command", "capture_pcap", "install_package"):
            self.assertNotIn(f"def {forbidden}", text)


if __name__ == "__main__":
    unittest.main()
