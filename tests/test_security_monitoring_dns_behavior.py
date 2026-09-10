from __future__ import annotations

import inspect
import json
import unittest

import three_agent.security_monitoring.dns_behavior as dns_behavior
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.dns_behavior import extract_dns_behavior_features
from three_agent.security_monitoring.entity_context import opaque_entity_ref


class DNSBehaviorFeatureTests(unittest.TestCase):
    def test_suricata_feature_is_deterministic_and_metadata_only(self):
        payload = {
            "timestamp": "2026-09-01T00:00:00+00:00",
            "event_type": "dns",
            "src_ip": "192.0.2.10",
            "dns": {
                "rrname": "A8f9-x7.Internal.Example.COM.",
                "rrtype": "A",
                "rcode": "NXDOMAIN",
                "answers": [],
            },
            "http": {"hostname": "must-not-enter.example"},
        }
        raw = json.dumps(payload, sort_keys=True)
        first = extract_dns_behavior_features(
            event_id="evt-dns-feature-001",
            source_type="suricata_eve",
            raw_line=raw,
        )
        second = extract_dns_behavior_features(
            event_id="evt-dns-feature-001",
            source_type="suricata_eve",
            raw_line=raw,
        )
        self.assertEqual(first, second)
        self.assertTrue(first.is_nxdomain)
        self.assertEqual(first.query_type, "A")
        self.assertEqual(first.answer_count, 0)
        self.assertEqual(
            first.query_entity_ref,
            opaque_entity_ref("dns", "a8f9-x7.internal.example.com"),
        )
        rendered = json.dumps(first.public_dict(), sort_keys=True).lower()
        for forbidden in (
            "a8f9-x7.internal.example.com",
            "must-not-enter.example",
            "192.0.2.10",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertGreater(first.shannon_entropy, 0)
        self.assertGreaterEqual(first.normalized_entropy, 0)
        self.assertLessEqual(first.normalized_entropy, 1)

    def test_zeek_numeric_response_and_query_types_are_canonical(self):
        raw = json.dumps(
            {
                "ts": 1788220800.0,
                "_path": "dns",
                "query": "updates.example.org",
                "rcode": 3,
                "qtype": 28,
                "answers": ["198.51.100.9"],
            }
        )
        feature = extract_dns_behavior_features(
            event_id="evt-dns-feature-002",
            source_type="zeek_json",
            raw_line=raw,
        )
        self.assertEqual(feature.response_code, "NXDOMAIN")
        self.assertEqual(feature.query_type, "TYPE28")
        self.assertEqual(feature.answer_count, 1)

    def test_non_dns_structured_records_return_none(self):
        self.assertIsNone(
            extract_dns_behavior_features(
                event_id="evt-flow",
                source_type="suricata_eve",
                raw_line=json.dumps({"event_type": "flow"}),
            )
        )
        self.assertIsNone(
            extract_dns_behavior_features(
                event_id="evt-conn",
                source_type="zeek_json",
                raw_line=json.dumps({"_path": "conn"}),
            )
        )

    def test_missing_query_malformed_json_and_answer_overflow_fail_closed(self):
        with self.assertRaises(MonitoringContractError):
            extract_dns_behavior_features(
                event_id="evt-bad-json",
                source_type="zeek_json",
                raw_line="{bad",
            )
        with self.assertRaises(MonitoringContractError):
            extract_dns_behavior_features(
                event_id="evt-missing-query",
                source_type="zeek_json",
                raw_line=json.dumps({"_path": "dns"}),
            )
        with self.assertRaises(MonitoringContractError):
            extract_dns_behavior_features(
                event_id="evt-too-many-answers",
                source_type="zeek_json",
                raw_line=json.dumps(
                    {"_path": "dns", "query": "example.org", "answers": ["x"] * 257}
                ),
            )

    def test_query_bounds_and_control_characters_fail_closed(self):
        for query in ("", "x" * 254, "bad\nname.example", "a..example"):
            with self.assertRaises(MonitoringContractError):
                extract_dns_behavior_features(
                    event_id="evt-query-bound",
                    source_type="zeek_json",
                    raw_line=json.dumps({"_path": "dns", "query": query}),
                )

    def test_module_has_no_network_model_shell_or_remediation_authority(self):
        source = inspect.getsource(dns_behavior)
        for forbidden in (
            "import socket",
            "subprocess",
            "urlopen",
            "requests.",
            "OllamaClient",
            "generate_json",
            "pcap",
            "firewall",
            "quarantine_host",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
