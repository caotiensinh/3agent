from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from pathlib import Path

import three_agent.security_monitoring.behavior_store as behavior_store
from three_agent.security_monitoring.behavior_intelligence import (
    BehaviorBaselineConfig,
    RULE_DNS_ENTROPY,
    RULE_RARE_PEER,
)
from three_agent.security_monitoring.behavior_store import (
    BehaviorAnalysisWindow,
    BehaviorStoreConfig,
    BehaviorStoreReader,
)
from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.dns_behavior import extract_dns_behavior_features
from three_agent.security_monitoring.dns_behavior_storage import DNSBehaviorFeatureStore
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.storage import MonitoringStore


class BehaviorStoreReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MonitoringStore(Path(self.temp.name) / "monitoring.sqlite3")
        self.entities = EventEntityContextStore(self.store)
        self.entities.initialize()
        self.dns = DNSBehaviorFeatureStore(self.store)
        self.dns.initialize()

    def tearDown(self):
        self.temp.cleanup()

    def _add_flow(self, event_id: str, observed_at: str, destination: str):
        event = CanonicalEvent(
            event_id=event_id,
            source_id="zeek-flow",
            source_type="zeek_json",
            observed_at=observed_at,
            category="zeek.conn",
            severity="info",
            message_sha256="sha256:" + ("a" if "known" in event_id else "b") * 64,
            parser_version="test/v1",
            evidence_ref="event:" + event_id,
        ).validate()
        context = EventEntityContext(
            event_id=event_id,
            references=(
                EventEntityReference.opaque(
                    kind="ip", role="source_ip", value="192.0.2.10"
                ),
                EventEntityReference.opaque(
                    kind="ip", role="destination_ip", value=destination
                ),
                EventEntityReference.opaque(
                    kind="service", role="service", value="tcp:443"
                ),
            ),
        ).validate()
        self.store.add_event(event)
        self.entities.put(context)

    def _add_dns(self, event_id: str, observed_at: str, query: str):
        raw = json.dumps(
            {
                "_path": "dns",
                "query": query,
                "rcode_name": "NXDOMAIN",
                "qtype_name": "A",
                "answers": [],
            }
        )
        feature = extract_dns_behavior_features(
            event_id=event_id,
            source_type="zeek_json",
            raw_line=raw,
        )
        event = CanonicalEvent(
            event_id=event_id,
            source_id="zeek-dns",
            source_type="zeek_json",
            observed_at=observed_at,
            category="zeek.dns",
            severity="info",
            message_sha256="sha256:" + "c" * 64,
            parser_version="test/v1",
            evidence_ref="event:" + event_id,
        ).validate()
        context = EventEntityContext(
            event_id=event_id,
            references=(
                EventEntityReference.opaque(
                    kind="ip", role="source_ip", value="192.0.2.10"
                ),
                EventEntityReference(
                    kind="dns", role="dns_query", entity_ref=feature.query_entity_ref
                ).validate(),
            ),
        ).validate()
        self.store.add_event(event)
        self.entities.put(context)
        self.dns.put(feature)

    def test_reader_uses_bounded_history_and_current_without_leakage(self):
        for index in range(6):
            self._add_flow(
                f"evt-known-{index}",
                f"2026-08-31T{index:02d}:00:00+00:00",
                "198.51.100.20",
            )
        self._add_flow(
            "evt-rare-current",
            "2026-09-01T12:00:10+00:00",
            "203.0.113.77",
        )
        reader = BehaviorStoreReader(
            store=self.store,
            entity_store=self.entities,
            dns_store=self.dns,
            analyzer_config=BehaviorBaselineConfig(
                min_history_events=5,
                min_history_buckets=4,
                rare_max_occurrences=1,
            ),
            store_config=BehaviorStoreConfig(lookback_seconds=2 * 24 * 3600),
        )
        assessments = reader.analyze_window(
            BehaviorAnalysisWindow(
                starts_at="2026-09-01T12:00:00+00:00",
                ends_at="2026-09-01T12:01:00+00:00",
            )
        )
        peer = next(item for item in assessments if item.rule_id == RULE_RARE_PEER)
        self.assertEqual(peer.status, "signal")
        rendered = json.dumps(peer.public_dict(), sort_keys=True)
        self.assertNotIn("203.0.113.77", rendered)

    def test_reader_loads_persisted_dns_features_for_entropy_signal(self):
        self._add_dns(
            "evt-dns-current",
            "2026-09-01T12:00:10+00:00",
            "a8f9c2d7e1b6f0a3c5d9.example.org",
        )
        reader = BehaviorStoreReader(
            store=self.store,
            entity_store=self.entities,
            dns_store=self.dns,
            analyzer_config=BehaviorBaselineConfig(
                min_entropy_query_length=20,
                min_shannon_entropy=3.0,
                min_normalized_entropy=0.6,
            ),
        )
        assessments = reader.analyze_window(
            BehaviorAnalysisWindow(
                starts_at="2026-09-01T12:00:00+00:00",
                ends_at="2026-09-01T12:01:00+00:00",
            )
        )
        entropy = next(item for item in assessments if item.rule_id == RULE_DNS_ENTROPY)
        self.assertEqual(entropy.status, "signal")

    def test_current_event_is_not_used_as_its_own_history(self):
        self._add_flow(
            "evt-only-current",
            "2026-09-01T12:00:00+00:00",
            "198.51.100.20",
        )
        reader = BehaviorStoreReader(
            store=self.store,
            entity_store=self.entities,
            dns_store=self.dns,
            analyzer_config=BehaviorBaselineConfig(
                min_history_events=3,
                min_history_buckets=2,
            ),
        )
        assessments = reader.analyze_window(
            BehaviorAnalysisWindow(
                starts_at="2026-09-01T12:00:00+00:00",
                ends_at="2026-09-01T12:01:00+00:00",
            )
        )
        peer = next(item for item in assessments if item.rule_id == RULE_RARE_PEER)
        self.assertEqual(peer.status, "data_gap")
        self.assertEqual(peer.baseline_occurrences, 0)

    def test_window_lookback_event_and_entity_bounds_fail_closed(self):
        with self.assertRaises(MonitoringContractError):
            BehaviorAnalysisWindow(
                starts_at="2026-09-01T10:00:00+00:00",
                ends_at="2026-09-01T11:00:01+00:00",
            ).validate()
        with self.assertRaises(MonitoringContractError):
            BehaviorStoreConfig(lookback_seconds=31 * 24 * 3600).validate()

        self._add_flow("evt-a", "2026-09-01T12:00:00+00:00", "198.51.100.20")
        self._add_flow("evt-b", "2026-09-01T12:00:01+00:00", "198.51.100.21")
        window = BehaviorAnalysisWindow(
            starts_at="2026-09-01T12:00:00+00:00",
            ends_at="2026-09-01T12:01:00+00:00",
        )
        with self.assertRaises(MonitoringContractError):
            BehaviorStoreReader(
                store=self.store,
                entity_store=self.entities,
                dns_store=self.dns,
                analyzer_config=BehaviorBaselineConfig(max_events=1),
            ).read_inputs(window)
        with self.assertRaises(MonitoringContractError):
            BehaviorStoreReader(
                store=self.store,
                entity_store=self.entities,
                dns_store=self.dns,
                store_config=BehaviorStoreConfig(max_entity_rows=1),
            ).read_inputs(window)

    def test_reader_has_no_network_model_or_write_authority(self):
        source = inspect.getsource(behavior_store)
        for forbidden in (
            "import socket",
            "subprocess",
            "urlopen",
            "requests.",
            "OllamaClient",
            "generate_json",
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "firewall",
            "pcap",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
