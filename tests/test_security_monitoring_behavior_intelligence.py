from __future__ import annotations

import inspect
import json
import unittest

import three_agent.security_monitoring.behavior_intelligence as behavior
from three_agent.security_monitoring.behavior_intelligence import (
    BehaviorBaselineConfig,
    DeterministicBehaviorAnalyzer,
    RULE_DNS_CARDINALITY,
    RULE_DNS_ENTROPY,
    RULE_DNS_NXDOMAIN,
    RULE_RARE_PEER,
)
from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.dns_behavior import extract_dns_behavior_features
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference


def corr_event(
    event_id: str,
    observed_at: str,
    *,
    category: str = "zeek.conn",
    source_type: str = "zeek_json",
    source_ip: str = "192.0.2.10",
    destination_ip: str | None = "198.51.100.20",
    service: str | None = "tcp:443",
    dns_query: str | None = None,
) -> CorrelationEvent:
    refs = [EventEntityReference.opaque(kind="ip", role="source_ip", value=source_ip)]
    if destination_ip is not None:
        refs.append(
            EventEntityReference.opaque(
                kind="ip", role="destination_ip", value=destination_ip
            )
        )
    if service is not None:
        refs.append(EventEntityReference.opaque(kind="service", role="service", value=service))
    if dns_query is not None:
        refs.append(EventEntityReference.opaque(kind="dns", role="dns_query", value=dns_query))
    marker = "abcdef0123456789"[sum(ord(ch) for ch in event_id) % 16]
    event = CanonicalEvent(
        event_id=event_id,
        source_id="source-" + event_id,
        source_type=source_type,
        observed_at=observed_at,
        category=category,
        severity="info",
        message_sha256="sha256:" + marker * 64,
        parser_version="test/v1",
        evidence_ref="event:" + event_id,
    ).validate()
    return CorrelationEvent(
        event=event,
        context=EventEntityContext(event_id=event_id, references=tuple(refs)).validate(),
    ).validate()


def dns_pair(event_id: str, observed_at: str, query: str, *, rcode: str = "NOERROR"):
    item = corr_event(
        event_id,
        observed_at,
        category="zeek.dns",
        destination_ip=None,
        service=None,
        dns_query=query,
    )
    feature = extract_dns_behavior_features(
        event_id=event_id,
        source_type="zeek_json",
        raw_line=json.dumps(
            {
                "_path": "dns",
                "query": query,
                "rcode_name": rcode,
                "qtype_name": "A",
                "answers": [],
            }
        ),
    )
    return item, feature


class BehaviorIntelligenceTests(unittest.TestCase):
    def test_cold_baseline_returns_data_gap_not_rare_signal(self):
        current = corr_event("evt-current", "2026-09-01T12:00:00+00:00")
        history = [
            corr_event(f"evt-h-{index}", f"2026-09-01T0{index}:00:00+00:00")
            for index in range(3)
        ]
        analyzer = DeterministicBehaviorAnalyzer(
            BehaviorBaselineConfig(min_history_events=5, min_history_buckets=4)
        )
        assessments = analyzer.analyze(current_events=(current,), history_events=history)
        peer = next(item for item in assessments if item.rule_id == RULE_RARE_PEER)
        self.assertEqual(peer.status, "data_gap")
        self.assertEqual(peer.severity, "info")

    def test_unrelated_dns_history_does_not_warm_peer_baseline(self):
        history = [
            dns_pair(
                f"evt-dns-history-{index}",
                f"2026-08-31T{index:02d}:00:00+00:00",
                f"known-{index}.example.org",
            )[0]
            for index in range(6)
        ]
        current = corr_event(
            "evt-peer-current",
            "2026-09-01T12:00:00+00:00",
            destination_ip="203.0.113.77",
        )
        assessments = DeterministicBehaviorAnalyzer(
            BehaviorBaselineConfig(min_history_events=5, min_history_buckets=4)
        ).analyze(current_events=(current,), history_events=history)
        peer = next(item for item in assessments if item.rule_id == RULE_RARE_PEER)
        self.assertEqual(peer.status, "data_gap")
        self.assertEqual(peer.baseline_buckets, 0)

    def test_warm_baseline_distinguishes_known_and_rare_peer(self):
        history = []
        for index in range(6):
            history.append(
                corr_event(
                    f"evt-known-{index}",
                    f"2026-08-31T{index:02d}:00:00+00:00",
                    destination_ip="198.51.100.20",
                )
            )
        known = corr_event(
            "evt-known-current",
            "2026-09-01T12:00:00+00:00",
            destination_ip="198.51.100.20",
        )
        rare = corr_event(
            "evt-rare-current",
            "2026-09-01T12:00:01+00:00",
            destination_ip="203.0.113.77",
        )
        analyzer = DeterministicBehaviorAnalyzer(
            BehaviorBaselineConfig(
                min_history_events=5,
                min_history_buckets=4,
                rare_max_occurrences=1,
            )
        )
        assessments = analyzer.analyze(
            current_events=(known, rare),
            history_events=history,
        )
        peers = [item for item in assessments if item.rule_id == RULE_RARE_PEER]
        by_event = {item.event_ids[0]: item for item in peers}
        self.assertEqual(by_event["evt-known-current"].status, "normal")
        self.assertGreater(by_event["evt-known-current"].baseline_occurrences, 1)
        self.assertEqual(by_event["evt-rare-current"].status, "signal")
        self.assertEqual(by_event["evt-rare-current"].severity, "low")
        rendered = json.dumps(by_event["evt-rare-current"].public_dict(), sort_keys=True)
        self.assertNotIn("203.0.113.77", rendered)

    def test_high_entropy_dns_is_deterministic_metadata_only_signal(self):
        item, feature = dns_pair(
            "evt-entropy",
            "2026-09-01T12:00:00+00:00",
            "a8f9c2d7e1b6f0a3c5d9.example.org",
        )
        analyzer = DeterministicBehaviorAnalyzer(
            BehaviorBaselineConfig(
                min_entropy_query_length=20,
                min_shannon_entropy=3.0,
                min_normalized_entropy=0.6,
            )
        )
        first = analyzer.analyze(
            current_events=(item,), history_events=(), current_dns_features=(feature,)
        )
        second = analyzer.analyze(
            current_events=(item,), history_events=(), current_dns_features=(feature,)
        )
        self.assertEqual(first, second)
        entropy = next(value for value in first if value.rule_id == RULE_DNS_ENTROPY)
        self.assertEqual(entropy.status, "signal")
        self.assertEqual(entropy.severity, "medium")
        rendered = json.dumps(entropy.public_dict(), sort_keys=True).lower()
        self.assertNotIn("a8f9c2d7e1b6f0a3c5d9.example.org", rendered)

    def test_dns_cardinality_and_nxdomain_ratio_are_bounded_group_signals(self):
        pairs = [
            dns_pair(
                f"evt-dns-{index}",
                f"2026-09-01T12:00:0{index}+00:00",
                f"q{index}.example.org",
                rcode="NXDOMAIN" if index < 2 else "NOERROR",
            )
            for index in range(3)
        ]
        analyzer = DeterministicBehaviorAnalyzer(
            BehaviorBaselineConfig(
                min_current_dns_events=3,
                dns_cardinality_threshold=3,
                nxdomain_ratio_threshold=0.5,
            )
        )
        assessments = analyzer.analyze(
            current_events=tuple(item for item, _ in pairs),
            history_events=(),
            current_dns_features=tuple(feature for _, feature in pairs),
        )
        rules = {item.rule_id for item in assessments if item.status == "signal"}
        self.assertIn(RULE_DNS_CARDINALITY, rules)
        self.assertIn(RULE_DNS_NXDOMAIN, rules)

    def test_duplicate_replay_does_not_inflate_and_feature_mismatch_fails_closed(self):
        item, feature = dns_pair(
            "evt-replay",
            "2026-09-01T12:00:00+00:00",
            "replay.example.org",
        )
        analyzer = DeterministicBehaviorAnalyzer()
        first = analyzer.analyze(
            current_events=(item,),
            history_events=(),
            current_dns_features=(feature,),
        )
        replay = analyzer.analyze(
            current_events=(item, item),
            history_events=(),
            current_dns_features=(feature, feature),
        )
        self.assertEqual(first, replay)

        _other_item, other_feature = dns_pair(
            "evt-other",
            "2026-09-01T12:00:01+00:00",
            "other.example.org",
        )
        with self.assertRaises(MonitoringContractError):
            analyzer.analyze(
                current_events=(item,),
                history_events=(),
                current_dns_features=(other_feature,),
            )

    def test_bounds_and_authority_fail_closed(self):
        item = corr_event("evt-one", "2026-09-01T12:00:00+00:00")
        analyzer = DeterministicBehaviorAnalyzer(BehaviorBaselineConfig(max_events=1))
        with self.assertRaises(MonitoringContractError):
            analyzer.analyze(
                current_events=(item, corr_event("evt-two", "2026-09-01T12:00:01+00:00")),
                history_events=(),
            )
        source = inspect.getsource(behavior)
        for forbidden in (
            "import socket",
            "subprocess",
            "urlopen",
            "requests.",
            "OllamaClient",
            "generate_json",
            "firewall",
            "pcap",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
