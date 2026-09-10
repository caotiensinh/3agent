from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext
from three_agent.security_monitoring.temporal_behavior import (
    DeterministicTemporalBucketizer,
    TemporalAnalysisWindow,
    TemporalBucketConfig,
)


_DIGEST = "sha256:" + "a" * 64


def event(n: int, *, second: int, category: str = "suricata.dns", event_id: str | None = None) -> CorrelationEvent:
    record = CanonicalEvent(
        event_id=event_id or f"event-{n}",
        source_id="sensor-01",
        source_type="suricata_eve",
        observed_at=f"2026-09-01T14:{second // 60:02d}:{second % 60:02d}Z",
        category=category,
        severity="info",
        message_sha256=_DIGEST,
        parser_version="parser-v1",
        evidence_ref=f"evidence:{n}",
    ).validate()
    return CorrelationEvent(
        event=record,
        context=EventEntityContext(event_id=record.event_id, references=()).validate(),
    ).validate()


class TemporalBucketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = TemporalAnalysisWindow(
            starts_at="2026-09-01T14:00:00Z",
            ends_at="2026-09-01T14:03:00Z",
        )
        self.bucketizer = DeterministicTemporalBucketizer(
            TemporalBucketConfig(bucket_seconds=60, max_window_seconds=3600, max_events=100, max_buckets=60)
        )

    def test_shuffled_input_produces_identical_buckets_and_fingerprints(self) -> None:
        first_events = (
            event(1, second=10),
            event(2, second=50, category="suricata.flow"),
            event(3, second=70),
        )
        left = self.bucketizer.bucketize(window=self.window, events=first_events)
        right = self.bucketizer.bucketize(window=self.window, events=reversed(first_events))
        self.assertEqual(tuple(item.to_json() for item in left), tuple(item.to_json() for item in right))
        self.assertEqual(tuple(item.fingerprint for item in left), tuple(item.fingerprint for item in right))
        self.assertEqual([item.bucket_index for item in left], [0, 1])
        self.assertEqual(left[0].event_ids, ("event-1", "event-2"))
        self.assertEqual(left[0].stage_types, ("DNS", "FLOW"))

    def test_exact_duplicate_is_deduplicated(self) -> None:
        item = event(1, second=10)
        buckets = self.bucketizer.bucketize(window=self.window, events=(item, item))
        self.assertEqual(len(buckets), 1)
        self.assertEqual(buckets[0].event_ids, ("event-1",))

    def test_conflicting_duplicate_event_id_fails_closed(self) -> None:
        left = event(1, second=10, category="suricata.dns", event_id="event-same")
        right = event(2, second=10, category="suricata.flow", event_id="event-same")
        with self.assertRaises(MonitoringContractError):
            self.bucketizer.bucketize(window=self.window, events=(left, right))

    def test_out_of_window_event_is_not_silently_ignored(self) -> None:
        with self.assertRaises(MonitoringContractError):
            self.bucketizer.bucketize(window=self.window, events=(event(1, second=180),))

    def test_event_bound_is_enforced(self) -> None:
        small = DeterministicTemporalBucketizer(
            TemporalBucketConfig(bucket_seconds=60, max_window_seconds=3600, max_events=2, max_buckets=60)
        )
        with self.assertRaises(MonitoringContractError):
            small.bucketize(
                window=self.window,
                events=(event(1, second=10), event(2, second=20), event(3, second=30)),
            )

    def test_window_requires_utc_and_config_must_cover_bucket_count(self) -> None:
        with self.assertRaises(MonitoringContractError):
            TemporalAnalysisWindow(
                starts_at="2026-09-01T14:00:00+09:00",
                ends_at="2026-09-01T14:03:00+09:00",
            ).validate()
        with self.assertRaises(MonitoringContractError):
            TemporalBucketConfig(
                bucket_seconds=10,
                max_window_seconds=3600,
                max_events=100,
                max_buckets=10,
            ).validate()


if __name__ == "__main__":
    unittest.main()
