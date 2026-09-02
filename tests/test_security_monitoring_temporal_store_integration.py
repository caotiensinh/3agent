from __future__ import annotations

import unittest

from three_agent.security_monitoring import (
    BehaviorAnalysisWindow,
    BehaviorStoreReader,
    DeterministicTemporalScenarioEngine,
    TemporalAnalysisWindow,
    TemporalBucketConfig,
    TemporalScenario,
)
from three_agent.security_monitoring.contracts import CanonicalEvent
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference


_DIGEST = "sha256:" + "c" * 64


def event(n: int, second: int) -> CorrelationEvent:
    record = CanonicalEvent(
        event_id=f"event-{n}",
        source_id="sensor-01",
        source_type="suricata_eve",
        observed_at=f"2026-09-01T14:{second // 60:02d}:{second % 60:02d}Z",
        category="suricata.dns",
        severity="info",
        message_sha256=_DIGEST,
        parser_version="parser-v1",
        evidence_ref=f"evidence:{n}",
    ).validate()
    return CorrelationEvent(
        event=record,
        context=EventEntityContext(
            event_id=record.event_id,
            references=(EventEntityReference.approved_asset(role="asset", asset_id="switch-01"),),
        ).validate(),
    ).validate()


class FakeBehaviorStoreReader(BehaviorStoreReader):
    def __init__(self, current: tuple[CorrelationEvent, ...]) -> None:
        self.current = current

    def read_temporal_events(self, window: BehaviorAnalysisWindow) -> tuple[CorrelationEvent, ...]:
        window.validate()
        return self.current


class TemporalStoreIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = (
            event(1, 10),
            event(2, 20),
            event(3, 70),
            event(4, 80),
        )
        self.scenario = TemporalScenario(
            scenario_id="DNS_BURST_V1",
            stage="DNS",
            scope_role="asset",
            min_events_per_bucket=2,
            min_matching_buckets=2,
            require_consecutive=True,
            severity="medium",
        )
        self.config = TemporalBucketConfig(
            bucket_seconds=60,
            max_window_seconds=3600,
            max_events=100,
            max_buckets=60,
        )

    def test_store_adapter_reuses_current_events_and_matches_direct_engine(self) -> None:
        reader = FakeBehaviorStoreReader(self.events)
        behavior_window = BehaviorAnalysisWindow(
            starts_at="2026-09-01T23:00:00+09:00",
            ends_at="2026-09-01T23:03:00+09:00",
        )
        integrated = reader.analyze_temporal_window(
            behavior_window,
            scenarios=(self.scenario,),
            bucket_config=self.config,
        )
        direct = DeterministicTemporalScenarioEngine(
            (self.scenario,),
            bucket_config=self.config,
        ).evaluate(
            window=TemporalAnalysisWindow(
                starts_at="2026-09-01T14:00:00Z",
                ends_at="2026-09-01T14:03:00Z",
            ),
            events=self.events,
        )
        self.assertEqual(tuple(item.to_json() for item in integrated), tuple(item.to_json() for item in direct))
        self.assertEqual(len(integrated), 1)
        self.assertEqual(integrated[0].authority, "advisory")

    def test_store_adapter_returns_assessment_not_finding_or_response(self) -> None:
        reader = FakeBehaviorStoreReader(self.events)
        result = reader.analyze_temporal_window(
            BehaviorAnalysisWindow(
                starts_at="2026-09-01T14:00:00Z",
                ends_at="2026-09-01T14:03:00Z",
            ),
            scenarios=(self.scenario,),
            bucket_config=self.config,
        )
        self.assertEqual(result[0].schema_version, "workspace-security-monitoring/temporal-assessment-v1")
        self.assertFalse(hasattr(result[0], "remediation"))
        self.assertFalse(hasattr(result[0], "network_action"))


if __name__ == "__main__":
    unittest.main()
