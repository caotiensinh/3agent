from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.temporal_behavior import TemporalAnalysisWindow, TemporalBucketConfig
from three_agent.security_monitoring.temporal_scenarios import (
    DeterministicTemporalScenarioEngine,
    TemporalScenario,
)


_DIGEST = "sha256:" + "b" * 64


def event(
    n: int,
    *,
    second: int,
    asset_id: str = "switch-01",
    category: str = "suricata.dns",
    evidence: bool = True,
) -> CorrelationEvent:
    record = CanonicalEvent(
        event_id=f"event-{asset_id}-{n}",
        source_id="sensor-01",
        source_type="suricata_eve",
        observed_at=f"2026-09-01T14:{second // 60:02d}:{second % 60:02d}Z",
        category=category,
        severity="info",
        message_sha256=_DIGEST,
        parser_version="parser-v1",
        evidence_ref=f"evidence:{asset_id}:{n}" if evidence else None,
    ).validate()
    context = EventEntityContext(
        event_id=record.event_id,
        references=(EventEntityReference.approved_asset(role="asset", asset_id=asset_id),),
    ).validate()
    return CorrelationEvent(event=record, context=context).validate()


class TemporalScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = TemporalAnalysisWindow(
            starts_at="2026-09-01T14:00:00Z",
            ends_at="2026-09-01T14:04:00Z",
        )
        self.bucket_config = TemporalBucketConfig(
            bucket_seconds=60,
            max_window_seconds=3600,
            max_events=100,
            max_buckets=60,
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

    def engine(self, scenario: TemporalScenario | None = None, **kwargs) -> DeterministicTemporalScenarioEngine:
        return DeterministicTemporalScenarioEngine(
            (scenario or self.scenario,),
            bucket_config=self.bucket_config,
            **kwargs,
        )

    def test_positive_consecutive_buckets_produce_one_advisory_assessment(self) -> None:
        events = (
            event(1, second=10),
            event(2, second=20),
            event(3, second=70),
            event(4, second=80),
        )
        result = self.engine().evaluate(window=self.window, events=events)
        self.assertEqual(len(result), 1)
        assessment = result[0]
        self.assertEqual(assessment.bucket_indices, (0, 1))
        self.assertEqual(assessment.scope_entity_ref, "asset:switch-01")
        self.assertEqual(assessment.authority, "advisory")
        self.assertEqual(len(assessment.event_ids), 4)
        self.assertEqual(len(assessment.evidence_refs), 4)

    def test_cross_asset_events_are_never_combined(self) -> None:
        events = (
            event(1, second=10, asset_id="switch-01"),
            event(1, second=20, asset_id="switch-02"),
            event(2, second=70, asset_id="switch-01"),
            event(2, second=80, asset_id="switch-02"),
        )
        self.assertEqual(self.engine().evaluate(window=self.window, events=events), ())

    def test_nonconsecutive_buckets_require_explicit_nonconsecutive_policy(self) -> None:
        events = (
            event(1, second=10),
            event(2, second=20),
            event(3, second=130),
            event(4, second=140),
        )
        self.assertEqual(self.engine().evaluate(window=self.window, events=events), ())
        relaxed = TemporalScenario(
            scenario_id="DNS_REPEATED_V1",
            stage="DNS",
            scope_role="asset",
            min_events_per_bucket=2,
            min_matching_buckets=2,
            require_consecutive=False,
            severity="low",
        )
        result = self.engine(relaxed).evaluate(window=self.window, events=events)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket_indices, (0, 2))

    def test_shuffled_replay_is_byte_identical(self) -> None:
        events = (
            event(1, second=10),
            event(2, second=20),
            event(3, second=70),
            event(4, second=80),
        )
        left = self.engine().evaluate(window=self.window, events=events)
        right = self.engine().evaluate(window=self.window, events=reversed(events))
        self.assertEqual(tuple(item.to_json() for item in left), tuple(item.to_json() for item in right))
        self.assertEqual(tuple(item.fingerprint for item in left), tuple(item.fingerprint for item in right))

    def test_matched_signal_without_durable_evidence_fails_closed(self) -> None:
        events = (
            event(1, second=10, evidence=False),
            event(2, second=20),
            event(3, second=70),
            event(4, second=80),
        )
        with self.assertRaises(MonitoringContractError):
            self.engine().evaluate(window=self.window, events=events)

    def test_scenario_cannot_grant_authority_or_use_unknown_stage_role(self) -> None:
        with self.assertRaises(MonitoringContractError):
            TemporalScenario(
                scenario_id="BAD_AUTH",
                stage="DNS",
                scope_role="asset",
                authority="remediate",
            ).validate()
        with self.assertRaises(MonitoringContractError):
            TemporalScenario(scenario_id="BAD_STAGE", stage="PCAP", scope_role="asset").validate()
        with self.assertRaises(MonitoringContractError):
            TemporalScenario(scenario_id="BAD_ROLE", stage="DNS", scope_role="raw_user").validate()

    def test_assessment_bound_fails_closed_instead_of_truncating(self) -> None:
        events = (
            event(1, second=10, asset_id="switch-01"),
            event(2, second=20, asset_id="switch-01"),
            event(3, second=70, asset_id="switch-01"),
            event(4, second=80, asset_id="switch-01"),
            event(1, second=10, asset_id="switch-02"),
            event(2, second=20, asset_id="switch-02"),
            event(3, second=70, asset_id="switch-02"),
            event(4, second=80, asset_id="switch-02"),
        )
        with self.assertRaises(MonitoringContractError):
            self.engine(max_assessments=1).evaluate(window=self.window, events=events)


if __name__ == "__main__":
    unittest.main()
