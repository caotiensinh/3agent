from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.incident_timeline import IncidentTimeline, build_incident_timeline


def _event(
    event_id: str,
    *,
    category: str,
    observed_at: str,
    source_ip: str = "10.20.0.10",
    destination_ip: str = "10.20.0.20",
    dns_answer: str | None = None,
    evidence_ref: str | None = None,
    message_marker: str | None = None,
) -> CorrelationEvent:
    refs = [
        EventEntityReference.approved_asset(role="asset", asset_id="asset-timeline-1"),
        EventEntityReference.opaque(kind="ip", role="source_ip", value=source_ip),
    ]
    if category == "suricata.flow":
        refs.append(EventEntityReference.opaque(kind="ip", role="destination_ip", value=destination_ip))
    if dns_answer is not None:
        refs.append(EventEntityReference.opaque(kind="ip", role="dns_answer", value=dns_answer))
    event = CanonicalEvent(
        event_id=event_id,
        source_id="sensor-timeline-1",
        source_type="suricata_eve",
        observed_at=observed_at,
        category=category,
        severity="medium",
        message_sha256=sha256_fingerprint({"event": message_marker or event_id}),
        parser_version="parser-v1",
        evidence_ref=evidence_ref if evidence_ref is not None else f"evidence:{event_id}",
    ).validate()
    context = EventEntityContext(event_id=event_id, references=tuple(refs)).validate()
    return CorrelationEvent(event=event, context=context).validate()


def _dns_flow_pair() -> tuple[CorrelationEvent, CorrelationEvent]:
    dns = _event(
        "evt-timeline-dns",
        category="suricata.dns",
        observed_at="2026-09-02T11:00:00+00:00",
        dns_answer="10.20.0.20",
    )
    flow = _event(
        "evt-timeline-flow",
        category="suricata.flow",
        observed_at="2026-09-02T11:00:07+00:00",
        destination_ip="10.20.0.20",
    )
    return dns, flow


class SecurityIncidentTimelineV010Tests(unittest.TestCase):
    def test_timeline_is_deterministic_chronological_evidence_bound_and_advisory(self) -> None:
        dns, flow = _dns_flow_pair()

        first = build_incident_timeline((flow, dns))
        second = build_incident_timeline((dns, flow))

        self.assertIsInstance(first, IncidentTimeline)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.entry_count, 2)
        self.assertEqual(first.graph_count, 1)
        self.assertEqual(tuple(entry.event_id for entry in first.entries), ("evt-timeline-dns", "evt-timeline-flow"))
        self.assertEqual(tuple(entry.stage for entry in first.entries), ("DNS", "FLOW"))
        self.assertEqual(first.stage_types, ("DNS", "FLOW"))
        self.assertEqual(first.first_seen, "2026-09-02T11:00:00+00:00")
        self.assertEqual(first.last_seen, "2026-09-02T11:00:07+00:00")
        self.assertEqual(first.authority, "advisory")
        self.assertEqual(
            first.reason_codes,
            (
                "INCIDENT_TIMELINE_BUILT_DETERMINISTICALLY",
                "INCIDENT_TIMELINE_REQUIRES_EXACT_CORRELATION",
            ),
        )
        rendered = str(first.public_dict())
        self.assertNotIn("10.20.0.10", rendered)
        self.assertNotIn("10.20.0.20", rendered)

    def test_timeline_rejects_uncorrelated_events_instead_of_manufacturing_incident(self) -> None:
        dns, _flow = _dns_flow_pair()
        unrelated_flow = _event(
            "evt-timeline-unrelated-flow",
            category="suricata.flow",
            observed_at="2026-09-02T11:00:08+00:00",
            source_ip="10.20.0.99",
            destination_ip="10.20.0.77",
        )

        with self.assertRaisesRegex(MonitoringContractError, "requires deterministically correlated incident evidence"):
            build_incident_timeline((dns, unrelated_flow))

    def test_timeline_deduplicates_exact_event_and_rejects_conflicting_event_id(self) -> None:
        dns, flow = _dns_flow_pair()
        timeline = build_incident_timeline((dns, flow, flow))
        self.assertEqual(timeline.entry_count, 2)

        conflicting = _event(
            "evt-timeline-flow",
            category="suricata.flow",
            observed_at="2026-09-02T11:00:07+00:00",
            destination_ip="10.20.0.20",
            message_marker="conflicting-message-hash",
        )
        with self.assertRaisesRegex(MonitoringContractError, "conflicting timeline evidence"):
            build_incident_timeline((dns, flow, conflicting))

    def test_timeline_rejects_missing_evidence_anchor(self) -> None:
        dns, flow = _dns_flow_pair()
        flow_without_evidence = CorrelationEvent(
            event=replace(flow.event, evidence_ref=None),
            context=flow.context,
        )
        with self.assertRaisesRegex(MonitoringContractError, "requires evidence_ref"):
            build_incident_timeline((dns, flow_without_evidence))

    def test_timeline_entries_exactly_cover_correlated_graph_events(self) -> None:
        dns, flow = _dns_flow_pair()
        extra = _event(
            "evt-timeline-extra",
            category="suricata.flow",
            observed_at="2026-09-02T11:00:10+00:00",
            source_ip="10.20.0.55",
            destination_ip="10.20.0.66",
        )
        timeline = build_incident_timeline((extra, flow, dns))

        correlated = {event_id for graph in timeline.incident_graphs for event_id in graph.event_ids}
        self.assertEqual(correlated, {entry.event_id for entry in timeline.entries})
        self.assertNotIn("evt-timeline-extra", correlated)
        self.assertNotIn("evt-timeline-extra", {entry.event_id for entry in timeline.entries})


if __name__ == "__main__":
    unittest.main()
