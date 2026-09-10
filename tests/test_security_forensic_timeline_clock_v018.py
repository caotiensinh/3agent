from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.forensic_evidence import ForensicEventTime
from three_agent.security_monitoring.forensic_timeline_clock import build_forensic_timeline_clock_view
from three_agent.security_monitoring.incident_timeline import build_incident_timeline


def _event(event_id: str, *, category: str, observed_at: str, evidence_ref: str, dns_answer: str | None = None):
    refs = [
        EventEntityReference.approved_asset(role="asset", asset_id="asset-clock-01"),
        EventEntityReference.opaque(kind="ip", role="source_ip", value="10.55.0.10"),
    ]
    if category == "suricata.flow":
        refs.append(EventEntityReference.opaque(kind="ip", role="destination_ip", value="10.55.0.20"))
    if dns_answer is not None:
        refs.append(EventEntityReference.opaque(kind="ip", role="dns_answer", value=dns_answer))
    canonical = CanonicalEvent(
        event_id=event_id,
        source_id="sensor-clock-01",
        source_type="suricata_eve",
        observed_at=observed_at,
        category=category,
        severity="medium",
        message_sha256=sha256_fingerprint({"event": event_id}),
        parser_version="v1",
        evidence_ref=evidence_ref,
    ).validate()
    return CorrelationEvent(
        event=canonical,
        context=EventEntityContext(event_id=event_id, references=tuple(refs)).validate(),
    ).validate()


def _timeline():
    dns = _event(
        "evt-clock-dns",
        category="suricata.dns",
        observed_at="2026-09-02T15:00:00Z",
        evidence_ref="evidence:clock-dns",
        dns_answer="10.55.0.20",
    )
    flow = _event(
        "evt-clock-flow",
        category="suricata.flow",
        observed_at="2026-09-02T15:00:05Z",
        evidence_ref="evidence:clock-flow",
    )
    return build_incident_timeline((flow, dns))


def _time(original: str, normalized: str, *, uncertainty_ms: int):
    return ForensicEventTime(
        original_timestamp=original,
        normalized_utc=normalized,
        source_clock_ref="clock:sensor-clock-01",
        uncertainty_ms=uncertainty_ms,
    ).validate()


class SecurityForensicTimelineClockV018Tests(unittest.TestCase):
    def test_clock_view_is_deterministic_and_preserves_original_time(self) -> None:
        timeline = _timeline()
        mapping = {
            "evt-clock-dns": _time("2026-09-03T00:00:00+09:00", "2026-09-02T15:00:00Z", uncertainty_ms=10),
            "evt-clock-flow": _time("2026-09-03T00:00:05+09:00", "2026-09-02T15:00:05Z", uncertainty_ms=10),
        }
        first = build_forensic_timeline_clock_view(timeline, mapping)
        second = build_forensic_timeline_clock_view(timeline, dict(reversed(tuple(mapping.items()))))
        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.timeline_fingerprint, timeline.fingerprint)
        self.assertEqual(first.missing_clock_event_ids, ())
        self.assertEqual(first.conflict_event_ids, ())
        self.assertEqual(first.entries[0].delta_ms, 0)
        self.assertIn("+09:00", first.entries[0].original_timestamp)
        self.assertEqual(first.authority, "advisory")

    def test_clock_conflict_is_explicit_when_delta_exceeds_uncertainty(self) -> None:
        timeline = _timeline()
        view = build_forensic_timeline_clock_view(
            timeline,
            {
                "evt-clock-dns": _time("2026-09-03T00:00:01+09:00", "2026-09-02T15:00:01Z", uncertainty_ms=100),
                "evt-clock-flow": _time("2026-09-03T00:00:05+09:00", "2026-09-02T15:00:05Z", uncertainty_ms=100),
            },
        )
        self.assertEqual(view.conflict_event_ids, ("evt-clock-dns",))
        dns = next(row for row in view.entries if row.event_id == "evt-clock-dns")
        self.assertEqual(dns.delta_ms, 1000)
        self.assertTrue(dns.clock_conflict)

    def test_missing_clock_is_visibility_gap_not_fabricated_time(self) -> None:
        timeline = _timeline()
        view = build_forensic_timeline_clock_view(
            timeline,
            {"evt-clock-dns": _time("2026-09-03T00:00:00+09:00", "2026-09-02T15:00:00Z", uncertainty_ms=0)},
        )
        self.assertEqual(view.missing_clock_event_ids, ("evt-clock-flow",))
        self.assertEqual(tuple(row.event_id for row in view.entries), ("evt-clock-dns",))

    def test_clock_input_outside_timeline_fails_closed(self) -> None:
        timeline = _timeline()
        with self.assertRaisesRegex(MonitoringContractError, "outside timeline"):
            build_forensic_timeline_clock_view(
                timeline,
                {"evt-not-in-timeline": _time("2026-09-03T00:00:00+09:00", "2026-09-02T15:00:00Z", uncertainty_ms=0)},
            )


if __name__ == "__main__":
    unittest.main()
