from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import CanonicalEvent
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.operator_posture import reduce_operator_posture


def _event(
    *,
    event_id: str,
    observed_at: str,
    category: str,
    severity: str,
    references: tuple[EventEntityReference, ...],
) -> CorrelationEvent:
    return CorrelationEvent(
        event=CanonicalEvent(
            event_id=event_id,
            source_id="sensor-1",
            source_type="suricata_eve",
            observed_at=observed_at,
            category=category,
            severity=severity,
            message_sha256="sha256:" + "1" * 64,
            parser_version="test-v1",
        ),
        context=EventEntityContext(event_id=event_id, references=references),
    )


def _ref(*, kind: str, role: str, value: str) -> EventEntityReference:
    return EventEntityReference.opaque(kind=kind, role=role, value=value)


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = {str(key) for key in value}
        for nested in value.values():
            keys.update(_all_keys(nested))
        return keys
    if isinstance(value, (list, tuple)):
        keys: set[str] = set()
        for nested in value:
            keys.update(_all_keys(nested))
        return keys
    return set()


class SecurityNetworkTriagePostureTests(unittest.TestCase):
    def test_network_triage_posture_reduces_real_dns_flow_graph_to_fixed_aggregates(self) -> None:
        source_ip = "10.0.0.10"
        destination_ip = "10.0.0.20"
        events = (
            _event(
                event_id="event-dns-1",
                observed_at="2026-09-06T00:00:00Z",
                category="suricata.dns",
                severity="medium",
                references=(
                    _ref(kind="ip", role="source_ip", value=source_ip),
                    _ref(kind="ip", role="dns_answer", value=destination_ip),
                ),
            ),
            _event(
                event_id="event-flow-1",
                observed_at="2026-09-06T00:01:00Z",
                category="suricata.flow",
                severity="medium",
                references=(
                    _ref(kind="ip", role="source_ip", value=source_ip),
                    _ref(kind="ip", role="destination_ip", value=destination_ip),
                ),
            ),
        )

        posture = reduce_operator_posture(soc={}, assets={}, correlation_events=events)
        triage = posture["network_triage"]

        self.assertTrue(triage["available"])
        self.assertEqual(triage["data_state"], "available")
        self.assertEqual(triage["triage_count"], 1)
        self.assertEqual(triage["high_priority_count"], 0)
        self.assertEqual(triage["severity_counts"]["medium"], 1)
        self.assertEqual(triage["confidence_counts"]["medium"], 1)
        self.assertEqual(triage["priority_counts"]["normal"], 1)
        self.assertEqual(triage["triage_kind_counts"]["dns-flow"], 1)
        self.assertTrue(triage["authority"]["advisory_only"])
        self.assertFalse(triage["authority"]["network_execution"])
        self.assertFalse(triage["authority"]["packet_capture_execution"])
        self.assertFalse(triage["authority"]["command_execution"])
        self.assertFalse(triage["authority"]["remediation_execution"])

        forbidden_raw_keys = {
            "triage_id",
            "graph_id",
            "graph_fingerprint",
            "reason_codes",
            "stage_types",
            "rule_ids",
            "event_ids",
            "evidence_refs",
            "entity_refs",
            "first_seen",
            "last_seen",
        }
        self.assertTrue(forbidden_raw_keys.isdisjoint(_all_keys(triage)))

    def test_network_triage_posture_has_explicit_empty_state_and_zero_buckets(self) -> None:
        posture = reduce_operator_posture(soc={}, assets={}, correlation_events=())
        triage = posture["network_triage"]

        self.assertFalse(triage["available"])
        self.assertEqual(triage["data_state"], "empty")
        self.assertEqual(triage["triage_count"], 0)
        self.assertEqual(triage["high_priority_count"], 0)
        self.assertTrue(all(count == 0 for count in triage["severity_counts"].values()))
        self.assertTrue(all(count == 0 for count in triage["confidence_counts"].values()))
        self.assertTrue(all(count == 0 for count in triage["priority_counts"].values()))
        self.assertTrue(all(count == 0 for count in triage["triage_kind_counts"].values()))


if __name__ == "__main__":
    unittest.main()
