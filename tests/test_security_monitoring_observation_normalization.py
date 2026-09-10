from __future__ import annotations

import json
import unittest

from three_agent.security_monitoring.contracts import ObservationRecord
from three_agent.security_monitoring.entity_context import opaque_entity_ref
from three_agent.security_monitoring.observation_normalization import normalize_observation_evidence


class ObservationNormalizationTests(unittest.TestCase):
    def test_snmp_interface_observation_becomes_asset_and_hashed_interface_evidence(self):
        observation = ObservationRecord(
            run_id="run-snmp-001",
            asset_id="switch-rd-01",
            collector="snmpv3_read",
            observed_at="2026-09-01T10:20:00+09:00",
            metric="if_Ethernet1/1_rx_errors",
            status="ok",
            value=3,
            unit="count",
        ).validate()
        normalized = normalize_observation_evidence(observation)

        self.assertRegex(normalized.observation.evidence_ref, r"^observation:[0-9a-f]{32}$")
        self.assertEqual(normalized.event.evidence_ref, normalized.observation.evidence_ref)
        self.assertEqual(normalized.event.source_type, "monitoring_observation")
        self.assertEqual(normalized.event.category, "monitoring.snmpv3_read")
        self.assertEqual(normalized.event.severity, "info")
        self.assertEqual(
            normalized.entity_context.refs_for_role("asset"),
            ("asset:switch-rd-01",),
        )
        self.assertEqual(
            normalized.entity_context.refs_for_role("interface"),
            (opaque_entity_ref("interface", "Ethernet1/1"),),
        )
        public = json.dumps(normalized.entity_context.public_dict(), sort_keys=True)
        self.assertNotIn("Ethernet1/1", public)
        self.assertNotIn("credential", public.lower())
        self.assertNotIn("secret-ref", public.lower())

    def test_device_health_without_interface_is_asset_scoped_and_deterministic(self):
        observation = ObservationRecord(
            run_id="run-health-001",
            asset_id="router-rd-01",
            collector="icmp_echo",
            observed_at="2026-09-01T10:21:00+09:00",
            metric="icmp_reachable",
            status="ok",
            value=True,
            unit="bool",
        ).validate()
        first = normalize_observation_evidence(observation)
        second = normalize_observation_evidence(observation)

        self.assertEqual(first, second)
        self.assertEqual(first.entity_context.refs_for_role("asset"), ("asset:router-rd-01",))
        self.assertEqual(first.entity_context.refs_for_role("interface"), ())
        self.assertIsNone(observation.evidence_ref)
        self.assertIsNotNone(first.observation.evidence_ref)


if __name__ == "__main__":
    unittest.main()
