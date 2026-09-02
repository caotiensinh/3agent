from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.discovery_candidates import (
    DiscoveryCandidate,
    deduplicate_discovery_candidates,
    discovery_identity_ref,
)


class DiscoveryCandidateTests(unittest.TestCase):
    def candidate(
        self,
        *,
        identity_value: str = "192.0.2.10",
        first_seen: str = "2026-09-01T14:00:00Z",
        last_seen: str = "2026-09-01T14:00:00Z",
        count: int = 1,
        confidence: int = 5000,
        provenance: tuple[str, ...] = ("sensor:arp-01",),
        evidence: tuple[str, ...] = ("evidence:1",),
    ) -> DiscoveryCandidate:
        return DiscoveryCandidate.build(
            identity_kind="ip",
            identity_value=identity_value,
            first_seen=first_seen,
            last_seen=last_seen,
            observation_count=count,
            confidence_basis_points=confidence,
            provenance_refs=provenance,
            evidence_refs=evidence,
        )

    def test_raw_network_identity_is_not_retained_in_candidate_contract(self) -> None:
        candidate = self.candidate(identity_value="192.0.2.10")
        payload = candidate.to_dict()
        self.assertNotIn("192.0.2.10", candidate.to_json())
        self.assertEqual(candidate.identity_kind, "ip")
        self.assertTrue(str(payload["identity_ref"]).startswith("candidate:ip:sha256:"))
        self.assertNotIn("asset_id", payload)
        self.assertNotIn("management_host", payload)
        self.assertNotIn("collector_capabilities", payload)
        self.assertNotIn("credential_ref", payload)
        self.assertEqual(payload["trust_state"], "untrusted")
        self.assertEqual(payload["inventory_status"], "not_enrolled")
        self.assertEqual(payload["authority"], "none")

    def test_identity_normalization_is_deterministic(self) -> None:
        self.assertEqual(
            discovery_identity_ref("mac", "AA-BB-CC-DD-EE-FF"),
            discovery_identity_ref("mac", "aa:bb:cc:dd:ee:ff"),
        )
        self.assertEqual(
            discovery_identity_ref("dns", "Example.COM."),
            discovery_identity_ref("dns", "example.com"),
        )
        self.assertEqual(
            discovery_identity_ref("ip", "2001:0db8::1"),
            discovery_identity_ref("ip", "2001:db8::1"),
        )

    def test_dedupe_merges_time_count_provenance_and_evidence_without_trust_change(self) -> None:
        left = self.candidate(
            first_seen="2026-09-01T14:00:00Z",
            last_seen="2026-09-01T14:01:00Z",
            count=2,
            confidence=4000,
            provenance=("sensor:arp-01",),
            evidence=("evidence:1",),
        )
        right = self.candidate(
            first_seen="2026-09-01T14:00:30Z",
            last_seen="2026-09-01T14:02:00Z",
            count=3,
            confidence=7000,
            provenance=("sensor:arp-02",),
            evidence=("evidence:2",),
        )
        merged = deduplicate_discovery_candidates((right, left))
        self.assertEqual(len(merged), 1)
        item = merged[0]
        self.assertEqual(item.first_seen, "2026-09-01T14:00:00Z")
        self.assertEqual(item.last_seen, "2026-09-01T14:02:00Z")
        self.assertEqual(item.observation_count, 5)
        self.assertEqual(item.confidence_basis_points, 7000)
        self.assertEqual(item.provenance_refs, ("sensor:arp-01", "sensor:arp-02"))
        self.assertEqual(item.evidence_refs, ("evidence:1", "evidence:2"))
        self.assertEqual(item.trust_state, "untrusted")
        self.assertEqual(item.inventory_status, "not_enrolled")
        self.assertEqual(item.authority, "none")

    def test_input_order_does_not_change_deduplicated_bytes(self) -> None:
        a = self.candidate(identity_value="192.0.2.10", evidence=("evidence:a",))
        b = self.candidate(identity_value="192.0.2.11", evidence=("evidence:b",))
        left = deduplicate_discovery_candidates((a, b))
        right = deduplicate_discovery_candidates((b, a))
        self.assertEqual(tuple(item.to_json() for item in left), tuple(item.to_json() for item in right))
        self.assertEqual(tuple(item.fingerprint for item in left), tuple(item.fingerprint for item in right))

    def test_candidate_cannot_self_promote_trust_inventory_or_authority(self) -> None:
        base = self.candidate()
        with self.assertRaises(MonitoringContractError):
            DiscoveryCandidate(**{**base.__dict__, "trust_state": "trusted"}).validate()
        with self.assertRaises(MonitoringContractError):
            DiscoveryCandidate(**{**base.__dict__, "inventory_status": "approved"}).validate()
        with self.assertRaises(MonitoringContractError):
            DiscoveryCandidate(**{**base.__dict__, "authority": "network_read"}).validate()

    def test_invalid_identity_time_confidence_and_reference_bounds_fail_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            discovery_identity_ref("ip", "999.999.999.999")
        with self.assertRaises(MonitoringContractError):
            discovery_identity_ref("mac", "not-a-mac")
        with self.assertRaises(MonitoringContractError):
            self.candidate(first_seen="2026-09-01T14:02:00Z", last_seen="2026-09-01T14:01:00Z")
        with self.assertRaises(MonitoringContractError):
            self.candidate(confidence=10001)
        with self.assertRaises(MonitoringContractError):
            self.candidate(provenance=())
        with self.assertRaises(MonitoringContractError):
            self.candidate(evidence=())

    def test_dedupe_bounds_fail_closed(self) -> None:
        a = self.candidate(identity_value="192.0.2.10")
        b = self.candidate(identity_value="192.0.2.11")
        with self.assertRaises(MonitoringContractError):
            deduplicate_discovery_candidates((a, b), max_input_candidates=1)
        with self.assertRaises(MonitoringContractError):
            deduplicate_discovery_candidates((a, b), max_output_candidates=1)


if __name__ == "__main__":
    unittest.main()
