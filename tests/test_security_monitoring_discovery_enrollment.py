from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError
from three_agent.security_monitoring.discovery_candidate_store import DiscoveryCandidateStore
from three_agent.security_monitoring.discovery_candidates import DiscoveryCandidate
from three_agent.security_monitoring.discovery_enrollment import (
    DiscoveryEnrollmentRequest,
    DiscoveryEnrollmentService,
)
from three_agent.security_monitoring.storage import MonitoringStore


class DiscoveryEnrollmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "monitoring.db"
        self.monitoring = MonitoringStore(self.db)
        self.candidates = DiscoveryCandidateStore(self.monitoring)
        self.service = DiscoveryEnrollmentService(store=self.monitoring, candidate_store=self.candidates)
        self.service.initialize()
        self.candidate = self.candidates.put(
            DiscoveryCandidate.build(
                identity_kind="ip",
                identity_value="192.0.2.10",
                first_seen="2026-09-01T14:00:00Z",
                last_seen="2026-09-01T14:00:00Z",
                observation_count=1,
                confidence_basis_points=8000,
                provenance_refs=("sensor:arp-01",),
                evidence_refs=("evidence:1",),
            )
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def asset(self, **overrides) -> AssetInventoryRecord:
        payload = {
            "asset_id": "switch-01",
            "role": "switch",
            "management_host": "192.0.2.10",
            "collector_capabilities": ("local_net_read",),
            "allowed_tcp_ports": (),
            "data_class": "confidential",
            "enabled": True,
        }
        payload.update(overrides)
        return AssetInventoryRecord(**payload).validate()

    def request(self, **overrides) -> DiscoveryEnrollmentRequest:
        payload = {
            "candidate_id": self.candidate.candidate_id,
            "candidate_fingerprint": self.candidate.fingerprint,
            "asset": self.asset(),
            "operator_approval_ref": "approval-ref:ticket-123",
        }
        payload.update(overrides)
        return DiscoveryEnrollmentRequest(**payload)

    def test_operator_approval_enrolls_matching_candidate_and_preserves_candidate_state(self) -> None:
        receipt = self.service.enroll(
            self.request(),
            enrolled_at="2026-09-01T14:10:00Z",
        )
        self.assertEqual(receipt.authority, "operator_approved")
        self.assertEqual(receipt.asset_id, "switch-01")
        stored_asset = self.monitoring.get_asset("switch-01")
        self.assertIsNotNone(stored_asset)
        assert stored_asset is not None
        self.assertEqual(stored_asset.fingerprint, self.asset().fingerprint)

        candidate_after = self.candidates.get(self.candidate.candidate_id)
        self.assertIsNotNone(candidate_after)
        assert candidate_after is not None
        self.assertEqual(candidate_after.trust_state, "untrusted")
        self.assertEqual(candidate_after.inventory_status, "not_enrolled")
        self.assertEqual(candidate_after.authority, "none")
        self.assertEqual(candidate_after.fingerprint, self.candidate.fingerprint)

    def test_retry_at_later_time_returns_original_receipt_without_mutation(self) -> None:
        first = self.service.enroll(self.request(), enrolled_at="2026-09-01T14:10:00Z")
        second = self.service.enroll(self.request(), enrolled_at="2026-09-01T14:20:00Z")
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(second.enrolled_at, "2026-09-01T14:10:00Z")

    def test_missing_or_invalid_operator_approval_fails_before_inventory_write(self) -> None:
        with self.assertRaises(MonitoringContractError):
            self.service.enroll(
                self.request(operator_approval_ref="model-approved"),
                enrolled_at="2026-09-01T14:10:00Z",
            )
        self.assertIsNone(self.monitoring.get_asset("switch-01"))

    def test_management_host_must_hash_to_exact_candidate_identity(self) -> None:
        with self.assertRaises(MonitoringContractError):
            self.service.enroll(
                self.request(asset=self.asset(management_host="192.0.2.11")),
                enrolled_at="2026-09-01T14:10:00Z",
            )
        self.assertIsNone(self.monitoring.get_asset("switch-01"))

    def test_mac_candidate_requires_future_explicit_cross_identity_binding(self) -> None:
        mac_candidate = self.candidates.put(
            DiscoveryCandidate.build(
                identity_kind="mac",
                identity_value="aa:bb:cc:dd:ee:ff",
                first_seen="2026-09-01T14:00:00Z",
                last_seen="2026-09-01T14:00:00Z",
                observation_count=1,
                confidence_basis_points=8000,
                provenance_refs=("sensor:arp-01",),
                evidence_refs=("evidence:mac",),
            )
        )
        with self.assertRaises(MonitoringContractError):
            self.service.enroll(
                DiscoveryEnrollmentRequest(
                    candidate_id=mac_candidate.candidate_id,
                    candidate_fingerprint=mac_candidate.fingerprint,
                    asset=self.asset(),
                    operator_approval_ref="approval-ref:ticket-mac",
                ),
                enrolled_at="2026-09-01T14:10:00Z",
            )
        self.assertIsNone(self.monitoring.get_asset("switch-01"))

    def test_stale_candidate_fingerprint_fails_closed(self) -> None:
        stale = self.candidate.fingerprint
        self.candidate = self.candidates.put(
            DiscoveryCandidate.build(
                identity_kind="ip",
                identity_value="192.0.2.10",
                first_seen="2026-09-01T14:01:00Z",
                last_seen="2026-09-01T14:01:00Z",
                observation_count=1,
                confidence_basis_points=9000,
                provenance_refs=("sensor:arp-02",),
                evidence_refs=("evidence:2",),
            )
        )
        with self.assertRaises(MonitoringContractError):
            self.service.enroll(
                self.request(candidate_fingerprint=stale),
                enrolled_at="2026-09-01T14:10:00Z",
            )
        self.assertIsNone(self.monitoring.get_asset("switch-01"))

    def test_existing_asset_definition_cannot_be_mutated_through_discovery(self) -> None:
        existing = self.asset(role="router")
        self.monitoring.upsert_asset(existing)
        with self.assertRaises(MonitoringContractError):
            self.service.enroll(self.request(asset=self.asset()), enrolled_at="2026-09-01T14:10:00Z")
        stored = self.monitoring.get_asset("switch-01")
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored.fingerprint, existing.fingerprint)

    def test_management_host_owned_by_another_asset_fails_closed(self) -> None:
        self.monitoring.upsert_asset(self.asset(asset_id="other-asset"))
        with self.assertRaises(MonitoringContractError):
            self.service.enroll(self.request(), enrolled_at="2026-09-01T14:10:00Z")
        self.assertIsNone(self.monitoring.get_asset("switch-01"))

    def test_receipt_insert_failure_rolls_back_asset_write(self) -> None:
        with self.monitoring.connect() as conn:
            conn.execute(
                """
                CREATE TRIGGER fail_discovery_enrollment_receipt
                BEFORE INSERT ON discovery_enrollment_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'blocked');
                END;
                """
            )
        with self.assertRaises(MonitoringContractError):
            self.service.enroll(self.request(), enrolled_at="2026-09-01T14:10:00Z")
        self.assertIsNone(self.monitoring.get_asset("switch-01"))
        with self.monitoring.connect() as conn:
            count = conn.execute("SELECT COUNT(*) AS n FROM discovery_enrollment_receipts").fetchone()["n"]
        self.assertEqual(count, 0)

    def test_receipt_schema_has_no_raw_candidate_identity(self) -> None:
        receipt = self.service.enroll(self.request(), enrolled_at="2026-09-01T14:10:00Z")
        payload = receipt.to_json()
        self.assertNotIn("192.0.2.10", payload)
        self.assertIn(self.candidate.candidate_id, payload)
        self.assertIn(self.candidate.fingerprint, payload)


if __name__ == "__main__":
    unittest.main()
