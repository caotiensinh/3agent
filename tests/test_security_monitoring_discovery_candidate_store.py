from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.discovery_candidate_store import DiscoveryCandidateStore
from three_agent.security_monitoring.discovery_candidates import DiscoveryCandidate
from three_agent.security_monitoring.storage import MonitoringStore


class DiscoveryCandidateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "monitoring.db"
        self.monitoring = MonitoringStore(self.db)
        self.store = DiscoveryCandidateStore(self.monitoring)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def candidate(
        self,
        *,
        evidence: tuple[str, ...] = ("evidence:1",),
        provenance: tuple[str, ...] = ("sensor:arp-01",),
        count: int = 1,
        first_seen: str = "2026-09-01T14:00:00Z",
        last_seen: str = "2026-09-01T14:00:00Z",
        confidence: int = 5000,
    ) -> DiscoveryCandidate:
        return DiscoveryCandidate.build(
            identity_kind="ip",
            identity_value="192.0.2.10",
            first_seen=first_seen,
            last_seen=last_seen,
            observation_count=count,
            confidence_basis_points=confidence,
            provenance_refs=provenance,
            evidence_refs=evidence,
        )

    def test_schema_is_additive_and_candidate_table_has_no_inventory_authority_columns(self) -> None:
        self.assertEqual(self.store.schema_version(), 1)
        with self.monitoring.connect() as conn:
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(discovery_candidates)").fetchall()
            }
        self.assertNotIn("asset_id", columns)
        self.assertNotIn("management_host", columns)
        self.assertNotIn("collector_capabilities", columns)
        self.assertNotIn("credential_ref", columns)
        self.assertNotIn("enabled", columns)

    def test_exact_replay_is_idempotent_and_does_not_double_count(self) -> None:
        item = self.candidate(count=3)
        first = self.store.put(item)
        second = self.store.put(item)
        self.assertEqual(first.to_json(), second.to_json())
        stored = self.store.get(item.candidate_id)
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored.observation_count, 3)
        self.assertEqual(stored.evidence_refs, ("evidence:1",))

    def test_disjoint_new_evidence_merges_deterministically(self) -> None:
        first = self.candidate(
            evidence=("evidence:1",),
            provenance=("sensor:arp-01",),
            count=2,
            last_seen="2026-09-01T14:01:00Z",
            confidence=4000,
        )
        second = self.candidate(
            evidence=("evidence:2",),
            provenance=("sensor:arp-02",),
            count=3,
            first_seen="2026-09-01T14:00:30Z",
            last_seen="2026-09-01T14:02:00Z",
            confidence=7000,
        )
        self.store.put(first)
        merged = self.store.put(second)
        self.assertEqual(merged.observation_count, 5)
        self.assertEqual(merged.confidence_basis_points, 7000)
        self.assertEqual(merged.first_seen, "2026-09-01T14:00:00Z")
        self.assertEqual(merged.last_seen, "2026-09-01T14:02:00Z")
        self.assertEqual(merged.evidence_refs, ("evidence:1", "evidence:2"))
        self.assertEqual(merged.provenance_refs, ("sensor:arp-01", "sensor:arp-02"))
        self.assertEqual(merged.trust_state, "untrusted")
        self.assertEqual(merged.inventory_status, "not_enrolled")
        self.assertEqual(merged.authority, "none")

    def test_overlapping_evidence_with_changed_metadata_fails_closed(self) -> None:
        self.store.put(self.candidate(count=1, confidence=4000))
        with self.assertRaises(MonitoringContractError):
            self.store.put(self.candidate(count=2, confidence=9000))
        stored = self.store.get(self.candidate().candidate_id)
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored.observation_count, 1)
        self.assertEqual(stored.confidence_basis_points, 4000)

    def test_stored_fingerprint_tamper_fails_closed(self) -> None:
        item = self.store.put(self.candidate())
        with self.monitoring.connect() as conn:
            conn.execute(
                "UPDATE discovery_candidates SET candidate_fingerprint=? WHERE candidate_id=?",
                ("sha256:" + "0" * 64, item.candidate_id),
            )
        with self.assertRaises(MonitoringContractError):
            self.store.get(item.candidate_id)

    def test_stored_schema_tamper_fails_closed(self) -> None:
        item = self.store.put(self.candidate())
        with self.monitoring.connect() as conn:
            conn.execute(
                "UPDATE discovery_candidates SET schema_version=? WHERE candidate_id=?",
                ("workspace-security-monitoring/discovery-candidate-v999", item.candidate_id),
            )
        with self.assertRaises(MonitoringContractError):
            self.store.get(item.candidate_id)

    def test_list_is_deterministic_and_bounded(self) -> None:
        a = DiscoveryCandidate.build(
            identity_kind="ip",
            identity_value="192.0.2.10",
            first_seen="2026-09-01T14:00:00Z",
            last_seen="2026-09-01T14:00:00Z",
            observation_count=1,
            confidence_basis_points=5000,
            provenance_refs=("sensor:arp-01",),
            evidence_refs=("evidence:a",),
        )
        b = DiscoveryCandidate.build(
            identity_kind="ip",
            identity_value="192.0.2.11",
            first_seen="2026-09-01T14:00:00Z",
            last_seen="2026-09-01T14:00:00Z",
            observation_count=1,
            confidence_basis_points=5000,
            provenance_refs=("sensor:arp-01",),
            evidence_refs=("evidence:b",),
        )
        self.store.put(b)
        self.store.put(a)
        listed = self.store.list_candidates(limit=10)
        self.assertEqual(tuple(item.candidate_id for item in listed), tuple(sorted((a.candidate_id, b.candidate_id))))
        with self.assertRaises(MonitoringContractError):
            self.store.list_candidates(limit=0)
        with self.assertRaises(MonitoringContractError):
            self.store.list_candidates(limit=10001)

    def test_candidate_store_cannot_mutate_approved_inventory(self) -> None:
        self.store.put(self.candidate())
        with self.monitoring.connect() as conn:
            approved_count = conn.execute("SELECT COUNT(*) AS n FROM approved_assets").fetchone()["n"]
        self.assertEqual(approved_count, 0)
        self.assertFalse(hasattr(self.store, "upsert_asset"))
        self.assertFalse(hasattr(self.store, "enroll"))


if __name__ == "__main__":
    unittest.main()
