from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_checkpoint import (
    HmacCheckpointKeyring,
    LearningCheckpointAuthority,
    LearningStagingGateway,
)
from three_agent.adaptive_learning_contract import (
    ContradictionRecord,
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
)
from three_agent.adaptive_learning_contradictions import (
    AdaptiveLearningContradictionError,
    AdaptiveLearningContradictionIndex,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore, GENESIS_HASH


NOW = "2026-09-08T14:00:00Z"
LATER = "2026-09-08T14:05:00Z"
H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
STORE_ID = "learning-store:contradiction-test"
CHECKPOINT_KEY = b"contradiction-checkpoint-key-material-v01"


def candidate() -> KnowledgeCandidate:
    evidence = EvidenceReference(
        ref_id="evidence:source",
        sha256=H1,
        source_type="syslog",
        source_task_id="task:contradiction",
        sensitivity="confidential",
        collection_mode="passive",
        created_at=NOW,
        vendor_family="Cisco CBS250",
        version="3.x",
    )
    experience = ExperienceRecord(
        experience_id="experience:contradiction",
        domain="network",
        task_id="task:contradiction",
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified passive source experience.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return KnowledgeCandidate.from_experiences(
        candidate_id="candidate:contradiction",
        domain="network",
        kind="skill",
        title="Contradiction test skill",
        content="Correlate read-only evidence and preserve uncertainty.",
        scope="offline-read-only-analysis",
        sensitivity="confidential",
        risk_level="high",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only",
        experiences=(experience,),
        created_at=NOW,
    )


def contradiction(
    *,
    contradiction_id: str = "contradiction:1",
    status: str = "open",
    created_at: str = NOW,
    resolved_at: str | None = None,
    summary: str = "UNIQUE-CONTRADICTION-SUMMARY-DO-NOT-PERSIST",
) -> ContradictionRecord:
    return ContradictionRecord(
        contradiction_id=contradiction_id,
        candidate_id="candidate:contradiction",
        evidence_ref_ids=("evidence:contradiction:private",),
        evidence_hashes=(H2,),
        summary=summary,
        status=status,
        created_at=created_at,
        resolved_at=resolved_at,
    )


class AdaptiveLearningContradictionIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = AdaptiveLearningStore(self.root / "learning.db")
        self.authority = LearningCheckpointAuthority(
            self.root / "checkpoint" / "journal.jsonl",
            self.root / "trusted" / "head.json",
            HmacCheckpointKeyring(
                {"key:v1": CHECKPOINT_KEY},
                active_key_id="key:v1",
            ),
            store_id=STORE_ID,
        )
        self.authority.bootstrap(self.store)
        self.candidate = candidate()
        LearningStagingGateway(self.store, self.authority).stage(self.candidate)
        self.index = AdaptiveLearningContradictionIndex(
            self.store,
            self.authority,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _record(
        self,
        record: ContradictionRecord,
        *,
        head: str | None = None,
        candidate_sha: str | None = None,
        reason: str = "VERIFIED_CONTRADICTION",
    ):
        return self.index.record(
            record,
            expected_candidate_sha256=candidate_sha or self.candidate.sha256,
            expected_history_head_sha256=(
                self.index.verify()["head_sha256"] if head is None else head
            ),
            actor_id="reviewer:network",
            reason_code=reason,
        )

    def test_open_resolve_restart_and_statistics(self):
        opened = self._record(contradiction())
        self.assertEqual(opened.previous_entry_sha256, GENESIS_HASH)

        resolved = self._record(
            contradiction(status="resolved", resolved_at=LATER),
            head=opened.entry_sha256,
            reason="CONTRADICTION_RESOLVED",
        )
        self.assertNotEqual(opened.entry_sha256, resolved.entry_sha256)
        self.assertEqual(self.index.open_for_candidate(self.candidate.candidate_id), ())

        restarted = AdaptiveLearningContradictionIndex(
            AdaptiveLearningStore(self.root / "learning.db"),
            self.authority,
        )
        verification = restarted.verify()
        self.assertTrue(verification["passed"])
        self.assertEqual(verification["entry_count"], 2)
        self.assertEqual(verification["head_sha256"], resolved.entry_sha256)

        stats = restarted.statistics()
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0].total_contradictions, 1)
        self.assertEqual(stats[0].open_contradictions, 0)
        self.assertEqual(stats[0].resolved_contradictions, 1)
        self.assertEqual(stats[0].last_contradiction_at, NOW)
        self.assertEqual(stats[0].last_resolution_at, LATER)

    def test_open_projection_is_metadata_only(self):
        record = contradiction()
        event = self._record(record)
        states = self.index.open_for_candidate(self.candidate.candidate_id)
        self.assertEqual(len(states), 1)
        payload = states[0].to_payload()
        self.assertEqual(payload["candidate_sha256"], self.candidate.sha256)
        self.assertEqual(payload["status"], "open")
        self.assertEqual(payload["evidence_count"], 1)
        self.assertNotIn("summary", payload)
        self.assertNotIn("evidence_ref_ids", payload)
        self.assertNotIn("evidence_hashes", payload)
        self.assertNotIn(record.summary, str(payload))
        self.assertNotIn(record.evidence_ref_ids[0], str(payload))
        self.assertEqual(payload["latest_event_sha256"], event.entry_sha256)

    def test_persistent_table_contains_no_raw_summary_or_evidence_identifiers(self):
        record = contradiction()
        self._record(record)
        with self.store.connect() as conn:
            columns = [
                row["name"]
                for row in conn.execute(
                    "PRAGMA table_info(learning_contradiction_events)"
                ).fetchall()
            ]
            self.assertNotIn("record_json", columns)
            self.assertNotIn("summary", columns)
            self.assertNotIn("evidence_ref_ids", columns)
            row = conn.execute(
                "SELECT * FROM learning_contradiction_events"
            ).fetchone()
            persisted = "|".join(
                "" if value is None else str(value)
                for value in dict(row).values()
            )
        self.assertNotIn(record.summary, persisted)
        self.assertNotIn(record.evidence_ref_ids[0], persisted)

    def test_wrong_candidate_sha_fails_closed(self):
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "CONTRADICTION_CANDIDATE_SHA_CHANGED",
        ):
            self._record(
                contradiction(),
                candidate_sha="sha256:" + "f" * 64,
            )

    def test_stale_history_head_fails_closed(self):
        opened = self._record(contradiction())
        self.assertNotEqual(opened.entry_sha256, GENESIS_HASH)
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "CONTRADICTION_INDEX_HEAD_CHANGED",
        ):
            self._record(
                contradiction(
                    contradiction_id="contradiction:2",
                    summary="Second contradiction",
                ),
                head=GENESIS_HASH,
            )

    def test_terminal_without_open_fails_closed(self):
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "CONTRADICTION_MUST_OPEN_FIRST",
        ):
            self._record(
                contradiction(status="resolved", resolved_at=LATER),
            )

    def test_second_open_cannot_change_identity(self):
        opened = self._record(contradiction())
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "CONTRADICTION_ALREADY_OPEN",
        ):
            self._record(
                contradiction(summary="Changed contradiction summary"),
                head=opened.entry_sha256,
            )

    def test_resolution_cannot_change_metadata_commitments(self):
        opened = self._record(contradiction())
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "CONTRADICTION_TRANSITION_IDENTITY_CHANGED",
        ):
            self._record(
                contradiction(
                    status="resolved",
                    resolved_at=LATER,
                    summary="Changed contradiction summary",
                ),
                head=opened.entry_sha256,
            )

    def test_resolution_chronology_fails_closed(self):
        opened = self._record(
            contradiction(created_at="2026-09-08T14:10:00Z")
        )
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "resolution predates creation",
        ):
            self._record(
                contradiction(
                    status="resolved",
                    created_at="2026-09-08T14:10:00Z",
                    resolved_at="2026-09-08T14:09:59Z",
                ),
                head=opened.entry_sha256,
            )

    def test_tampered_event_fails_integrity_verification(self):
        self._record(contradiction())
        with self.store.connect() as conn:
            conn.execute("DROP TRIGGER learning_contradiction_events_no_update")
            conn.execute(
                """
                UPDATE learning_contradiction_events
                SET reason_code='FORGED_REASON'
                WHERE seq=1
                """
            )
        verification = self.index.verify()
        self.assertFalse(verification["passed"])
        self.assertTrue(
            any(
                "ENTRY_HASH_MISMATCH" in failure
                for failure in verification["failures"]
            )
        )

    def test_event_scan_is_bounded_and_emits_no_partial_result(self):
        first = self._record(contradiction())
        self._record(
            contradiction(
                contradiction_id="contradiction:2",
                summary="Second contradiction",
            ),
            head=first.entry_sha256,
        )
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "CONTRADICTION_EVENT_SCAN_CAPACITY_EXCEEDED",
        ):
            self.index.events(max_events=1)

    def test_authenticated_checkpoint_is_required(self):
        other_root = self.root / "missing-checkpoint"
        other_store = AdaptiveLearningStore(other_root / "learning.db")
        other_authority = LearningCheckpointAuthority(
            other_root / "checkpoint" / "journal.jsonl",
            other_root / "trusted" / "head.json",
            HmacCheckpointKeyring(
                {"key:v1": CHECKPOINT_KEY},
                active_key_id="key:v1",
            ),
            store_id="learning-store:missing-checkpoint",
        )
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "AUTHENTICATED_LEARNING_CHECKPOINT_INVALID",
        ):
            AdaptiveLearningContradictionIndex(other_store, other_authority)

    def test_index_has_no_production_mutation_surface(self):
        forbidden = {
            "stage",
            "promote",
            "archive",
            "rollback",
            "materialize",
            "invoke",
            "execute",
            "network",
            "credential",
        }
        public = {
            name
            for name in dir(AdaptiveLearningContradictionIndex)
            if not name.startswith("_")
        }
        self.assertTrue(forbidden.isdisjoint(public))

    def test_duplicate_terminal_event_is_idempotent_only_with_same_metadata(self):
        opened = self._record(contradiction())
        terminal = contradiction(status="dismissed", resolved_at=LATER)
        dismissed = self._record(
            terminal,
            head=opened.entry_sha256,
            reason="CONTRADICTION_DISMISSED",
        )
        replayed = self._record(
            terminal,
            head=dismissed.entry_sha256,
            reason="CONTRADICTION_DISMISSED",
        )
        self.assertEqual(replayed.entry_sha256, dismissed.entry_sha256)
        self.assertEqual(self.index.verify()["entry_count"], 2)
        with self.assertRaisesRegex(
            AdaptiveLearningContradictionError,
            "CONTRADICTION_EVENT_METADATA_IMMUTABLE",
        ):
            self.index.record(
                terminal,
                expected_candidate_sha256=self.candidate.sha256,
                expected_history_head_sha256=dismissed.entry_sha256,
                actor_id="reviewer:other",
                reason_code="CONTRADICTION_DISMISSED",
            )


if __name__ == "__main__":
    unittest.main()
