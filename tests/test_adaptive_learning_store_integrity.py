from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
    LearningValidationReceipt,
)
from three_agent.adaptive_learning_store import (
    AdaptiveLearningStore,
    AdaptiveLearningStoreError,
    GENESIS_HASH,
    LEDGER_SCHEMA,
)

NOW = "2026-08-31T03:30:00Z"
H1 = "sha256:" + "1" * 64


def approved_candidate() -> tuple[KnowledgeCandidate, LearningValidationReceipt, LearningValidationReceipt]:
    evidence = EvidenceReference(
        ref_id="evidence:integrity",
        sha256=H1,
        source_type="syslog",
        source_task_id="task:integrity",
        sensitivity="confidential",
        collection_mode="passive",
        created_at=NOW,
        vendor_family="Cisco CBS250",
        version="3.x",
    )
    experience = ExperienceRecord(
        experience_id="experience:integrity",
        domain="network",
        task_id="task:integrity",
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified passive read-only analysis sequence.",
        evidence=(evidence,),
        created_at=NOW,
    )
    candidate = KnowledgeCandidate.from_experiences(
        candidate_id="candidate:integrity",
        domain="network",
        kind="skill",
        title="Integrity checked network analysis",
        content="Correlate read-only evidence and preserve uncertainty before conclusion.",
        scope="offline-read-only-analysis",
        sensitivity="confidential",
        risk_level="high",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only",
        experiences=(experience,),
        created_at=NOW,
    )

    def receipt(receipt_id: str, *, reviewed: bool) -> LearningValidationReceipt:
        return LearningValidationReceipt(
            receipt_id=receipt_id,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id="reviewer:network" if reviewed else None,
            human_reviewer_id="reviewer:human" if reviewed else None,
            created_at=NOW,
        )

    return candidate, receipt("receipt:integrity:validated", reviewed=False), receipt(
        "receipt:integrity:approved", reviewed=True
    )


class AdaptiveLearningStoreIntegrityTests(unittest.TestCase):
    def test_forged_ledger_row_blocks_active_read_and_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AdaptiveLearningStore(Path(tmp) / "learning.db")
            with store.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO learning_ledger(
                        schema_version,event_id,event_type,item_id,candidate_id,candidate_sha256,
                        knowledge_sha256,before_sha256,after_sha256,validation_receipt_sha256,
                        source_experience_hashes_json,evidence_hashes_json,actor_id,reason_code,
                        timestamp,previous_entry_sha256,entry_sha256
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        LEDGER_SCHEMA,
                        "learning-event:forged",
                        "archive",
                        "candidate:forged",
                        None,
                        None,
                        H1,
                        H1,
                        None,
                        None,
                        "[]",
                        "[]",
                        "attacker:local",
                        "FORGED",
                        NOW,
                        GENESIS_HASH,
                        H1,
                    ),
                )

            verification = store.verify_ledger()
            self.assertFalse(verification["passed"])
            self.assertTrue(
                any(code.startswith("ENTRY_HASH_MISMATCH") for code in verification["failures"])
            )

            with self.assertRaisesRegex(
                AdaptiveLearningStoreError, "LEARNING_LEDGER_INTEGRITY_FAILED"
            ):
                store.active("candidate:forged")

            with self.assertRaisesRegex(
                AdaptiveLearningStoreError, "LEARNING_LEDGER_INTEGRITY_FAILED"
            ):
                store.archive(
                    "candidate:forged",
                    expected_current_sha256=H1,
                )

    def test_candidate_json_tamper_is_detected_even_when_ledger_chain_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AdaptiveLearningStore(Path(tmp) / "learning.db")
            candidate, validated_receipt, approved_receipt = approved_candidate()
            store.stage(candidate)
            store.promote(
                candidate.candidate_id,
                target_level="validated",
                receipt=validated_receipt,
            )
            store.promote(
                candidate.candidate_id,
                target_level="approved",
                receipt=approved_receipt,
            )
            active_before = store.active(candidate.candidate_id)
            self.assertIsNotNone(active_before)
            self.assertTrue(store.verify_ledger()["passed"])

            tampered = dict(candidate.to_payload())
            tampered["title"] = "Tampered title not covered by stored row hashes"
            with store.connect() as conn:
                conn.execute("DROP TRIGGER learning_versions_no_update")
                conn.execute(
                    """
                    UPDATE learning_versions
                    SET candidate_json=?
                    WHERE item_id=? AND disposition='active_snapshot'
                    """,
                    (json.dumps(tampered, sort_keys=True), candidate.candidate_id),
                )

            # The ledger itself was not modified, so ledger verification remains green.
            self.assertTrue(store.verify_ledger()["passed"])
            with self.assertRaisesRegex(
                AdaptiveLearningStoreError, "LEARNING_VERSION_INTEGRITY_FAILED"
            ):
                store.active(candidate.candidate_id)


if __name__ == "__main__":
    unittest.main()
