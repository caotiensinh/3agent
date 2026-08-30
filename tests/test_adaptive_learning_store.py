from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
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

NOW = "2026-08-31T03:00:00Z"
H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


def evidence(task_id: str, suffix: str = "1") -> EvidenceReference:
    return EvidenceReference(
        ref_id=f"evidence:{suffix}",
        sha256=H1 if suffix == "1" else H2,
        source_type="syslog",
        source_task_id=task_id,
        sensitivity="confidential",
        collection_mode="passive",
        created_at=NOW,
        vendor_family="Cisco CBS250",
        version="3.x",
    )


def experience(
    experience_id: str,
    task_id: str,
    *,
    domain: str = "network",
    suffix: str = "1",
) -> ExperienceRecord:
    return ExperienceRecord(
        experience_id=experience_id,
        domain=domain,
        task_id=task_id,
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified reusable read-only analysis procedure.",
        evidence=(evidence(task_id, suffix),),
        created_at=NOW,
    )


def candidate(
    candidate_id: str,
    *,
    domain: str = "network",
    content: str = "Correlate interface transitions with endpoint evidence and preserve uncertainty.",
    action: str = "create",
    target_item_id: str | None = None,
    base_item_sha256: str | None = None,
    ownership: str = "learner_managed",
) -> KnowledgeCandidate:
    exp = experience(
        f"experience:{candidate_id.split(':')[-1]}",
        f"task:{candidate_id.split(':')[-1]}",
        domain=domain,
        suffix="2" if action != "create" else "1",
    )
    return KnowledgeCandidate.from_experiences(
        candidate_id=candidate_id,
        domain=domain,
        kind="skill" if domain != "analyst" else "analytical_pattern",
        title=f"Procedure {candidate_id}",
        content=content,
        scope="offline-read-only-analysis",
        sensitivity="confidential",
        risk_level="high" if domain in {"network", "security"} else "low",
        ownership=ownership,
        action=action,
        execution_mode="read_only" if domain == "network" else "analysis_only",
        experiences=(exp,),
        target_item_id=target_item_id,
        base_item_sha256=base_item_sha256,
        created_at=NOW,
    )


def receipt(
    item: KnowledgeCandidate,
    *,
    passed: bool = True,
    human: str | None = None,
    domain_reviewer: str | None = None,
) -> LearningValidationReceipt:
    return LearningValidationReceipt(
        receipt_id=f"receipt:{item.candidate_id.split(':')[-1]}:{'pass' if passed else 'fail'}:{'h' if human else 'n'}",
        candidate_id=item.candidate_id,
        candidate_sha256=item.sha256,
        checks={
            "SCHEMA": True,
            "EVIDENCE": passed,
            "SECURITY": passed,
            "OFFLINE_REPLAY": passed,
        },
        validator_ids=("validator:policy", "validator:evidence", "validator:offline"),
        evidence_ref_ids=item.evidence_ref_ids,
        evidence_hashes=item.evidence_hashes,
        domain_reviewer_id=domain_reviewer,
        human_reviewer_id=human,
        created_at=NOW,
    )


class AdaptiveLearningStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "learning.db"
        self.store = AdaptiveLearningStore(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def promote_approved(self, item: KnowledgeCandidate):
        self.store.stage(item)
        self.store.promote(
            item.candidate_id,
            target_level="validated",
            receipt=receipt(item),
        )
        return self.store.promote(
            item.candidate_id,
            target_level="approved",
            receipt=receipt(
                item,
                human="reviewer:human",
                domain_reviewer="reviewer:network" if item.domain == "network" else "reviewer:security",
            ),
        )

    def test_stage_is_not_active(self):
        item = candidate("candidate:base")
        row = self.store.stage(item)
        self.assertEqual(row["level"], "candidate")
        self.assertIsNone(self.store.active(item.candidate_id))
        self.assertEqual([x["event_type"] for x in self.store.ledger()], ["stage"])

    def test_validated_is_still_staged_and_approved_becomes_active(self):
        item = candidate("candidate:base")
        self.store.stage(item)
        validated = self.store.promote(
            item.candidate_id,
            target_level="validated",
            receipt=receipt(item),
        )
        self.assertEqual(validated["disposition"], "staged")
        self.assertIsNone(self.store.active(item.candidate_id))

        approved = self.store.promote(
            item.candidate_id,
            target_level="approved",
            receipt=receipt(
                item,
                human="reviewer:human",
                domain_reviewer="reviewer:network",
            ),
        )
        self.assertEqual(approved["disposition"], "active_snapshot")
        active = self.store.active(item.candidate_id)
        self.assertIsNotNone(active)
        self.assertEqual(active["knowledge_sha256"], approved["knowledge_sha256"])

    def test_failed_receipt_blocks_promotion(self):
        item = candidate("candidate:failed")
        self.store.stage(item)
        with self.assertRaisesRegex(AdaptiveLearningStoreError, "PROMOTION_BLOCKED"):
            self.store.promote(
                item.candidate_id,
                target_level="validated",
                receipt=receipt(item, passed=False),
            )

    def test_network_approval_requires_human_and_domain_review(self):
        item = candidate("candidate:review")
        self.store.stage(item)
        self.store.promote(
            item.candidate_id,
            target_level="validated",
            receipt=receipt(item),
        )
        with self.assertRaisesRegex(AdaptiveLearningStoreError, "HUMAN_REVIEW_REQUIRED"):
            self.store.promote(
                item.candidate_id,
                target_level="approved",
                receipt=receipt(item),
            )

    def test_phase3_store_rejects_self_claimed_user_or_system_ownership(self):
        item = candidate("candidate:owner", ownership="user_team")
        with self.assertRaisesRegex(AdaptiveLearningStoreError, "learner_managed"):
            self.store.stage(item)

    def test_patch_requires_exact_active_base_hash(self):
        base = candidate("candidate:base")
        approved = self.promote_approved(base)
        patch = candidate(
            "candidate:patch",
            action="patch",
            target_item_id=base.candidate_id,
            base_item_sha256=H2,
            content="Improved read-only analysis procedure.",
        )
        self.assertNotEqual(approved["knowledge_sha256"], H2)
        with self.assertRaisesRegex(AdaptiveLearningStoreError, "STALE_BASE_ITEM_SHA256"):
            self.store.stage(patch)

    def test_patch_promote_and_rollback_restore_exact_prior_version(self):
        base = candidate("candidate:base")
        base_row = self.promote_approved(base)
        old_hash = str(base_row["knowledge_sha256"])

        patch = candidate(
            "candidate:patch",
            action="patch",
            target_item_id=base.candidate_id,
            base_item_sha256=old_hash,
            content="Improved procedure with explicit contradiction check before conclusion.",
        )
        patch_row = self.promote_approved(patch)
        new_hash = str(patch_row["knowledge_sha256"])
        self.assertNotEqual(old_hash, new_hash)
        self.assertEqual(self.store.active(base.candidate_id)["knowledge_sha256"], new_hash)

        restored = self.store.rollback(
            base.candidate_id,
            target_knowledge_sha256=old_hash,
            expected_current_sha256=new_hash,
        )
        self.assertEqual(restored["knowledge_sha256"], old_hash)
        self.assertEqual(self.store.active(base.candidate_id)["knowledge_sha256"], old_hash)

    def test_archive_preserves_version_and_rollback_can_restore_it(self):
        base = candidate("candidate:base")
        row = self.promote_approved(base)
        current = str(row["knowledge_sha256"])
        self.store.archive(
            base.candidate_id,
            expected_current_sha256=current,
        )
        self.assertIsNone(self.store.active(base.candidate_id))
        restored = self.store.rollback(
            base.candidate_id,
            target_knowledge_sha256=current,
            expected_current_sha256=None,
        )
        self.assertEqual(restored["knowledge_sha256"], current)

    def test_rollback_rejects_unknown_or_unpromoted_hash(self):
        base = candidate("candidate:base")
        row = self.promote_approved(base)
        with self.assertRaisesRegex(AdaptiveLearningStoreError, "ROLLBACK_TARGET_NOT_PROMOTED"):
            self.store.rollback(
                base.candidate_id,
                target_knowledge_sha256=H2,
                expected_current_sha256=str(row["knowledge_sha256"]),
            )

    def test_enterprise_baseline_is_not_displaced_by_approved_patch(self):
        base = candidate("candidate:base")
        self.promote_approved(base)
        enterprise = self.store.promote(
            base.candidate_id,
            target_level="enterprise",
            receipt=receipt(
                base,
                human="reviewer:human",
                domain_reviewer="reviewer:network",
            ),
        )
        enterprise_hash = str(enterprise["knowledge_sha256"])

        patch = candidate(
            "candidate:patch",
            action="patch",
            target_item_id=base.candidate_id,
            base_item_sha256=enterprise_hash,
            content="Candidate replacement for an enterprise baseline.",
        )
        self.store.stage(patch)
        self.store.promote(
            patch.candidate_id,
            target_level="validated",
            receipt=receipt(patch),
        )
        approved_patch = self.store.promote(
            patch.candidate_id,
            target_level="approved",
            receipt=receipt(
                patch,
                human="reviewer:human",
                domain_reviewer="reviewer:network",
            ),
        )
        self.assertEqual(approved_patch["disposition"], "staged")
        self.assertEqual(self.store.active(base.candidate_id)["knowledge_sha256"], enterprise_hash)

        enterprise_patch = self.store.promote(
            patch.candidate_id,
            target_level="enterprise",
            receipt=receipt(
                patch,
                human="reviewer:human",
                domain_reviewer="reviewer:network",
            ),
        )
        self.assertEqual(enterprise_patch["disposition"], "active_snapshot")
        self.assertEqual(
            self.store.active(base.candidate_id)["knowledge_sha256"],
            enterprise_patch["knowledge_sha256"],
        )

    def test_ledger_contains_hashes_and_no_raw_candidate_or_evidence_content(self):
        item = candidate(
            "candidate:metadata",
            content="SENSITIVE PROCEDURE BODY THAT MUST NOT APPEAR IN LEDGER",
        )
        self.promote_approved(item)
        exported = json.dumps(self.store.ledger(), ensure_ascii=False)
        self.assertNotIn("SENSITIVE PROCEDURE BODY", exported)
        self.assertNotIn("candidate_json", exported)
        self.assertIn(item.sha256, exported)
        self.assertIn(item.evidence_hashes[0], exported)

    def test_ledger_and_versions_are_sql_append_only(self):
        item = candidate("candidate:immutable")
        self.store.stage(item)
        with self.store.connect() as conn:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE learning_ledger SET reason_code='TAMPERED' WHERE seq=1")
        with self.store.connect() as conn:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM learning_versions WHERE version_id=1")

    def test_ledger_hash_chain_verifies_and_detects_injected_bad_row(self):
        item = candidate("candidate:chain")
        self.store.stage(item)
        self.assertTrue(self.store.verify_ledger()["passed"])

        with self.store.connect() as conn:
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
                    "stage",
                    "candidate:forged",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    "[]",
                    "[]",
                    "attacker:local",
                    "FORGED",
                    NOW,
                    GENESIS_HASH,
                    H2,
                ),
            )
        verification = self.store.verify_ledger()
        self.assertFalse(verification["passed"])
        self.assertTrue(
            any(
                code.startswith("CHAIN_PREVIOUS_MISMATCH")
                or code.startswith("ENTRY_HASH_MISMATCH")
                for code in verification["failures"]
            )
        )

    def test_reopen_preserves_active_state_and_chain(self):
        item = candidate("candidate:restart")
        row = self.promote_approved(item)
        reopened = AdaptiveLearningStore(self.db)
        self.assertEqual(
            reopened.active(item.candidate_id)["knowledge_sha256"],
            row["knowledge_sha256"],
        )
        self.assertTrue(reopened.verify_ledger()["passed"])

    def test_promotion_is_idempotent_only_for_same_receipt(self):
        item = candidate("candidate:idempotent")
        self.store.stage(item)
        r = receipt(item)
        first = self.store.promote(item.candidate_id, target_level="validated", receipt=r)
        second = self.store.promote(item.candidate_id, target_level="validated", receipt=r)
        self.assertEqual(first["version_id"], second["version_id"])
        changed = replace(r, receipt_id="receipt:other")
        with self.assertRaisesRegex(AdaptiveLearningStoreError, "receipt is immutable"):
            self.store.promote(item.candidate_id, target_level="validated", receipt=changed)


if __name__ == "__main__":
    unittest.main()
