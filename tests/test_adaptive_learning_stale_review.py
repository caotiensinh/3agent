from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.adaptive_learning_checkpoint import (
    HmacCheckpointKeyring,
    LearningCheckpointAuthority,
    LearningOperatorGateway,
    LearningStagingGateway,
)
from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
    LearningValidationReceipt,
)
from three_agent.adaptive_learning_effectiveness import (
    REUSE_ACTIVITY_ACTION,
    REUSE_ACTIVITY_AGENT,
    record_learning_reuse,
)
from three_agent.adaptive_learning_retrieval import LearningContext, LearningContextItem
from three_agent.adaptive_learning_stale_review import (
    STATUS_ACTIVE_SKILL_LIMIT_EXCEEDED,
    STATUS_DISABLED,
    STATUS_NO_STALE_SKILLS,
    STATUS_REVIEWS_READY,
    DeterministicStaleSkillReviewAdvisor,
    StaleSkillReviewConfig,
    StaleSkillReviewError,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger

SOURCE_TIME = "2026-01-01T00:00:00Z"
STORE_ID = "learning-store:stale-review-test"
KEY = b"adaptive-stale-skill-review-key-v1"


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class StaleSkillReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.task_store = TaskStore(self.root / "tasks.db")
        self.task_store.initialize()
        self.task_contracts = TaskContractCompiler()
        self.validator = ValidatorLedger(self.task_store)

        self.learning_store = AdaptiveLearningStore(self.root / "learning.db")
        self.authority = LearningCheckpointAuthority(
            self.root / "checkpoint" / "journal.jsonl",
            self.root / "trusted-head" / "head.json",
            HmacCheckpointKeyring({"key:v1": KEY}, active_key_id="key:v1"),
            store_id=STORE_ID,
        )
        self.authority.bootstrap(self.learning_store)
        self.learner = LearningStagingGateway(self.learning_store, self.authority)
        self.operator = LearningOperatorGateway(self.learning_store, self.authority)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def candidate(self, name: str, *, domain: str = "analyst") -> KnowledgeCandidate:
        source_task_id = f"task:stale-source:{name}"
        evidence = EvidenceReference(
            ref_id=f"evidence:stale:{name}",
            sha256=sha(f"evidence:{name}"),
            source_type="task_artifact",
            source_task_id=source_task_id,
            sensitivity="confidential",
            collection_mode="offline",
            created_at=SOURCE_TIME,
        )
        experience = ExperienceRecord(
            experience_id=f"experience:stale:{name}",
            domain=domain,
            task_id=source_task_id,
            outcome="verified_success",
            sensitivity="confidential",
            summary=f"Verified stale-review source {name}.",
            evidence=(evidence,),
            created_at=SOURCE_TIME,
        )
        return KnowledgeCandidate.from_experiences(
            candidate_id=f"knowledge:stale:{name}",
            domain=domain,
            kind="skill",
            title=f"Stale review skill {name}",
            content=f"PRIVATE-SKILL-CONTENT-{name}",
            scope="local analysis only",
            sensitivity="confidential",
            risk_level="medium",
            ownership="learner_managed",
            action="create",
            execution_mode="analysis_only",
            experiences=(experience,),
            created_at=SOURCE_TIME,
        )

    @staticmethod
    def validation_receipt(candidate: KnowledgeCandidate, *, level: str) -> LearningValidationReceipt:
        human = "reviewer:human" if level == "approved" else None
        domain_reviewer = (
            "reviewer:domain"
            if level == "approved" and candidate.domain in {"network", "security"}
            else None
        )
        return LearningValidationReceipt(
            receipt_id=f"receipt:stale:{candidate.candidate_id}:{level}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=domain_reviewer,
            human_reviewer_id=human,
            created_at=SOURCE_TIME,
        ).validate()

    def active_item(
        self,
        name: str,
        *,
        domain: str = "analyst",
        activated_at: str = SOURCE_TIME,
    ) -> tuple[KnowledgeCandidate, dict]:
        candidate = self.candidate(name, domain=domain)
        with patch("three_agent.adaptive_learning_store._now", return_value=activated_at):
            self.learner.stage(candidate)
            self.operator.promote(
                candidate.candidate_id,
                target_level="validated",
                receipt=self.validation_receipt(candidate, level="validated"),
            )
            row = self.operator.promote(
                candidate.candidate_id,
                target_level="approved",
                receipt=self.validation_receipt(candidate, level="approved"),
            )
        return candidate, row

    def task(self) -> str:
        task = self.task_store.create_task("Stale review", "PRIVATE-TASK-REQUEST")
        contract = self.task_contracts.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="confidential",
            risk_level="low",
        )
        self.validator.bind_contract(contract)
        return task.task_id

    @staticmethod
    def context_item(candidate: KnowledgeCandidate, row: dict) -> LearningContextItem:
        return LearningContextItem(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            level=str(row["level"]),
            domain=candidate.domain,
            kind=candidate.kind,
            title=candidate.title,
            content=candidate.content,
            scope=candidate.scope,
            sensitivity=candidate.sensitivity,
            risk_level=candidate.risk_level,
            execution_mode=candidate.execution_mode,
        ).validate()

    def record_reuse_at(
        self,
        candidate: KnowledgeCandidate,
        row: dict,
        *,
        timestamp: str,
        query: str,
    ) -> str:
        task_id = self.task()
        item = self.context_item(candidate, row)
        context = LearningContext(
            query_sha256=sha(f"query:{query}"),
            domain=item.domain,
            task_sensitivity="confidential",
            items=(item,),
        ).validate()
        record_learning_reuse(self.task_store, task_id, context)
        with self.task_store.connect() as conn:
            conn.execute(
                """
                UPDATE activities
                SET timestamp=?
                WHERE task_id=? AND agent_id=? AND action=?
                """,
                (timestamp, task_id, REUSE_ACTIVITY_AGENT, REUSE_ACTIVITY_ACTION),
            )
        return task_id

    def advisor(
        self,
        *,
        enabled: bool = True,
        stale_after_days: int = 90,
        max_active_skills: int = 64,
        max_reuse_receipts: int = 2048,
    ) -> DeterministicStaleSkillReviewAdvisor:
        return DeterministicStaleSkillReviewAdvisor(
            StaleSkillReviewConfig(
                enabled=enabled,
                stale_after_days=stale_after_days,
                max_active_skills=max_active_skills,
                max_reuse_receipts=max_reuse_receipts,
            ),
            self.task_store,
            self.learning_store,
            self.authority,
        )

    def test_disabled_policy_is_exact_noop(self):
        before = self.authority.verify(self.learning_store)
        receipt = self.advisor(enabled=False).run_once()
        after = self.authority.verify(self.learning_store)
        self.assertEqual(receipt.status, STATUS_DISABLED)
        self.assertEqual(receipt.reviews, ())
        self.assertIsNone(receipt.as_of)
        self.assertEqual(before.checkpoint_sha256, after.checkpoint_sha256)

    def test_unused_active_skill_becomes_stale_at_exact_threshold(self):
        candidate, row = self.active_item("unused")
        receipt = self.advisor(stale_after_days=90).run_once(as_of="2026-04-01T00:00:00Z")
        self.assertEqual(receipt.status, STATUS_REVIEWS_READY)
        self.assertEqual(receipt.scanned_active_skills, 1)
        self.assertEqual(receipt.scanned_reuse_receipts, 0)
        self.assertEqual(len(receipt.reviews), 1)
        review = receipt.reviews[0]
        self.assertEqual(review.item_id, row["item_id"])
        self.assertEqual(review.knowledge_sha256, row["knowledge_sha256"])
        self.assertEqual(review.candidate_sha256, candidate.sha256)
        self.assertEqual(review.activated_at, SOURCE_TIME)
        self.assertIsNone(review.last_reuse_at)
        self.assertEqual(review.age_seconds, 90 * 86400)
        self.assertIn("NO_REUSE_SINCE_ACTIVATION", review.reason_codes)

    def test_skill_is_fresh_before_threshold(self):
        self.active_item("fresh")
        receipt = self.advisor(stale_after_days=90).run_once(as_of="2026-03-31T00:00:00Z")
        self.assertEqual(receipt.status, STATUS_NO_STALE_SKILLS)
        self.assertEqual(receipt.reviews, ())

    def test_exact_version_reuse_resets_freshness_clock(self):
        candidate, row = self.active_item("reuse-reset")
        self.record_reuse_at(
            candidate,
            row,
            timestamp="2026-06-01T00:00:00+00:00",
            query="reuse-reset",
        )
        fresh = self.advisor(stale_after_days=90).run_once(as_of="2026-08-01T00:00:00Z")
        self.assertEqual(fresh.status, STATUS_NO_STALE_SKILLS)

        stale = self.advisor(stale_after_days=90).run_once(as_of="2026-09-01T00:00:00Z")
        self.assertEqual(stale.status, STATUS_REVIEWS_READY)
        review = stale.reviews[0]
        self.assertEqual(review.last_reuse_at, "2026-06-01T00:00:00Z")
        self.assertEqual(review.freshness_anchor_at, "2026-06-01T00:00:00Z")
        self.assertIn("REUSE_AGE_THRESHOLD_EXCEEDED", review.reason_codes)

    def test_rollback_reactivation_ignores_reuse_from_prior_tenure(self):
        candidate, row = self.active_item("reactivated")
        self.record_reuse_at(
            candidate,
            row,
            timestamp="2026-01-15T00:00:00+00:00",
            query="old-tenure",
        )
        with patch("three_agent.adaptive_learning_store._now", return_value="2026-07-01T00:00:00Z"):
            self.operator.rollback(
                str(row["item_id"]),
                target_knowledge_sha256=str(row["knowledge_sha256"]),
                expected_current_sha256=str(row["knowledge_sha256"]),
            )

        receipt = self.advisor(stale_after_days=30).run_once(as_of="2026-08-01T00:00:00Z")
        self.assertEqual(receipt.status, STATUS_REVIEWS_READY)
        review = receipt.reviews[0]
        self.assertEqual(review.activated_at, "2026-07-01T00:00:00Z")
        self.assertIsNone(review.last_reuse_at)
        self.assertEqual(review.freshness_anchor_at, "2026-07-01T00:00:00Z")
        self.assertIn("NO_REUSE_SINCE_ACTIVATION", review.reason_codes)

    def test_network_stale_review_requires_domain_review(self):
        self.active_item("network", domain="network")
        receipt = self.advisor(stale_after_days=30).run_once(as_of="2026-02-01T00:00:00Z")
        review = receipt.reviews[0]
        self.assertTrue(review.human_review_required)
        self.assertTrue(review.domain_review_required)
        self.assertIn("DOMAIN_REVIEW_REQUIRED", review.reason_codes)

    def test_active_skill_limit_fails_closed_without_partial_reviews(self):
        self.active_item("capacity-one")
        self.active_item("capacity-two")
        before = self.authority.verify(self.learning_store)
        receipt = self.advisor(max_active_skills=1).run_once(as_of="2026-04-01T00:00:00Z")
        self.assertEqual(receipt.status, STATUS_ACTIVE_SKILL_LIMIT_EXCEEDED)
        self.assertEqual(receipt.scanned_active_skills, 2)
        self.assertEqual(receipt.reviews, ())
        self.assertEqual(before.checkpoint_sha256, self.authority.verify(self.learning_store).checkpoint_sha256)

    def test_malformed_reuse_receipt_blocks_stale_review(self):
        self.active_item("malformed")
        task_id = self.task()
        self.task_store.record_activity(
            task_id,
            REUSE_ACTIVITY_AGENT,
            REUSE_ACTIVITY_ACTION,
            "ok",
            "{}",
        )
        with self.assertRaisesRegex(StaleSkillReviewError, "STALE_SKILL_REUSE_RECEIPT_INVALID"):
            self.advisor().run_once(as_of="2026-04-01T00:00:00Z")

    def test_receipt_is_deterministic_metadata_only_and_has_no_mutation_surface(self):
        candidate, _row = self.active_item("privacy", domain="security")
        advisor = self.advisor(stale_after_days=30)
        first = advisor.run_once(as_of="2026-02-01T00:00:00Z").to_payload()
        second = advisor.run_once(as_of="2026-02-01T00:00:00Z").to_payload()
        self.assertEqual(first, second)
        serialized = json.dumps(first, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(candidate.content, serialized)
        self.assertNotIn("PRIVATE-TASK-REQUEST", serialized)
        self.assertRegex(first["receipt_sha256"], r"^sha256:[0-9a-f]{64}$")
        for forbidden in (
            "promote",
            "stage",
            "archive",
            "rollback",
            "materialize",
            "execute",
            "invoke",
        ):
            self.assertFalse(hasattr(advisor, forbidden), forbidden)

    def test_enabled_policy_requires_explicit_as_of(self):
        self.active_item("as-of")
        with self.assertRaisesRegex(StaleSkillReviewError, "STALE_SKILL_AS_OF_REQUIRED"):
            self.advisor().run_once()


if __name__ == "__main__":
    unittest.main()
