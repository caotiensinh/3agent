from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

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
from three_agent.adaptive_learning_effectiveness import record_learning_reuse
from three_agent.adaptive_learning_maintenance import (
    STATUS_DISABLED,
    STATUS_RECOMMENDATIONS_READY,
    STATUS_SIGNAL_LIMIT_EXCEEDED,
    TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
    TYPE_KEEP_ACTIVE_REVIEW,
    TYPE_REVISION_OR_RETIREMENT_REVIEW,
    AdaptiveLearningMaintenanceAdvisor,
    AdaptiveLearningMaintenanceConfig,
    AdaptiveLearningMaintenanceError,
)
from three_agent.adaptive_learning_retrieval import LearningContext, LearningContextItem
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger

NOW = "2026-09-08T00:00:00Z"
STORE_ID = "learning-store:maintenance-test"
KEY = b"adaptive-maintenance-checkpoint-key-v1"


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class AdaptiveLearningMaintenanceTests(unittest.TestCase):
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
        source_task_id = f"task:maintenance-source:{name}"
        evidence = EvidenceReference(
            ref_id=f"evidence:maintenance:{name}",
            sha256=sha(f"evidence:{name}"),
            source_type="task_artifact",
            source_task_id=source_task_id,
            sensitivity="confidential",
            collection_mode="offline",
            created_at=NOW,
        )
        experience = ExperienceRecord(
            experience_id=f"experience:maintenance:{name}",
            domain=domain,
            task_id=source_task_id,
            outcome="verified_success",
            sensitivity="confidential",
            summary=f"Verified reusable maintenance source {name}.",
            evidence=(evidence,),
            created_at=NOW,
        )
        return KnowledgeCandidate.from_experiences(
            candidate_id=f"knowledge:maintenance:{name}",
            domain=domain,
            kind="skill",
            title=f"Maintenance skill {name}",
            content=f"Evidence-bound reusable procedure content {name}.",
            scope="local analysis only",
            sensitivity="confidential",
            risk_level="medium",
            ownership="learner_managed",
            action="create",
            execution_mode="analysis_only",
            experiences=(experience,),
            created_at=NOW,
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
            receipt_id=f"receipt:maintenance:{candidate.candidate_id}:{level}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=domain_reviewer,
            human_reviewer_id=human,
            created_at=NOW,
        ).validate()

    def active_item(self, name: str, *, domain: str = "analyst") -> tuple[KnowledgeCandidate, dict]:
        candidate = self.candidate(name, domain=domain)
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
        task = self.task_store.create_task("Adaptive maintenance", "authoritative local task")
        contract = self.task_contracts.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="confidential",
            risk_level="low",
        )
        self.validator.bind_contract(contract)
        return task.task_id

    def verify_task(self, task_id: str) -> None:
        contract = self.task_store.task_contract_for_task(task_id)
        assert isinstance(contract, dict)
        for attempt, validator_id in enumerate(contract["validators"], start=1):
            self.validator.record(
                task_id,
                validator_id,
                status="passed",
                reason_code=f"MAINTENANCE_{validator_id.upper()}_PASS",
                evidence_refs=(sha(f"{task_id}:{validator_id}"),),
                validator_version="maintenance-test/v1",
                attempt=attempt,
            )
        self.task_store.set_status(task_id, TaskStatus.DONE)

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

    @staticmethod
    def context(item: LearningContextItem, *, query: str) -> LearningContext:
        return LearningContext(
            query_sha256=sha(f"query:{query}"),
            domain=item.domain,
            task_sensitivity="confidential",
            items=(item,),
        ).validate()

    def failed_reuse(self, item: LearningContextItem, *, query: str) -> None:
        task_id = self.task()
        record_learning_reuse(self.task_store, task_id, self.context(item, query=query))
        self.task_store.set_status(task_id, TaskStatus.FAILED)

    def successful_reuse(self, item: LearningContextItem, *, query: str) -> None:
        task_id = self.task()
        record_learning_reuse(self.task_store, task_id, self.context(item, query=query))
        self.verify_task(task_id)

    def advisor(self, *, enabled: bool = True, max_signals: int = 32):
        return AdaptiveLearningMaintenanceAdvisor(
            AdaptiveLearningMaintenanceConfig(enabled=enabled, max_signals=max_signals),
            self.task_store,
            self.learning_store,
            self.authority,
        )

    def test_disabled_tick_is_exact_noop(self):
        before = self.authority.verify(self.learning_store)
        receipt = self.advisor(enabled=False).run_once()
        after = self.authority.verify(self.learning_store)

        self.assertEqual(receipt.status, STATUS_DISABLED)
        self.assertFalse(receipt.enabled)
        self.assertEqual(receipt.recommendations, ())
        self.assertEqual(before.checkpoint_sha256, after.checkpoint_sha256)

    def test_network_failure_becomes_domain_revision_or_retirement_review(self):
        candidate, row = self.active_item("network", domain="network")
        item = self.context_item(candidate, row)
        self.failed_reuse(item, query="network-failure")
        before = self.authority.verify(self.learning_store)

        receipt = self.advisor().run_once()

        self.assertEqual(receipt.status, STATUS_RECOMMENDATIONS_READY)
        self.assertEqual(receipt.scanned_signals, 1)
        self.assertEqual(len(receipt.recommendations), 1)
        recommendation = receipt.recommendations[0]
        self.assertEqual(
            recommendation.recommendation_type,
            TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
        )
        self.assertTrue(recommendation.human_review_required)
        self.assertTrue(recommendation.domain_review_required)
        self.assertEqual(recommendation.knowledge_sha256, row["knowledge_sha256"])
        self.assertEqual(self.authority.verify(self.learning_store).checkpoint_sha256, before.checkpoint_sha256)

    def test_two_analyst_failures_become_revision_or_retirement_review(self):
        candidate, row = self.active_item("analyst")
        item = self.context_item(candidate, row)
        self.failed_reuse(item, query="analyst-failure-1")
        self.failed_reuse(item, query="analyst-failure-2")

        receipt = self.advisor().run_once()
        self.assertEqual(receipt.status, STATUS_RECOMMENDATIONS_READY)
        self.assertEqual(
            receipt.recommendations[0].recommendation_type,
            TYPE_REVISION_OR_RETIREMENT_REVIEW,
        )
        self.assertTrue(receipt.recommendations[0].human_review_required)
        self.assertFalse(receipt.recommendations[0].domain_review_required)

    def test_three_verified_successes_become_keep_active_review(self):
        candidate, row = self.active_item("support")
        item = self.context_item(candidate, row)
        for index in range(3):
            self.successful_reuse(item, query=f"support-{index}")

        receipt = self.advisor().run_once()
        self.assertEqual(receipt.status, STATUS_RECOMMENDATIONS_READY)
        self.assertEqual(
            receipt.recommendations[0].recommendation_type,
            TYPE_KEEP_ACTIVE_REVIEW,
        )
        self.assertTrue(receipt.recommendations[0].human_review_required)

    def test_signal_capacity_excess_fails_closed_without_partial_recommendations(self):
        first_candidate, first_row = self.active_item("capacity-one")
        second_candidate, second_row = self.active_item("capacity-two")
        self.failed_reuse(self.context_item(first_candidate, first_row), query="cap-one")
        self.failed_reuse(self.context_item(second_candidate, second_row), query="cap-two")
        before = self.authority.verify(self.learning_store)

        receipt = self.advisor(max_signals=1).run_once()

        self.assertEqual(receipt.status, STATUS_SIGNAL_LIMIT_EXCEEDED)
        self.assertEqual(receipt.scanned_signals, 2)
        self.assertEqual(receipt.emitted_recommendations, 0)
        self.assertEqual(receipt.recommendations, ())
        self.assertIsNone(receipt.proposal_set_sha256)
        self.assertEqual(self.authority.verify(self.learning_store).checkpoint_sha256, before.checkpoint_sha256)

    def test_stale_reuse_version_is_rejected_by_canonical_phase4i_binding(self):
        candidate, row = self.active_item("stale")
        item = self.context_item(candidate, row)
        stale = LearningContextItem(
            item_id=item.item_id,
            knowledge_sha256=sha("stale-knowledge-version"),
            level=item.level,
            domain=item.domain,
            kind=item.kind,
            title=item.title,
            content=item.content,
            scope=item.scope,
            sensitivity=item.sensitivity,
            risk_level=item.risk_level,
            execution_mode=item.execution_mode,
        ).validate()
        self.failed_reuse(stale, query="stale")

        with self.assertRaisesRegex(
            AdaptiveLearningMaintenanceError,
            "MAINTENANCE_CURATION_BLOCKED:CURATION_TARGET_SHA_MISMATCH",
        ):
            self.advisor().run_once()

    def test_receipt_is_deterministic_metadata_only_and_has_no_mutation_surface(self):
        candidate, row = self.active_item("metadata")
        item = self.context_item(candidate, row)
        self.failed_reuse(item, query="metadata-one")
        self.failed_reuse(item, query="metadata-two")
        advisor = self.advisor()

        first = advisor.run_once().to_payload()
        second = advisor.run_once().to_payload()
        self.assertEqual(first, second)
        serialized = json.dumps(first, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(candidate.content, serialized)
        self.assertNotIn("authoritative local task", serialized)
        self.assertNotIn("evidence_bytes", serialized)
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


if __name__ == "__main__":
    unittest.main()
