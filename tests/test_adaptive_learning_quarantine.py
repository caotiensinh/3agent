from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
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
    TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
    AdaptiveLearningMaintenanceAdvisor,
    AdaptiveLearningMaintenanceConfig,
)
from three_agent.adaptive_learning_quarantine import (
    RECOMMENDED_DISPOSITION,
    STATUS_NO_RECOMMENDATIONS,
    STATUS_RECOMMENDATIONS_READY,
    AdaptiveLearningQuarantineError,
    AdaptiveLearningQuarantineProjector,
)
from three_agent.adaptive_learning_retrieval import LearningContext, LearningContextItem
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger

NOW = "2026-09-08T00:00:00Z"
STORE_ID = "learning-store:quarantine-test"
KEY = b"adaptive-quarantine-checkpoint-key-v1"


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class AdaptiveLearningQuarantineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.task_store = TaskStore(self.root / "tasks.db")
        self.task_store.initialize()
        self.contracts = TaskContractCompiler()
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

    def candidate(self, name: str, *, domain: str) -> KnowledgeCandidate:
        source_task_id = f"task:quarantine-source:{name}"
        evidence = EvidenceReference(
            ref_id=f"evidence:quarantine:{name}",
            sha256=sha(f"evidence:{name}"),
            source_type="task_artifact",
            source_task_id=source_task_id,
            sensitivity="confidential",
            collection_mode="offline",
            created_at=NOW,
        )
        experience = ExperienceRecord(
            experience_id=f"experience:quarantine:{name}",
            domain=domain,
            task_id=source_task_id,
            outcome="verified_success",
            sensitivity="confidential",
            summary=f"Verified quarantine source {name}.",
            evidence=(evidence,),
            created_at=NOW,
        )
        return KnowledgeCandidate.from_experiences(
            candidate_id=f"knowledge:quarantine:{name}",
            domain=domain,
            kind="skill",
            title=f"Quarantine skill {name}",
            content=f"Evidence-bound reusable content {name}.",
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
    def receipt(candidate: KnowledgeCandidate, *, level: str) -> LearningValidationReceipt:
        return LearningValidationReceipt(
            receipt_id=f"receipt:quarantine:{candidate.candidate_id}:{level}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=(
                "reviewer:domain"
                if level == "approved" and candidate.domain in {"network", "security"}
                else None
            ),
            human_reviewer_id="reviewer:human" if level == "approved" else None,
            created_at=NOW,
        ).validate()

    def active_item(self, name: str, *, domain: str) -> tuple[KnowledgeCandidate, dict]:
        candidate = self.candidate(name, domain=domain)
        self.learner.stage(candidate)
        self.operator.promote(
            candidate.candidate_id,
            target_level="validated",
            receipt=self.receipt(candidate, level="validated"),
        )
        row = self.operator.promote(
            candidate.candidate_id,
            target_level="approved",
            receipt=self.receipt(candidate, level="approved"),
        )
        return candidate, row

    @staticmethod
    def item(candidate: KnowledgeCandidate, row: dict) -> LearningContextItem:
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

    def failed_reuse(self, item: LearningContextItem, *, query: str) -> None:
        task = self.task_store.create_task("Quarantine review", "authoritative local task")
        contract = self.contracts.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="confidential",
            risk_level="low",
        )
        self.validator.bind_contract(contract)
        context = LearningContext(
            query_sha256=sha(f"query:{query}"),
            domain=item.domain,
            task_sensitivity="confidential",
            items=(item,),
        ).validate()
        record_learning_reuse(self.task_store, task.task_id, context)
        self.task_store.set_status(task.task_id, TaskStatus.FAILED)

    def maintenance_receipt(self):
        return AdaptiveLearningMaintenanceAdvisor(
            AdaptiveLearningMaintenanceConfig(enabled=True, max_signals=32),
            self.task_store,
            self.learning_store,
            self.authority,
        ).run_once()

    def projector(self):
        return AdaptiveLearningQuarantineProjector(self.learning_store, self.authority)

    def test_network_domain_review_projects_quarantine_recommendation(self):
        candidate, row = self.active_item("network", domain="network")
        self.failed_reuse(self.item(candidate, row), query="network-failure")
        maintenance = self.maintenance_receipt()
        self.assertEqual(
            maintenance.recommendations[0].recommendation_type,
            TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
        )
        before = self.authority.verify(self.learning_store)

        result = self.projector().project(maintenance)

        self.assertEqual(result.status, STATUS_RECOMMENDATIONS_READY)
        self.assertEqual(len(result.recommendations), 1)
        recommendation = result.recommendations[0]
        self.assertEqual(recommendation.item_id, row["item_id"])
        self.assertEqual(recommendation.knowledge_sha256, row["knowledge_sha256"])
        self.assertEqual(recommendation.candidate_sha256, row["candidate_sha256"])
        self.assertEqual(recommendation.recommended_disposition, RECOMMENDED_DISPOSITION)
        self.assertTrue(recommendation.human_review_required)
        self.assertTrue(recommendation.domain_review_required)
        self.assertEqual(result.checkpoint_sha256, before.checkpoint_sha256)
        self.assertEqual(self.authority.verify(self.learning_store).checkpoint_sha256, before.checkpoint_sha256)

    def test_non_sensitive_revision_review_does_not_project_quarantine(self):
        candidate, row = self.active_item("analyst", domain="analyst")
        item = self.item(candidate, row)
        self.failed_reuse(item, query="analyst-failure-one")
        self.failed_reuse(item, query="analyst-failure-two")
        maintenance = self.maintenance_receipt()

        result = self.projector().project(maintenance)

        self.assertEqual(result.status, STATUS_NO_RECOMMENDATIONS)
        self.assertEqual(result.recommendations, ())

    def test_stale_maintenance_checkpoint_is_rejected(self):
        candidate, row = self.active_item("stale", domain="security")
        self.failed_reuse(self.item(candidate, row), query="security-failure")
        maintenance = self.maintenance_receipt()
        self.active_item("checkpoint-change", domain="analyst")

        with self.assertRaisesRegex(
            AdaptiveLearningQuarantineError,
            "QUARANTINE_MAINTENANCE_CHECKPOINT_STALE",
        ):
            self.projector().project(maintenance)

    def test_forged_current_checkpoint_identity_is_rejected(self):
        candidate, row = self.active_item("forged", domain="network")
        self.failed_reuse(self.item(candidate, row), query="forged-failure")
        maintenance = self.maintenance_receipt()
        source = maintenance.recommendations[0]
        forged_source = replace(
            source,
            item_id="knowledge:quarantine:not-active",
            proposal_id="curation:" + "a" * 64,
        ).validate()
        forged_receipt = replace(
            maintenance,
            recommendations=(forged_source,),
            emitted_recommendations=1,
        ).validate()

        with self.assertRaisesRegex(
            AdaptiveLearningQuarantineError,
            "QUARANTINE_TARGET_NOT_ACTIVE",
        ):
            self.projector().project(forged_receipt)

    def test_projection_is_deterministic_metadata_only_and_has_no_mutation_surface(self):
        candidate, row = self.active_item("metadata", domain="security")
        self.failed_reuse(self.item(candidate, row), query="metadata-failure")
        maintenance = self.maintenance_receipt()
        projector = self.projector()

        first = projector.project(maintenance).to_payload()
        second = projector.project(maintenance).to_payload()

        self.assertEqual(first, second)
        serialized = json.dumps(first, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(candidate.content, serialized)
        self.assertNotIn("authoritative local task", serialized)
        self.assertNotIn("query:metadata-failure", serialized)
        self.assertRegex(first["recommendation_set_sha256"], r"^sha256:[0-9a-f]{64}$")
        for forbidden in (
            "archive",
            "disable",
            "rollback",
            "promote",
            "stage",
            "materialize",
            "supersede",
            "execute",
            "invoke",
        ):
            self.assertFalse(hasattr(projector, forbidden), forbidden)

    def test_disabled_or_no_signal_maintenance_receipt_is_not_a_quarantine_source(self):
        disabled = AdaptiveLearningMaintenanceAdvisor(
            AdaptiveLearningMaintenanceConfig(enabled=False),
            self.task_store,
            self.learning_store,
            self.authority,
        ).run_once()
        with self.assertRaisesRegex(
            AdaptiveLearningQuarantineError,
            "QUARANTINE_MAINTENANCE_RECEIPT_NOT_READY",
        ):
            self.projector().project(disabled)


if __name__ == "__main__":
    unittest.main()
