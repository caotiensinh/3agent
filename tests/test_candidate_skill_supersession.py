from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.adaptive_learning_checkpoint import (
    HmacCheckpointKeyring,
    LearningOperatorGateway,
    LearningStagingGateway,
)
from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
    LearningValidationReceipt,
)
from three_agent.adaptive_learning_curation import DeterministicCurationProposalCompiler
from three_agent.adaptive_learning_curation_revision import (
    AuthenticatedCurationRevisionApprovalService,
    CurationRevisionBoundCheckpointAuthority,
    CurationRevisionCoordinator,
    CurationRevisionReceiptStore,
)
from three_agent.adaptive_learning_curation_revision_contract import CurationRevisionResult
from three_agent.adaptive_learning_effectiveness import (
    SIGNAL_REVIEW,
    KnowledgeEffectivenessSignal,
    LearningEffectivenessSnapshot,
)
from three_agent.adaptive_learning_promotion import (
    AuthenticatedLearningPromotionService,
    LearningReviewerAuthorizationPolicy,
    LearningReviewerGrant,
)
from three_agent.adaptive_learning_revision_evaluation import (
    DeterministicRevisionEvaluator,
    RevisionActivationGate,
    RevisionEvaluationBoundCheckpointAuthority,
    RevisionEvaluationPackage,
    RevisionRollbackPlan,
    RevisionValidationGate,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.candidate_skill import CandidateSkill
from three_agent.candidate_skill_materialization import CandidateSkillMaterializer
from three_agent.candidate_skill_review import CandidateSkillApprovalResult
from three_agent.candidate_skill_supersession import (
    CandidateSkillSupersessionError,
    CandidateSkillSupersessionManager,
)
from three_agent.skills import ApprovedSkillLoader, SkillSecurityError
from three_agent.workspace_auth import WorkspaceAuthStore

NOW = "2026-09-08T07:00:00Z"
STORE_ID = "learning-store:skill-supersession"
KEY_ID = "key:v1"
KEY = b"skill-supersession-checkpoint-key-material-0001"
_CHECKS = (
    "PATCH_ACTION",
    "LEARNER_MANAGED",
    "ACTIVE_BASE_PRESENT",
    "ACTIVE_LEVEL_SUPPORTED",
    "EXACT_TARGET_BINDING",
    "LOCKED_METADATA_PRESERVED",
    "SOURCE_LINEAGE_PRESERVED",
    "CURATION_APPROVAL_EVIDENCE_BOUND",
    "CONTENT_CHANGED",
    "NON_SECRET_REVISION",
    "CONTRACT_VALID",
    "DOMAIN_VALIDATION_PASSED",
    "NO_DOMAIN_SAFETY_REGRESSION",
    "ROLLBACK_BASE_AVAILABLE",
)


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest(payload: object) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FakeRevisionRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, packet):
        packet.validate()
        self.calls += 1
        return CurationRevisionResult(
            result="REVISION_CANDIDATE",
            title="Revised passive camera evidence diagnosis",
            content=(
                "Correlate exact admitted passive evidence before drawing a fault conclusion. "
                "Require independent corroboration when evidence conflicts, preserve uncertainty, "
                "and do not mutate device or network state."
            ),
            scope="camera evidence read-only synthesis",
            revision_reason="Observed isolated failures justify stricter evidence corroboration.",
        ).validate()


class CandidateSkillSupersessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.skills_root = self.root / "skills"
        self.store = AdaptiveLearningStore(self.root / "learning.db")
        self.journal = self.root / "checkpoint" / "journal.jsonl"
        self.witness = self.root / "trusted-head" / "head.json"
        self.keyring = HmacCheckpointKeyring({KEY_ID: KEY}, active_key_id=KEY_ID)
        self.phase4j_authority = CurationRevisionBoundCheckpointAuthority(
            self.journal,
            self.witness,
            self.keyring,
            store_id=STORE_ID,
        )
        self.phase4j_authority.bootstrap(self.store)
        self.learner = LearningStagingGateway(self.store, self.phase4j_authority)
        self.operator = LearningOperatorGateway(self.store, self.phase4j_authority)

        self.auth = WorkspaceAuthStore(self.root / "workspace.db")
        self.auth.initialize()
        self.reviewer = self.auth.create_user(
            username="skill.reviewer",
            password="abcdefghijklmnop",
            display_name="Skill Reviewer",
            department="R&D",
            role="user",
        )
        logged = self.auth.login(
            "skill.reviewer",
            "abcdefghijklmnop",
            "192.168.11.20",
        )
        assert logged is not None
        self.token = logged[0]
        self.actor = f"workspace-user:{self.reviewer['user_id']}"
        self.policy = LearningReviewerAuthorizationPolicy(
            (
                LearningReviewerGrant(
                    user_id=self.reviewer["user_id"],
                    allowed_levels=("approved", "enterprise"),
                    reviewer_domains=(),
                ),
            )
        )
        self.revision_receipts = CurationRevisionReceiptStore(
            self.root / "revision-receipts"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def candidate(self, suffix: str = "base") -> KnowledgeCandidate:
        task_id = f"task:skill-supersession:{suffix}"
        evidence = EvidenceReference(
            ref_id=f"evidence:skill-supersession:{suffix}",
            sha256=sha(f"evidence:{suffix}"),
            source_type="task_artifact",
            source_task_id=task_id,
            sensitivity="confidential",
            collection_mode="offline",
            created_at=NOW,
            vendor_family="ExampleCam",
            version="v1",
        )
        experience = ExperienceRecord(
            experience_id=f"experience:skill-supersession:{suffix}",
            domain="analyst",
            task_id=task_id,
            outcome="verified_success",
            sensitivity="confidential",
            summary="Verified passive camera evidence diagnosis experience.",
            evidence=(evidence,),
            created_at=NOW,
        )
        return KnowledgeCandidate.from_experiences(
            candidate_id=f"candidate:skill-supersession:{suffix}",
            domain="analyst",
            kind="skill",
            title="Passive camera evidence diagnosis",
            content=(
                "Correlate admitted passive evidence with device and stream state. "
                "Preserve uncertainty and do not mutate device or network state."
            ),
            scope="camera evidence read-only synthesis",
            sensitivity="confidential",
            risk_level="medium",
            ownership="learner_managed",
            action="create",
            execution_mode="analysis_only",
            experiences=(experience,),
            created_at=NOW,
        )

    @staticmethod
    def validation_receipt(
        candidate: KnowledgeCandidate,
        level: str,
        *,
        reviewer: str | None = None,
    ) -> LearningValidationReceipt:
        return LearningValidationReceipt(
            receipt_id=f"receipt:supersession:{candidate.candidate_id}:{level}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=None,
            human_reviewer_id=reviewer,
            created_at=NOW,
        ).validate()

    def create_and_materialize_base(self):
        base = self.candidate()
        self.learner.stage(base)
        self.operator.promote(
            base.candidate_id,
            target_level="validated",
            receipt=self.validation_receipt(base, "validated"),
            actor_id="validator:base-skill",
            reason_code="BASE_SKILL_VALIDATED",
        )
        base_row = self.operator.promote(
            base.candidate_id,
            target_level="approved",
            receipt=self.validation_receipt(base, "approved"),
            actor_id=self.actor,
            reason_code="AUTHENTICATED_PROMOTION_GATE_PASSED",
        )
        checkpoint = self.phase4j_authority.verify(self.store)
        approval = CandidateSkillApprovalResult(
            status="approved",
            candidate_id=base.candidate_id,
            candidate_sha256=base.sha256,
            review_fingerprint=sha("base-review-fingerprint"),
            target_level="approved",
            actor_id=self.actor,
            checkpoint_sequence=checkpoint.sequence,
            checkpoint_state_sha256=checkpoint.state_sha256,
        ).validate()
        result = CandidateSkillMaterializer(
            self.store,
            self.phase4j_authority,
            self.skills_root,
        ).materialize(approval, agent_ids=("research",))
        return base, base_row, result

    @staticmethod
    def adverse_signal(row: dict) -> KnowledgeEffectivenessSignal:
        return KnowledgeEffectivenessSignal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain="analyst",
            unique_task_observations=2,
            unique_reuse_receipts=2,
            isolated_task_observations=2,
            confounded_task_observations=0,
            verified_success_after_reuse=0,
            failed_after_reuse=2,
            waiting_human_after_reuse=0,
            pending_after_reuse=0,
            done_unverified_after_reuse=0,
            isolated_verified_success=0,
            isolated_failed=2,
            isolated_waiting_human=0,
            isolated_done_unverified=0,
            advisory_signal=SIGNAL_REVIEW,
        )

    def phase4k_authority(self) -> RevisionEvaluationBoundCheckpointAuthority:
        return RevisionEvaluationBoundCheckpointAuthority(
            self.journal,
            self.witness,
            self.keyring,
            store_id=STORE_ID,
        )

    def activate_real_phase4k_revision(self):
        base, base_row, materialized = self.create_and_materialize_base()
        signal = self.adverse_signal(base_row)
        proposal_set = DeterministicCurationProposalCompiler(
            self.store,
            self.phase4j_authority,
        ).compile(
            LearningEffectivenessSnapshot(
                signals=(signal,),
                unique_receipt_count=2,
                unique_task_count=2,
            )
        )
        proposal = proposal_set.proposals[0]
        approval = AuthenticatedCurationRevisionApprovalService(
            self.auth,
            self.store,
            self.phase4j_authority,
            self.policy,
        ).approve(
            proposal_set=proposal_set,
            proposal_id=proposal.proposal_id,
            session_token=self.token,
            client_ip="192.168.11.20",
        )
        runner = FakeRevisionRunner()
        outcome = CurationRevisionCoordinator(
            self.store,
            self.phase4j_authority,
            runner,
            self.revision_receipts,
        ).revise_and_stage(proposal_set=proposal_set, approval=approval)
        self.assertEqual(outcome.result, "STAGED")
        self.assertEqual(runner.calls, 1)
        assert outcome.candidate_id is not None

        authority = self.phase4k_authority()
        evaluator = DeterministicRevisionEvaluator(
            self.store,
            authority,
            self.revision_receipts,
        )
        candidate_package = evaluator.compile(outcome.candidate_id, approval=approval)
        validation = RevisionValidationGate(
            self.store,
            authority,
            self.revision_receipts,
        ).validate_candidate(candidate_package, approval=approval)
        activation_package = evaluator.compile(outcome.candidate_id, approval=approval)
        self.assertEqual(activation_package.next_transition, "approved")
        promotion = AuthenticatedLearningPromotionService(
            self.auth,
            self.store,
            authority,
            self.policy,
        )
        promotion_result = RevisionActivationGate(
            self.store,
            authority,
            self.revision_receipts,
            promotion,
        ).promote(
            package=activation_package,
            approval=approval,
            session_token=self.token,
            client_ip="192.168.11.20",
            receipt=validation.validation_receipt,
        )
        self.assertEqual(promotion_result["target_level"], "approved")
        return (
            base,
            base_row,
            materialized,
            authority,
            activation_package,
            promotion_result,
        )

    def manager(self, authority):
        return CandidateSkillSupersessionManager(
            self.store,
            authority,
            self.skills_root,
        )

    def registry(self) -> dict:
        return json.loads((self.skills_root / "registry.json").read_text(encoding="utf-8"))

    def test_real_phase4k_revision_supersedes_immutable_production_version(self):
        base, _row, materialized, authority, package, promotion = (
            self.activate_real_phase4k_revision()
        )
        old_path = self.skills_root / materialized.skill_name / "SKILL.md"
        old_bytes = old_path.read_bytes()

        result = self.manager(authority).supersede(
            package=package,
            promotion_result=promotion,
        )
        registry = self.registry()["skills"]
        self.assertFalse(registry[result.base_skill_name]["enabled"])
        self.assertTrue(registry[result.revised_skill_name]["enabled"])
        self.assertEqual(old_path.read_bytes(), old_bytes)
        self.assertTrue((self.skills_root / result.revised_skill_name / "SKILL.md").is_file())
        self.assertIn(
            f"candidate:{package.candidate_id}:{package.candidate_sha256}",
            registry[result.revised_skill_name]["provenance"],
        )
        self.assertIn(
            f"learning-item:{package.item_id}:{package.candidate_knowledge_sha256}",
            registry[result.revised_skill_name]["provenance"],
        )
        self.assertIn(
            f"learning-item:{package.item_id}:{package.base_knowledge_sha256}",
            registry[result.base_skill_name]["provenance"],
        )

        fresh = ApprovedSkillLoader(self.skills_root)
        blocks = fresh.load_for_agent("research", (result.revised_skill_name,))
        self.assertEqual(len(blocks), 1)
        self.assertIn("independent corroboration", blocks[0])
        with self.assertRaises(SkillSecurityError):
            fresh.load_for_agent("research", (result.base_skill_name,))
        self.assertEqual(base.sha256, package.base_candidate_sha256)

    def test_wrong_promotion_actor_is_rejected_without_production_mutation(self):
        _base, _row, _materialized, authority, package, promotion = (
            self.activate_real_phase4k_revision()
        )
        before = (self.skills_root / "registry.json").read_bytes()
        forged = dict(promotion)
        forged["actor_id"] = "workspace-user:usr_forged"
        with self.assertRaisesRegex(
            CandidateSkillSupersessionError,
            "SUPERSESSION_ACTIVATION_LEDGER_MISMATCH",
        ):
            self.manager(authority).supersede(
                package=package,
                promotion_result=forged,
            )
        self.assertEqual((self.skills_root / "registry.json").read_bytes(), before)

    def test_tampered_enabled_base_fails_closed_before_publication(self):
        _base, _row, materialized, authority, package, promotion = (
            self.activate_real_phase4k_revision()
        )
        base_path = self.skills_root / materialized.skill_name / "SKILL.md"
        base_path.write_text(
            base_path.read_text(encoding="utf-8") + "\nUNREVIEWED CHANGE\n",
            encoding="utf-8",
        )
        registry_before = (self.skills_root / "registry.json").read_bytes()
        with self.assertRaisesRegex(
            CandidateSkillSupersessionError,
            "SUPERSESSION_EXISTING_REGISTRY_INVALID",
        ):
            self.manager(authority).supersede(
                package=package,
                promotion_result=promotion,
            )
        self.assertEqual((self.skills_root / "registry.json").read_bytes(), registry_before)

    def test_production_restore_requires_completed_operator_learning_rollback(self):
        _base, _row, _materialized, authority, package, promotion = (
            self.activate_real_phase4k_revision()
        )
        manager = self.manager(authority)
        superseded = manager.supersede(package=package, promotion_result=promotion)
        plan = RevisionRollbackPlan.from_evaluation(package)

        with self.assertRaisesRegex(
            CandidateSkillSupersessionError,
            "RESTORATION_LEARNING_ROLLBACK_REQUIRED",
        ):
            manager.restore_after_operator_rollback(plan)

        LearningOperatorGateway(self.store, authority).rollback(
            plan.item_id,
            target_knowledge_sha256=plan.target_knowledge_sha256,
            expected_current_sha256=plan.expected_current_sha256,
            actor_id="operator:rollback-reviewer",
            reason_code="REVIEWED_REVISION_ROLLBACK",
        )
        restored = manager.restore_after_operator_rollback(plan)
        self.assertEqual(restored.restored_skill_name, superseded.base_skill_name)
        self.assertEqual(restored.disabled_skill_name, superseded.revised_skill_name)
        registry = self.registry()["skills"]
        self.assertTrue(registry[superseded.base_skill_name]["enabled"])
        self.assertFalse(registry[superseded.revised_skill_name]["enabled"])
        fresh = ApprovedSkillLoader(self.skills_root)
        blocks = fresh.load_for_agent("research", (superseded.base_skill_name,))
        self.assertEqual(len(blocks), 1)
        self.assertIn("Correlate admitted passive evidence", blocks[0])

    def test_tampered_disabled_rollback_target_is_not_reenabled(self):
        _base, _row, _materialized, authority, package, promotion = (
            self.activate_real_phase4k_revision()
        )
        manager = self.manager(authority)
        superseded = manager.supersede(package=package, promotion_result=promotion)
        plan = RevisionRollbackPlan.from_evaluation(package)
        LearningOperatorGateway(self.store, authority).rollback(
            plan.item_id,
            target_knowledge_sha256=plan.target_knowledge_sha256,
            expected_current_sha256=plan.expected_current_sha256,
            actor_id="operator:rollback-reviewer",
            reason_code="REVIEWED_REVISION_ROLLBACK",
        )
        target = self.skills_root / superseded.base_skill_name / "SKILL.md"
        target.write_text(
            target.read_text(encoding="utf-8") + "\nTAMPERED HISTORICAL BYTES\n",
            encoding="utf-8",
        )
        before = (self.skills_root / "registry.json").read_bytes()
        with self.assertRaisesRegex(
            CandidateSkillSupersessionError,
            "RESTORATION_PUBLICATION_FAILED",
        ):
            manager.restore_after_operator_rollback(plan)
        self.assertEqual((self.skills_root / "registry.json").read_bytes(), before)
        registry = self.registry()["skills"]
        self.assertFalse(registry[superseded.base_skill_name]["enabled"])
        self.assertTrue(registry[superseded.revised_skill_name]["enabled"])

    def test_post_commit_loader_failure_restores_registry_and_removes_new_version(self):
        _base, _row, materialized, authority, package, promotion = (
            self.activate_real_phase4k_revision()
        )
        before = (self.skills_root / "registry.json").read_bytes()
        old_dirs = {path.name for path in self.skills_root.iterdir() if path.is_dir()}
        with patch(
            "three_agent.candidate_skill_supersession.ApprovedSkillLoader.load_for_agent",
            side_effect=SkillSecurityError("forced production load failure"),
        ):
            with self.assertRaisesRegex(
                CandidateSkillSupersessionError,
                "SUPERSESSION_PUBLICATION_FAILED",
            ):
                self.manager(authority).supersede(
                    package=package,
                    promotion_result=promotion,
                )
        self.assertEqual((self.skills_root / "registry.json").read_bytes(), before)
        self.assertEqual(
            {path.name for path in self.skills_root.iterdir() if path.is_dir()},
            old_dirs,
        )
        self.assertEqual(old_dirs, {materialized.skill_name})

    def test_forged_pass_package_cannot_replace_missing_phase4k_validation(self):
        base, base_row, _materialized = self.create_and_materialize_base()
        patch_candidate = KnowledgeCandidate(
            candidate_id="candidate:generic-patch",
            domain=base.domain,
            kind="skill",
            title="Generic patched camera diagnosis",
            content="Use exact passive evidence and preserve uncertainty without state mutation.",
            scope=base.scope,
            sensitivity=base.sensitivity,
            risk_level=base.risk_level,
            ownership=base.ownership,
            action="patch",
            execution_mode=base.execution_mode,
            source_experience_ids=base.source_experience_ids,
            source_experience_hashes=base.source_experience_hashes,
            source_domains=base.source_domains,
            source_sensitivities=base.source_sensitivities,
            source_task_ids=base.source_task_ids,
            source_outcomes=base.source_outcomes,
            evidence_ref_ids=base.evidence_ref_ids,
            evidence_hashes=base.evidence_hashes,
            target_item_id=str(base_row["item_id"]),
            base_item_sha256=str(base_row["knowledge_sha256"]),
            created_at=NOW,
        ).validate()
        self.learner.stage(patch_candidate)
        validated_receipt = self.validation_receipt(patch_candidate, "validated")
        validated_row = self.operator.promote(
            patch_candidate.candidate_id,
            target_level="validated",
            receipt=validated_receipt,
            actor_id="validator:generic",
            reason_code="GENERIC_VALIDATION_PASSED",
        )
        checkpoint = self.phase4j_authority.verify(self.store)
        forged_package = RevisionEvaluationPackage(
            candidate_id=patch_candidate.candidate_id,
            candidate_sha256=patch_candidate.sha256,
            candidate_knowledge_sha256=str(validated_row["knowledge_sha256"]),
            candidate_level="validated",
            item_id=str(base_row["item_id"]),
            base_candidate_id=base.candidate_id,
            base_candidate_sha256=base.sha256,
            base_knowledge_sha256=str(base_row["knowledge_sha256"]),
            base_level="approved",
            curation_approval_id="curation-approval:forged",
            curation_approval_sha256=sha("forged-approval"),
            curation_proposal_id="curation:forged",
            curation_revision_receipt_sha256=sha("forged-revision-receipt"),
            domain=patch_candidate.domain,
            kind=patch_candidate.kind,
            sensitivity=patch_candidate.sensitivity,
            risk_level=patch_candidate.risk_level,
            ownership=patch_candidate.ownership,
            execution_mode=patch_candidate.execution_mode,
            changed_fields=("title", "content"),
            checks=tuple((name, True) for name in _CHECKS),
            reason_codes=(),
            result="PASS",
            checkpoint_sequence=checkpoint.sequence,
            checkpoint_sha256=checkpoint.checkpoint_sha256,
            state_sha256=checkpoint.state_sha256,
            created_at=checkpoint.created_at,
        ).validate()
        approved_receipt = self.validation_receipt(
            patch_candidate,
            "approved",
            reviewer=self.actor,
        )
        actor = self.actor
        self.operator.promote(
            patch_candidate.candidate_id,
            target_level="approved",
            receipt=approved_receipt,
            actor_id=actor,
            reason_code="AUTHENTICATED_PROMOTION_GATE_PASSED",
        )
        after = self.phase4j_authority.verify(self.store)
        promotion_result = {
            "schema_version": "workspace-adaptive-learning-promotion-result/v1",
            "status": "promoted",
            "candidate_id": patch_candidate.candidate_id,
            "candidate_sha256": patch_candidate.sha256,
            "target_level": "approved",
            "actor_id": actor,
            "validation_receipt_sha256": digest(approved_receipt.to_payload()),
            "checkpoint_sequence": after.sequence,
            "checkpoint_state_sha256": after.state_sha256,
        }
        before_registry = (self.skills_root / "registry.json").read_bytes()
        with self.assertRaisesRegex(
            CandidateSkillSupersessionError,
            "SUPERSESSION_PHASE4K_VALIDATION_LEDGER_INVALID",
        ):
            self.manager(self.phase4k_authority()).supersede(
                package=forged_package,
                promotion_result=promotion_result,
            )
        self.assertEqual((self.skills_root / "registry.json").read_bytes(), before_registry)


if __name__ == "__main__":
    unittest.main()
