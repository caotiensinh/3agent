from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from three_agent.adaptive_learning_checkpoint import HmacCheckpointKeyring, LearningStagingGateway
from three_agent.adaptive_learning_contract import EvidenceReference, ExperienceRecord, KnowledgeCandidate
from three_agent.adaptive_learning_promotion import (
    LearningReviewerAuthorizationPolicy,
    LearningReviewerGrant,
    PromotionBoundCheckpointAuthority,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.candidate_skill import CandidateSkill
from three_agent.candidate_skill_materialization import (
    CandidateSkillMaterializationError,
    CandidateSkillMaterializer,
)
from three_agent.candidate_skill_review import (
    CandidateSkillApprovalResult,
    CandidateSkillApprovalService,
)
from three_agent.candidate_skill_validation import CandidateSkillValidationService
from three_agent.skills import ApprovedSkillLoader, SkillSecurityError
from three_agent.workspace_auth import WorkspaceAuthStore

NOW = "2026-09-08T05:30:00Z"
STORE_ID = "learning-store:candidate-skill-materialization-test"
KEY = b"candidate-skill-materialization-checkpoint-key-v1"


def candidate_fixture(suffix: str) -> KnowledgeCandidate:
    task_id = f"task:skill-materialize:{suffix}"
    evidence = EvidenceReference(
        ref_id=f"evidence:skill-materialize:{suffix}",
        sha256="sha256:" + hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
        source_type="task_artifact",
        source_task_id=task_id,
        sensitivity="confidential",
        collection_mode="local_artifact",
        created_at=NOW,
        vendor_family="ExampleCam",
        version="v5",
    )
    experience = ExperienceRecord(
        experience_id=f"experience:skill-materialize:{suffix}",
        domain="network",
        task_id=task_id,
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified passive evidence for a reusable diagnostic procedure.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return KnowledgeCandidate.from_experiences(
        candidate_id=f"candidate:skill-materialize:{suffix}",
        domain="network",
        kind="skill",
        title=f"Passive camera diagnosis {suffix}",
        content=(
            "Correlate admitted passive evidence with device and stream state. "
            "Preserve uncertainty, report the likely fault boundary, and do not mutate state."
        ),
        scope="camera-network-read-only-analysis",
        sensitivity="confidential",
        risk_level="high",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only",
        experiences=(experience,),
        created_at=NOW,
    )


class CandidateSkillMaterializationTests(unittest.TestCase):
    def make_environment(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        store = AdaptiveLearningStore(root / "learning.db")
        authority = PromotionBoundCheckpointAuthority(
            root / "checkpoints" / "journal.jsonl",
            root / "trusted" / "head.json",
            HmacCheckpointKeyring({"key:v1": KEY}, active_key_id="key:v1"),
            store_id=STORE_ID,
        )
        authority.bootstrap(store)
        learner = LearningStagingGateway(store, authority)
        auth = WorkspaceAuthStore(root / "workspace.db")
        auth.initialize()
        reviewer = auth.create_user(
            username="network.publisher",
            password="abcdefghijklmnop",
            display_name="Network Publisher",
            department="R&D",
            role="user",
        )
        policy = LearningReviewerAuthorizationPolicy(
            (
                LearningReviewerGrant(
                    user_id=reviewer["user_id"],
                    allowed_levels=("approved",),
                    reviewer_domains=("network",),
                ),
            )
        )
        return root, store, authority, learner, auth, reviewer, policy

    @staticmethod
    def validate(store, authority, learner, candidate):
        learner.stage(candidate)
        return CandidateSkillValidationService(store, authority).validate_candidate(
            candidate.candidate_id
        )

    def approve(self, store, authority, learner, auth, policy, candidate):
        self.validate(store, authority, learner, candidate)
        service = CandidateSkillApprovalService(auth, store, authority, policy)
        packet = service.queue.get(candidate.candidate_id)
        login = auth.login("network.publisher", "abcdefghijklmnop", "192.168.11.20")
        self.assertIsNotNone(login)
        token = login[0]
        result = service.approve(
            session_token=token,
            client_ip="192.168.11.20",
            candidate_id=candidate.candidate_id,
            expected_candidate_sha256=packet.candidate_sha256,
            expected_review_fingerprint=packet.review_fingerprint,
            confirm_approve=True,
        )
        return packet, result

    def test_approved_candidate_materializes_and_fresh_loader_accepts_it(self):
        root, store, authority, learner, auth, _, policy = self.make_environment()
        candidate = candidate_fixture("restart-load")
        _, approval = self.approve(store, authority, learner, auth, policy, candidate)
        skills_root = root / "skills"

        result = CandidateSkillMaterializer(store, authority, skills_root).materialize(
            approval,
            agent_ids=("research",),
        )
        self.assertEqual(result.publication_state, "materialized")
        self.assertEqual(result.candidate_sha256, candidate.sha256)
        self.assertTrue((skills_root / result.skill_name / "SKILL.md").is_file())
        review = skills_root / result.skill_name / "references" / "approval-review.md"
        self.assertTrue(review.is_file())
        self.assertNotIn(candidate.content, review.read_text(encoding="utf-8"))

        # A new loader instance models process restart; no materializer state is needed.
        loader = ApprovedSkillLoader(skills_root)
        self.assertIn(result.skill_name, loader.audit_registry())
        blocks = loader.load_for_agent("research", (result.skill_name,))
        self.assertEqual(len(blocks), 1)
        self.assertIn("Approved local skill", blocks[0])
        refs = loader.list_references_for_agent("research", result.skill_name)
        self.assertEqual(refs[0]["reference_id"], "approval-review")

        registry = json.loads((skills_root / "registry.json").read_text(encoding="utf-8"))
        entry = registry["skills"][result.skill_name]
        self.assertEqual(entry["references"]["approval-review"]["sha256"], result.review_sha256[7:])
        self.assertEqual(entry["review"], f"skills/{result.skill_name}/references/approval-review.md")

    def test_review_provenance_tamper_is_rejected_after_restart(self):
        root, store, authority, learner, auth, _, policy = self.make_environment()
        candidate = candidate_fixture("review-tamper")
        _, approval = self.approve(store, authority, learner, auth, policy, candidate)
        skills_root = root / "skills"
        result = CandidateSkillMaterializer(store, authority, skills_root).materialize(
            approval,
            agent_ids=("research",),
        )

        review = skills_root / result.skill_name / "references" / "approval-review.md"
        review.write_text(review.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
        fresh_loader = ApprovedSkillLoader(skills_root)
        with self.assertRaisesRegex(SkillSecurityError, "reference (?:size|integrity) mismatch"):
            fresh_loader.load_for_agent("research", (result.skill_name,))

    def test_unapproved_candidate_cannot_publish_any_production_file(self):
        root, store, authority, learner, auth, reviewer, _ = self.make_environment()
        candidate = candidate_fixture("not-approved")
        self.validate(store, authority, learner, candidate)
        service = CandidateSkillApprovalService(
            auth,
            store,
            authority,
            LearningReviewerAuthorizationPolicy(
                (
                    LearningReviewerGrant(
                        user_id=reviewer["user_id"],
                        allowed_levels=("approved",),
                        reviewer_domains=("network",),
                    ),
                )
            ),
        )
        packet = service.queue.get(candidate.candidate_id)
        forged = CandidateSkillApprovalResult(
            status="approved",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            review_fingerprint=packet.review_fingerprint,
            target_level="approved",
            actor_id=f"workspace-user:{reviewer['user_id']}",
            checkpoint_sequence=packet.expected_checkpoint_sequence,
            checkpoint_state_sha256=packet.expected_checkpoint_state_sha256,
        )
        skill_name = CandidateSkill.from_candidate(candidate).proposed_skill_name
        skills_root = root / "skills"

        with self.assertRaisesRegex(
            CandidateSkillMaterializationError,
            "MATERIALIZATION_CANDIDATE_NOT_ACTIVE",
        ):
            CandidateSkillMaterializer(store, authority, skills_root).materialize(
                forged,
                agent_ids=("research",),
            )
        self.assertFalse((skills_root / skill_name).exists())
        self.assertFalse((skills_root / "registry.json").exists())

    def test_create_only_publication_rejects_duplicate_without_mutating_first_copy(self):
        root, store, authority, learner, auth, _, policy = self.make_environment()
        candidate = candidate_fixture("duplicate")
        _, approval = self.approve(store, authority, learner, auth, policy, candidate)
        skills_root = root / "skills"
        materializer = CandidateSkillMaterializer(store, authority, skills_root)
        first = materializer.materialize(approval, agent_ids=("research",))
        registry_before = (skills_root / "registry.json").read_bytes()
        skill_before = (skills_root / first.skill_name / "SKILL.md").read_bytes()

        with self.assertRaisesRegex(
            CandidateSkillMaterializationError,
            "MATERIALIZATION_SKILL_EXISTS",
        ):
            materializer.materialize(approval, agent_ids=("research",))

        self.assertEqual((skills_root / "registry.json").read_bytes(), registry_before)
        self.assertEqual((skills_root / first.skill_name / "SKILL.md").read_bytes(), skill_before)
        self.assertEqual(
            len(ApprovedSkillLoader(skills_root).load_for_agent("research", (first.skill_name,))),
            1,
        )

    def test_failed_post_commit_production_load_rolls_back_registry_and_skill_directory(self):
        root, store, authority, learner, auth, _, policy = self.make_environment()
        candidate = candidate_fixture("rollback")
        _, approval = self.approve(store, authority, learner, auth, policy, candidate)
        skills_root = root / "skills"
        skill_name = CandidateSkill.from_candidate(candidate).proposed_skill_name

        with mock.patch(
            "three_agent.candidate_skill_materialization.ApprovedSkillLoader.load_for_agent",
            side_effect=SkillSecurityError("forced production load failure"),
        ):
            with self.assertRaisesRegex(
                CandidateSkillMaterializationError,
                "MATERIALIZATION_PUBLICATION_FAILED",
            ):
                CandidateSkillMaterializer(store, authority, skills_root).materialize(
                    approval,
                    agent_ids=("research",),
                )

        self.assertFalse((skills_root / skill_name).exists())
        self.assertFalse((skills_root / "registry.json").exists())
        self.assertFalse((root / ".candidate-skill-materialization.lock").exists())


if __name__ == "__main__":
    unittest.main()
