from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_checkpoint import HmacCheckpointKeyring, LearningStagingGateway
from three_agent.adaptive_learning_contract import EvidenceReference, ExperienceRecord, KnowledgeCandidate
from three_agent.adaptive_learning_promotion import (
    LearningPromotionAuthorizationError,
    LearningReviewerAuthorizationPolicy,
    LearningReviewerGrant,
    PromotionBoundCheckpointAuthority,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.candidate_skill import CandidateSkill
from three_agent.candidate_skill_review import (
    CandidateSkillApprovalService,
    CandidateSkillReviewError,
    CandidateSkillReviewQueue,
)
from three_agent.candidate_skill_validation import CandidateSkillValidationService
from three_agent.workspace_auth import WorkspaceAuthStore

NOW = "2026-09-08T04:00:00Z"
STORE_ID = "learning-store:candidate-skill-review-test"
KEY = b"candidate-skill-review-checkpoint-key-v1"


def candidate_fixture(
    suffix: str,
    *,
    domain: str = "network",
    title: str | None = None,
) -> KnowledgeCandidate:
    task_id = f"task:skill-review:{suffix}"
    evidence = EvidenceReference(
        ref_id=f"evidence:skill-review:{suffix}",
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
        experience_id=f"experience:skill-review:{suffix}",
        domain=domain,
        task_id=task_id,
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified evidence-backed reusable diagnostic procedure.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return KnowledgeCandidate.from_experiences(
        candidate_id=f"candidate:skill-review:{suffix}",
        domain=domain,
        kind="skill",
        title=title or f"Passive camera diagnosis {suffix}",
        content=(
            "Correlate admitted passive evidence with device and stream state. "
            "Preserve uncertainty, report the likely fault boundary, and do not mutate state."
        ),
        scope="camera-network-read-only-analysis",
        sensitivity="confidential",
        risk_level="high" if domain in {"network", "security"} else "medium",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only" if domain == "network" else "analysis_only",
        experiences=(experience,),
        created_at=NOW,
    )


class CandidateSkillReviewQueueTests(unittest.TestCase):
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
            username="network.reviewer",
            password="abcdefghijklmnop",
            display_name="Network Reviewer",
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

    def login(self, auth):
        result = auth.login("network.reviewer", "abcdefghijklmnop", "192.168.11.20")
        self.assertIsNotNone(result)
        return result[0]

    def test_only_validated_staged_skills_are_listed(self):
        _, store, authority, learner, *_ = self.make_environment()
        pending = candidate_fixture("pending")
        candidate_only = candidate_fixture("candidate-only")
        self.validate(store, authority, learner, pending)
        learner.stage(candidate_only)

        items = CandidateSkillReviewQueue(store, authority).list_pending()
        self.assertEqual([item.candidate_id for item in items], [pending.candidate_id])
        self.assertEqual(items[0].state, "pending_human_approval")
        self.assertNotIn(pending.content, repr(items[0].to_dict()))

    def test_review_packet_explains_workflow_benefit_input_output_and_risk(self):
        _, store, authority, learner, *_ = self.make_environment()
        candidate = candidate_fixture("packet", title="カメラ通信の受動診断")
        self.validate(store, authority, learner, candidate)
        packet = CandidateSkillReviewQueue(store, authority).get(candidate.candidate_id)

        self.assertEqual(packet.domain, "network")
        self.assertEqual(packet.risk_level, "high")
        self.assertGreaterEqual(len(packet.workflow_steps), 3)
        self.assertGreaterEqual(len(packet.benefits), 2)
        self.assertEqual(packet.input_contract["accepted_source"], "verified_evidence_or_observation")
        self.assertIsNone(packet.input_contract["typed_data_schema"])
        self.assertEqual(packet.output_contract["kind"], "instruction_only_reusable_procedure")
        self.assertEqual(packet.authority_summary["capability_grants"], [])
        self.assertFalse(packet.evidence_summary["raw_evidence_included"])
        self.assertIn("カメラ通信の受動診断", packet.proposed_skill_markdown)
        self.assertIn("## Procedure", packet.proposed_skill_markdown)
        self.assertEqual(
            CandidateSkill.from_candidate(candidate).proposed_skill_sha256,
            packet.proposed_skill_sha256,
        )

    def test_review_packet_is_restart_stable_when_canonical_state_is_unchanged(self):
        _, store, authority, learner, *_ = self.make_environment()
        candidate = candidate_fixture("restart")
        self.validate(store, authority, learner, candidate)
        first = CandidateSkillReviewQueue(store, authority).get(candidate.candidate_id)
        second = CandidateSkillReviewQueue(store, authority).get(candidate.candidate_id)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.review_fingerprint, second.review_fingerprint)

    def test_human_confirmation_is_required_and_binds_exact_candidate_hash(self):
        _, store, authority, learner, auth, _, policy = self.make_environment()
        candidate = candidate_fixture("confirm")
        self.validate(store, authority, learner, candidate)
        service = CandidateSkillApprovalService(auth, store, authority, policy)
        packet = service.queue.get(candidate.candidate_id)
        token = self.login(auth)
        before = authority.verify(store)

        with self.assertRaisesRegex(
            CandidateSkillReviewError, "CANDIDATE_SKILL_APPROVAL_CONFIRMATION_REQUIRED"
        ):
            service.approve(
                session_token=token,
                client_ip="192.168.11.20",
                candidate_id=candidate.candidate_id,
                expected_candidate_sha256=packet.candidate_sha256,
                expected_review_fingerprint=packet.review_fingerprint,
                confirm_approve=False,
            )
        self.assertEqual(authority.verify(store).checkpoint_sha256, before.checkpoint_sha256)

        with self.assertRaisesRegex(
            CandidateSkillReviewError, "CANDIDATE_SKILL_APPROVAL_CANDIDATE_CHANGED"
        ):
            service.approve(
                session_token=token,
                client_ip="192.168.11.20",
                candidate_id=candidate.candidate_id,
                expected_candidate_sha256="sha256:" + "f" * 64,
                expected_review_fingerprint=packet.review_fingerprint,
                confirm_approve=True,
            )
        self.assertEqual(authority.verify(store).checkpoint_sha256, before.checkpoint_sha256)

    def test_review_confirmation_becomes_stale_when_checkpoint_changes(self):
        _, store, authority, learner, auth, _, policy = self.make_environment()
        candidate = candidate_fixture("stale")
        self.validate(store, authority, learner, candidate)
        service = CandidateSkillApprovalService(auth, store, authority, policy)
        packet = service.queue.get(candidate.candidate_id)
        token = self.login(auth)

        # Unrelated canonical learning mutation invalidates the packet fingerprint.
        learner.stage(candidate_fixture("other"))
        changed = authority.verify(store)
        with self.assertRaisesRegex(
            CandidateSkillReviewError, "CANDIDATE_SKILL_APPROVAL_REVIEW_CHANGED"
        ):
            service.approve(
                session_token=token,
                client_ip="192.168.11.20",
                candidate_id=candidate.candidate_id,
                expected_candidate_sha256=packet.candidate_sha256,
                expected_review_fingerprint=packet.review_fingerprint,
                confirm_approve=True,
            )
        self.assertEqual(authority.verify(store).checkpoint_sha256, changed.checkpoint_sha256)

    def test_network_approval_still_requires_authenticated_explicit_domain_reviewer(self):
        _, store, authority, learner, auth, reviewer, _ = self.make_environment()
        candidate = candidate_fixture("domain-auth")
        self.validate(store, authority, learner, candidate)
        denied_policy = LearningReviewerAuthorizationPolicy(
            (
                LearningReviewerGrant(
                    user_id=reviewer["user_id"],
                    allowed_levels=("approved",),
                    reviewer_domains=(),
                ),
            )
        )
        service = CandidateSkillApprovalService(auth, store, authority, denied_policy)
        packet = service.queue.get(candidate.candidate_id)
        token = self.login(auth)
        before = authority.verify(store)
        with self.assertRaisesRegex(
            LearningPromotionAuthorizationError, "PROMOTION_DOMAIN_REVIEW_NOT_AUTHORIZED"
        ):
            service.approve(
                session_token=token,
                client_ip="192.168.11.20",
                candidate_id=candidate.candidate_id,
                expected_candidate_sha256=packet.candidate_sha256,
                expected_review_fingerprint=packet.review_fingerprint,
                confirm_approve=True,
            )
        self.assertEqual(authority.verify(store).checkpoint_sha256, before.checkpoint_sha256)

    def test_successful_approval_removes_candidate_from_pending_but_does_not_publish_files(self):
        _, store, authority, learner, auth, reviewer, policy = self.make_environment()
        candidate = candidate_fixture("approve")
        self.validate(store, authority, learner, candidate)
        service = CandidateSkillApprovalService(auth, store, authority, policy)
        packet = service.queue.get(candidate.candidate_id)
        token = self.login(auth)

        result = service.approve(
            session_token=token,
            client_ip="192.168.11.20",
            candidate_id=candidate.candidate_id,
            expected_candidate_sha256=packet.candidate_sha256,
            expected_review_fingerprint=packet.review_fingerprint,
            confirm_approve=True,
        )
        self.assertEqual(result.status, "approved")
        self.assertEqual(result.publication_state, "approved_not_materialized")
        self.assertEqual(result.actor_id, f"workspace-user:{reviewer['user_id']}")
        self.assertEqual(service.queue.list_pending(), ())
        active = store.active(candidate.candidate_id)
        self.assertIsNotNone(active)
        self.assertEqual(active["level"], "approved")
        self.assertFalse(hasattr(service, "materialize"))
        self.assertFalse(hasattr(service, "publish"))

        with self.assertRaisesRegex(CandidateSkillReviewError, "CANDIDATE_SKILL_REVIEW_NOT_PENDING"):
            service.approve(
                session_token=token,
                client_ip="192.168.11.20",
                candidate_id=candidate.candidate_id,
                expected_candidate_sha256=packet.candidate_sha256,
                expected_review_fingerprint=packet.review_fingerprint,
                confirm_approve=True,
            )

    def test_pending_list_is_not_hidden_by_newer_non_pending_versions(self):
        _, store, authority, learner, auth, _, policy = self.make_environment()
        pending = candidate_fixture("older-pending")
        self.validate(store, authority, learner, pending)

        # Create many newer candidates and approve them so the queue must filter
        # before applying the caller-visible pending limit.
        for index in range(4):
            candidate = candidate_fixture(f"newer-{index}")
            self.validate(store, authority, learner, candidate)
            service = CandidateSkillApprovalService(auth, store, authority, policy)
            packet = service.queue.get(candidate.candidate_id)
            token = self.login(auth)
            service.approve(
                session_token=token,
                client_ip="192.168.11.20",
                candidate_id=candidate.candidate_id,
                expected_candidate_sha256=packet.candidate_sha256,
                expected_review_fingerprint=packet.review_fingerprint,
                confirm_approve=True,
            )

        items = CandidateSkillReviewQueue(store, authority).list_pending(limit=1)
        self.assertEqual([item.candidate_id for item in items], [pending.candidate_id])


if __name__ == "__main__":
    unittest.main()
