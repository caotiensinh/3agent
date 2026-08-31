from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.adaptive_learning_checkpoint import (
    HmacCheckpointKeyring,
    LearningCheckpointError,
    LearningOperatorGateway,
    LearningStagingGateway,
)
from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
    LearningValidationReceipt,
)
from three_agent.adaptive_learning_promotion import (
    AuthenticatedLearningPromotionService,
    LearningPromotionAuthorizationError,
    LearningReviewerAuthorizationPolicy,
    LearningReviewerGrant,
    PromotionBoundCheckpointAuthority,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.workspace_auth import WorkspaceAuthStore
from three_agent.workspace_external_identity import ExternalSessionAuthStore

NOW = "2026-08-31T08:30:00Z"
STORE_ID = "learning-store:phase4e"
KEY = b"phase4e-checkpoint-key-material-0000001"


def candidate_fixture(suffix: str = "primary") -> tuple[
    KnowledgeCandidate,
    LearningValidationReceipt,
    LearningValidationReceipt,
]:
    evidence = EvidenceReference(
        ref_id=f"evidence:phase4e:{suffix}",
        sha256="sha256:" + ("1" if suffix == "primary" else "2") * 64,
        source_type="syslog",
        source_task_id=f"task:phase4e:{suffix}",
        sensitivity="confidential",
        collection_mode="passive",
        created_at=NOW,
        vendor_family="Cisco CBS250",
        version="3.x",
    )
    experience = ExperienceRecord(
        experience_id=f"experience:phase4e:{suffix}",
        domain="network",
        task_id=f"task:phase4e:{suffix}",
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified passive read-only network analysis for promotion-boundary tests.",
        evidence=(evidence,),
        created_at=NOW,
    )
    candidate = KnowledgeCandidate.from_experiences(
        candidate_id=f"candidate:phase4e:{suffix}",
        domain="network",
        kind="skill",
        title=f"Phase 4E authenticated network review {suffix}",
        content="Correlate passive evidence, preserve uncertainty, and do not mutate network state.",
        scope="offline-read-only-analysis",
        sensitivity="confidential",
        risk_level="high",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only",
        experiences=(experience,),
        created_at=NOW,
    )

    def receipt(name: str) -> LearningValidationReceipt:
        return LearningValidationReceipt(
            receipt_id=f"receipt:phase4e:{suffix}:{name}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=None,
            human_reviewer_id=None,
            created_at=NOW,
        )

    return candidate, receipt("validated"), receipt("approved")


class AdaptiveLearningPromotionTests(unittest.TestCase):
    def make_environment(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)

        auth = WorkspaceAuthStore(root / "workspace.db")
        auth.initialize()
        admin = auth.bootstrap_admin("admin", "0123456789abcdef")
        reviewer = auth.create_user(
            username="network.reviewer",
            password="abcdefghijklmnop",
            display_name="Network Reviewer",
            department="R&D",
            role="user",
        )

        store = AdaptiveLearningStore(root / "learning.db")
        authority = PromotionBoundCheckpointAuthority(
            root / "checkpoint-journal" / "learning-checkpoints.jsonl",
            root / "trusted-head" / "learning-checkpoint-head.json",
            HmacCheckpointKeyring({"key:v1": KEY}, active_key_id="key:v1"),
            store_id=STORE_ID,
        )
        authority.bootstrap(store)
        learner = LearningStagingGateway(store, authority)
        raw_operator = LearningOperatorGateway(store, authority)

        candidate, validated_receipt, approved_receipt = candidate_fixture()
        learner.stage(candidate)
        raw_operator.promote(
            candidate.candidate_id,
            target_level="validated",
            receipt=validated_receipt,
            actor_id="validator:offline",
            reason_code="VALIDATION_GATE_PASSED",
        )

        return {
            "root": root,
            "auth": auth,
            "admin": admin,
            "reviewer": reviewer,
            "store": store,
            "authority": authority,
            "learner": learner,
            "raw_operator": raw_operator,
            "candidate": candidate,
            "approved_receipt": approved_receipt,
        }

    @staticmethod
    def policy_for(user_id: str, *, domains=("network",), levels=("approved",)):
        return LearningReviewerAuthorizationPolicy(
            (
                LearningReviewerGrant(
                    user_id=user_id,
                    allowed_levels=tuple(levels),
                    reviewer_domains=tuple(domains),
                ),
            )
        )

    def login_reviewer(self, env, ip="192.168.11.20"):
        result = env["auth"].login("network.reviewer", "abcdefghijklmnop", ip)
        self.assertIsNotNone(result)
        return result[0]

    def service(self, env, policy):
        return AuthenticatedLearningPromotionService(
            env["auth"], env["store"], env["authority"], policy
        )

    def test_explicitly_granted_user_can_promote_with_authenticated_reviewer_binding(self):
        env = self.make_environment()
        token = self.login_reviewer(env)
        service = self.service(env, self.policy_for(env["reviewer"]["user_id"]))
        before = env["raw_operator"].verify()
        ceremony = service.prepare(
            session_token=token,
            client_ip="192.168.11.20",
            candidate=env["candidate"],
            target_level="approved",
        )
        self.assertEqual(ceremony.expected_checkpoint_sequence, before.sequence)
        self.assertEqual(ceremony.expected_state_sha256, before.state_sha256)

        result = service.promote(
            ceremony=ceremony,
            session_token=token,
            client_ip="192.168.11.20",
            candidate=env["candidate"],
            receipt=env["approved_receipt"],
        )
        after = env["raw_operator"].verify()
        self.assertEqual(result["status"], "promoted")
        self.assertEqual(result["checkpoint_sequence"], before.sequence + 1)
        self.assertEqual(after.sequence, before.sequence + 1)
        self.assertIsNotNone(env["store"].active(env["candidate"].candidate_id))
        actor = f"workspace-user:{env['reviewer']['user_id']}"
        self.assertEqual(result["actor_id"], actor)

        ledger = env["store"].ledger()
        self.assertEqual(ledger[-1]["actor_id"], actor)
        self.assertEqual(ledger[-1]["reason_code"], "AUTHENTICATED_PROMOTION_GATE_PASSED")
        rendered = repr(result)
        self.assertNotIn(env["candidate"].content, rendered)
        self.assertNotIn(token, rendered)
        self.assertNotIn(KEY.decode("ascii"), rendered)

    def test_admin_role_alone_does_not_grant_promotion(self):
        env = self.make_environment()
        result = env["auth"].login("admin", "0123456789abcdef", "192.168.11.21")
        self.assertIsNotNone(result)
        token, user = result
        self.assertEqual(user["role"], "admin")
        service = self.service(env, LearningReviewerAuthorizationPolicy(()))
        before = env["raw_operator"].verify()
        with self.assertRaisesRegex(
            LearningPromotionAuthorizationError, "PROMOTION_REVIEWER_NOT_AUTHORIZED"
        ):
            service.prepare(
                session_token=token,
                client_ip="192.168.11.21",
                candidate=env["candidate"],
                target_level="approved",
            )
        self.assertEqual(env["raw_operator"].verify().checkpoint_sha256, before.checkpoint_sha256)

    def test_domain_review_is_explicit_and_not_inferred_from_role_or_profile(self):
        env = self.make_environment()
        token = self.login_reviewer(env)
        service = self.service(
            env,
            self.policy_for(env["reviewer"]["user_id"], domains=()),
        )
        with self.assertRaisesRegex(
            LearningPromotionAuthorizationError, "PROMOTION_DOMAIN_REVIEW_NOT_AUTHORIZED"
        ):
            service.prepare(
                session_token=token,
                client_ip="192.168.11.20",
                candidate=env["candidate"],
                target_level="approved",
            )

    def test_wrong_ip_and_disabled_user_fail_before_mutation(self):
        env = self.make_environment()
        token = self.login_reviewer(env)
        service = self.service(env, self.policy_for(env["reviewer"]["user_id"]))
        before = env["raw_operator"].verify()
        with self.assertRaisesRegex(
            LearningPromotionAuthorizationError, "PROMOTION_SESSION_INVALID"
        ):
            service.prepare(
                session_token=token,
                client_ip="192.168.11.99",
                candidate=env["candidate"],
                target_level="approved",
            )
        self.assertEqual(env["raw_operator"].verify().checkpoint_sha256, before.checkpoint_sha256)

        token = self.login_reviewer(env)
        ceremony = service.prepare(
            session_token=token,
            client_ip="192.168.11.20",
            candidate=env["candidate"],
            target_level="approved",
        )
        env["auth"].update_user(env["reviewer"]["user_id"], enabled=False)
        with self.assertRaisesRegex(
            LearningPromotionAuthorizationError, "PROMOTION_SESSION_INVALID"
        ):
            service.promote(
                ceremony=ceremony,
                session_token=token,
                client_ip="192.168.11.20",
                candidate=env["candidate"],
                receipt=env["approved_receipt"],
            )
        self.assertEqual(env["raw_operator"].verify().checkpoint_sha256, before.checkpoint_sha256)

    def test_receipt_reviewer_assertion_cannot_impersonate_another_reviewer(self):
        env = self.make_environment()
        token = self.login_reviewer(env)
        service = self.service(env, self.policy_for(env["reviewer"]["user_id"]))
        ceremony = service.prepare(
            session_token=token,
            client_ip="192.168.11.20",
            candidate=env["candidate"],
            target_level="approved",
        )
        forged = replace(
            env["approved_receipt"],
            human_reviewer_id="reviewer:forged",
            domain_reviewer_id="reviewer:forged",
        )
        before = env["raw_operator"].verify()
        with self.assertRaisesRegex(
            LearningPromotionAuthorizationError, "PROMOTION_HUMAN_REVIEWER_MISMATCH"
        ):
            service.promote(
                ceremony=ceremony,
                session_token=token,
                client_ip="192.168.11.20",
                candidate=env["candidate"],
                receipt=forged,
            )
        self.assertEqual(env["raw_operator"].verify().checkpoint_sha256, before.checkpoint_sha256)

    def test_stale_ceremony_fails_inside_checkpoint_boundary_before_target_mutation(self):
        env = self.make_environment()
        token = self.login_reviewer(env)
        service = self.service(env, self.policy_for(env["reviewer"]["user_id"]))
        ceremony = service.prepare(
            session_token=token,
            client_ip="192.168.11.20",
            candidate=env["candidate"],
            target_level="approved",
        )

        other, _, _ = candidate_fixture("other")
        env["learner"].stage(other)
        changed = env["raw_operator"].verify()
        with self.assertRaisesRegex(
            LearningCheckpointError, "PROMOTION_EXPECTED_SEQUENCE_MISMATCH"
        ):
            service.promote(
                ceremony=ceremony,
                session_token=token,
                client_ip="192.168.11.20",
                candidate=env["candidate"],
                receipt=env["approved_receipt"],
            )
        after = env["raw_operator"].verify()
        self.assertEqual(after.checkpoint_sha256, changed.checkpoint_sha256)
        self.assertIsNone(env["store"].active(env["candidate"].candidate_id))

    def test_successful_ceremony_is_one_shot_against_checkpoint_state(self):
        env = self.make_environment()
        token = self.login_reviewer(env)
        service = self.service(env, self.policy_for(env["reviewer"]["user_id"]))
        ceremony = service.prepare(
            session_token=token,
            client_ip="192.168.11.20",
            candidate=env["candidate"],
            target_level="approved",
        )
        service.promote(
            ceremony=ceremony,
            session_token=token,
            client_ip="192.168.11.20",
            candidate=env["candidate"],
            receipt=env["approved_receipt"],
        )
        after_first = env["raw_operator"].verify()
        with self.assertRaisesRegex(
            LearningCheckpointError, "PROMOTION_EXPECTED_SEQUENCE_MISMATCH"
        ):
            service.promote(
                ceremony=ceremony,
                session_token=token,
                client_ip="192.168.11.20",
                candidate=env["candidate"],
                receipt=env["approved_receipt"],
            )
        self.assertEqual(
            env["raw_operator"].verify().checkpoint_sha256,
            after_first.checkpoint_sha256,
        )

    def test_external_session_resolves_to_same_local_principal_and_authorization(self):
        env = self.make_environment()
        external_auth = ExternalSessionAuthStore(env["root"] / "workspace.db")
        token, user = external_auth.issue_session_for_user(
            env["reviewer"]["user_id"], "192.168.11.30"
        )
        self.assertEqual(user["user_id"], env["reviewer"]["user_id"])
        service = AuthenticatedLearningPromotionService(
            external_auth,
            env["store"],
            env["authority"],
            self.policy_for(env["reviewer"]["user_id"]),
        )
        ceremony = service.prepare(
            session_token=token,
            client_ip="192.168.11.30",
            candidate=env["candidate"],
            target_level="approved",
        )
        result = service.promote(
            ceremony=ceremony,
            session_token=token,
            client_ip="192.168.11.30",
            candidate=env["candidate"],
            receipt=env["approved_receipt"],
        )
        self.assertEqual(
            result["actor_id"], f"workspace-user:{env['reviewer']['user_id']}"
        )


if __name__ == "__main__":
    unittest.main()
