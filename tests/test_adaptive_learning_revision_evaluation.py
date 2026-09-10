from __future__ import annotations

import hashlib
import tempfile
import unittest
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
from three_agent.adaptive_learning_curation import DeterministicCurationProposalCompiler
from three_agent.adaptive_learning_curation_revision import (
    AuthenticatedCurationRevisionApprovalService,
    CurationRevisionBoundCheckpointAuthority,
    CurationRevisionCoordinator,
    CurationRevisionReceiptStore,
)
from three_agent.adaptive_learning_curation_revision_contract import CurationRevisionResult
from three_agent.adaptive_learning_effectiveness import (
    INTERPRETATION,
    SIGNAL_DOMAIN_REVIEW,
    SIGNAL_REVIEW,
    KnowledgeEffectivenessSignal,
    LearningEffectivenessSnapshot,
)
from three_agent.adaptive_learning_promotion import (
    AuthenticatedLearningPromotionService,
    LearningPromotionAuthorizationError,
    LearningReviewerAuthorizationPolicy,
    LearningReviewerGrant,
)
from three_agent.adaptive_learning_revision_evaluation import (
    DeterministicRevisionEvaluator,
    RevisionActivationGate,
    RevisionEvaluationBoundCheckpointAuthority,
    RevisionEvaluationError,
    RevisionRollbackPlan,
    RevisionValidationGate,
    compare_revision_effectiveness,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.workspace_auth import WorkspaceAuthStore

NOW = "2026-09-01T06:00:00Z"
STORE_ID = "learning-store:phase4k"
KEY_ID = "key:v1"
KEY = b"phase-4k-checkpoint-key-material-00000001"


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class FakeRunner:
    def __init__(self, result: CurationRevisionResult):
        self.result = result.validate()
        self.calls = 0

    def run(self, packet):
        packet.validate()
        self.calls += 1
        return self.result


class AdaptiveLearningRevisionEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = AdaptiveLearningStore(self.root / "learning.db")
        self.journal = self.root / "checkpoint" / "journal.jsonl"
        self.witness = self.root / "trusted-head" / "head.json"
        self.keyring = HmacCheckpointKeyring({KEY_ID: KEY}, active_key_id=KEY_ID)
        self.phase4j_authority = CurationRevisionBoundCheckpointAuthority(
            self.journal, self.witness, self.keyring, store_id=STORE_ID
        )
        self.phase4j_authority.bootstrap(self.store)
        self.learner = LearningStagingGateway(self.store, self.phase4j_authority)
        self.operator = LearningOperatorGateway(self.store, self.phase4j_authority)
        self.auth = WorkspaceAuthStore(self.root / "workspace.db")
        self.auth.initialize()
        self.reviewer = self.auth.create_user(
            username="revision.reviewer",
            password="abcdefghijklmnop",
            display_name="Revision Reviewer",
            department="R&D",
            role="user",
        )
        logged = self.auth.login(
            "revision.reviewer", "abcdefghijklmnop", "192.168.11.20"
        )
        assert logged is not None
        self.token = logged[0]
        self.receipts = CurationRevisionReceiptStore(self.root / "revision-receipts")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def candidate(self, name: str, *, domain: str = "analyst") -> KnowledgeCandidate:
        task_id = f"task:phase4k:{name}"
        evidence = EvidenceReference(
            ref_id=f"evidence:phase4k:{name}",
            sha256=sha(f"evidence:{name}"),
            source_type="task_artifact",
            source_task_id=task_id,
            sensitivity="confidential",
            collection_mode="offline",
            created_at=NOW,
        )
        experience = ExperienceRecord(
            experience_id=f"experience:phase4k:{name}",
            domain=domain,
            task_id=task_id,
            outcome="verified_success",
            sensitivity="confidential",
            summary=f"Verified reusable Phase 4K source experience {name}.",
            evidence=(evidence,),
            created_at=NOW,
        )
        content = (
            "Observation: verified passive evidence is required. "
            "Hypothesis: correlate only exact evidence. "
            "Missing evidence keeps confidence bounded."
            if domain == "analyst"
            else f"Verified reusable passive procedure {name}."
        )
        return KnowledgeCandidate.from_experiences(
            candidate_id=f"knowledge:phase4k:{name}",
            domain=domain,
            kind="analytical_pattern" if domain == "analyst" else "skill",
            title=f"Phase4K {name}",
            content=content,
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
    def validation_receipt(candidate: KnowledgeCandidate, *, level: str):
        return LearningValidationReceipt(
            receipt_id=f"receipt:phase4k:{candidate.candidate_id}:{level}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=(
                "reviewer:domain"
                if level in {"approved", "enterprise"}
                and candidate.domain in {"network", "security"}
                else None
            ),
            human_reviewer_id=(
                "reviewer:human" if level in {"approved", "enterprise"} else None
            ),
            created_at=NOW,
        )

    def reviewer_policy(self, *, domains=()):
        return LearningReviewerAuthorizationPolicy(
            (
                LearningReviewerGrant(
                    user_id=self.reviewer["user_id"],
                    allowed_levels=("approved", "enterprise"),
                    reviewer_domains=tuple(domains),
                ),
            )
        )

    def active_item(self, name: str, *, domain="analyst", level="approved"):
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
        if level == "enterprise":
            row = self.operator.promote(
                candidate.candidate_id,
                target_level="enterprise",
                receipt=self.validation_receipt(candidate, level="enterprise"),
            )
        return candidate, row

    @staticmethod
    def adverse_signal(row: dict, *, domain: str):
        failures = 1 if domain in {"network", "security"} else 2
        return KnowledgeEffectivenessSignal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain=domain,
            unique_task_observations=failures,
            unique_reuse_receipts=failures,
            isolated_task_observations=failures,
            confounded_task_observations=0,
            verified_success_after_reuse=0,
            failed_after_reuse=failures,
            waiting_human_after_reuse=0,
            pending_after_reuse=0,
            done_unverified_after_reuse=0,
            isolated_verified_success=0,
            isolated_failed=failures,
            isolated_waiting_human=0,
            isolated_done_unverified=0,
            advisory_signal=(
                SIGNAL_DOMAIN_REVIEW if domain in {"network", "security"} else SIGNAL_REVIEW
            ),
        )

    def stage_phase4j_revision(self, name: str, *, domain="analyst", active_level="approved"):
        active, row = self.active_item(name, domain=domain, level=active_level)
        signal = self.adverse_signal(row, domain=domain)
        snapshot = LearningEffectivenessSnapshot(
            signals=(signal,),
            unique_receipt_count=signal.unique_reuse_receipts,
            unique_task_count=signal.unique_task_observations,
        )
        proposal_set = DeterministicCurationProposalCompiler(
            self.store, self.phase4j_authority
        ).compile(snapshot)
        proposal = proposal_set.proposals[0]
        policy = self.reviewer_policy(
            domains=((domain,) if domain in {"network", "security"} else ())
        )
        approval = AuthenticatedCurationRevisionApprovalService(
            self.auth, self.store, self.phase4j_authority, policy
        ).approve(
            proposal_set=proposal_set,
            proposal_id=proposal.proposal_id,
            session_token=self.token,
            client_ip="192.168.11.20",
        )
        runner = FakeRunner(
            CurationRevisionResult(
                result="REVISION_CANDIDATE",
                title=f"Revised {active.title}",
                content=(
                    "Observation: use exact verified passive evidence only. "
                    "Hypothesis: require independent corroboration before reuse. "
                    "Missing evidence keeps confidence explicitly bounded."
                    if domain == "analyst"
                    else "Use passive verified evidence, preserve uncertainty, and require corroboration."
                ),
                scope="local read-only analysis",
                revision_reason="Adverse isolated outcomes justify stricter evidence handling.",
            )
        )
        outcome = CurationRevisionCoordinator(
            self.store, self.phase4j_authority, runner, self.receipts
        ).revise_and_stage(proposal_set=proposal_set, approval=approval)
        self.assertEqual(outcome.result, "STAGED")
        self.assertEqual(runner.calls, 1)
        assert outcome.candidate_id is not None
        return active, row, approval, outcome

    def phase4k_authority(self):
        return RevisionEvaluationBoundCheckpointAuthority(
            self.journal, self.witness, self.keyring, store_id=STORE_ID
        )

    def test_exact_phase4j_revision_produces_metadata_only_pass_package(self):
        _active, base_row, approval, outcome = self.stage_phase4j_revision("pass")
        authority = self.phase4k_authority()
        package = DeterministicRevisionEvaluator(
            self.store, authority, self.receipts
        ).compile(outcome.candidate_id, approval=approval)
        self.assertEqual(package.result, "PASS")
        self.assertEqual(package.next_transition, "validated")
        self.assertEqual(package.base_knowledge_sha256, base_row["knowledge_sha256"])
        self.assertEqual(package.curation_approval_sha256, approval.sha256)
        self.assertTrue(all(package.check_map.values()))
        payload = package.to_payload()
        for forbidden in ("title", "content", "scope", "session_token"):
            self.assertNotIn(forbidden, payload)

    def test_phase4j_completed_staged_receipt_is_mandatory(self):
        _active, _row, approval, outcome = self.stage_phase4j_revision("receipt")
        evaluator = DeterministicRevisionEvaluator(
            self.store,
            self.phase4k_authority(),
            CurationRevisionReceiptStore(self.root / "empty-receipts"),
        )
        with self.assertRaisesRegex(RevisionEvaluationError, "PHASE4J_RECEIPT"):
            evaluator.compile(outcome.candidate_id, approval=approval)

    def test_validation_is_only_candidate_to_validated_and_base_stays_active(self):
        _active, base_row, approval, outcome = self.stage_phase4j_revision("validated")
        authority = self.phase4k_authority()
        evaluator = DeterministicRevisionEvaluator(self.store, authority, self.receipts)
        first = evaluator.compile(outcome.candidate_id, approval=approval)
        result = RevisionValidationGate(
            self.store, authority, self.receipts
        ).validate_candidate(first, approval=approval)
        current = self.store.active(first.item_id)
        self.assertEqual(current["knowledge_sha256"], base_row["knowledge_sha256"])
        self.assertEqual(result.candidate_sha256, first.candidate_sha256)
        fresh = evaluator.compile(outcome.candidate_id, approval=approval)
        self.assertEqual(fresh.candidate_level, "validated")
        self.assertEqual(fresh.next_transition, "approved")

    def test_stale_evaluation_fails_before_validation_mutation(self):
        _active, _row, approval, outcome = self.stage_phase4j_revision("stale")
        authority = self.phase4k_authority()
        evaluator = DeterministicRevisionEvaluator(self.store, authority, self.receipts)
        package = evaluator.compile(outcome.candidate_id, approval=approval)
        LearningStagingGateway(self.store, authority).stage(self.candidate("unrelated"))
        with self.assertRaisesRegex(RevisionEvaluationError, "STALE"):
            RevisionValidationGate(self.store, authority, self.receipts).validate_candidate(
                package, approval=approval
            )
        with self.store.connect() as conn:
            row = self.store._candidate_level_row(conn, outcome.candidate_id)
        self.assertEqual(str(row["level"]), "candidate")

    def test_approved_activation_reuses_phase4e_and_rollback_remains_operator_only(self):
        _active, base_row, approval, outcome = self.stage_phase4j_revision("activate")
        authority = self.phase4k_authority()
        evaluator = DeterministicRevisionEvaluator(self.store, authority, self.receipts)
        first = evaluator.compile(outcome.candidate_id, approval=approval)
        validation = RevisionValidationGate(
            self.store, authority, self.receipts
        ).validate_candidate(first, approval=approval)
        validated = evaluator.compile(outcome.candidate_id, approval=approval)
        promotion = AuthenticatedLearningPromotionService(
            self.auth, self.store, authority, self.reviewer_policy()
        )
        result = RevisionActivationGate(
            self.store, authority, self.receipts, promotion
        ).promote(
            package=validated,
            approval=approval,
            session_token=self.token,
            client_ip="192.168.11.20",
            receipt=validation.validation_receipt,
        )
        self.assertEqual(result["target_level"], "approved")
        current = self.store.active(validated.item_id)
        self.assertEqual(current["knowledge_sha256"], validated.candidate_knowledge_sha256)

        plan = RevisionRollbackPlan.from_evaluation(validated)
        self.assertTrue(plan.operator_only)
        self.assertFalse(plan.automatic_rollback)
        LearningOperatorGateway(self.store, authority).rollback(
            plan.item_id,
            target_knowledge_sha256=plan.target_knowledge_sha256,
            expected_current_sha256=plan.expected_current_sha256,
            actor_id="operator:rollback-reviewer",
            reason_code="REVIEWED_REVISION_ROLLBACK",
        )
        restored = self.store.active(plan.item_id)
        self.assertEqual(restored["knowledge_sha256"], base_row["knowledge_sha256"])

    def test_enterprise_baseline_requires_approved_then_enterprise(self):
        _active, base_row, approval, outcome = self.stage_phase4j_revision(
            "enterprise", active_level="enterprise"
        )
        authority = self.phase4k_authority()
        evaluator = DeterministicRevisionEvaluator(self.store, authority, self.receipts)
        first = evaluator.compile(outcome.candidate_id, approval=approval)
        validation = RevisionValidationGate(
            self.store, authority, self.receipts
        ).validate_candidate(first, approval=approval)
        validated = evaluator.compile(outcome.candidate_id, approval=approval)
        promotion = AuthenticatedLearningPromotionService(
            self.auth, self.store, authority, self.reviewer_policy()
        )
        gate = RevisionActivationGate(self.store, authority, self.receipts, promotion)
        gate.promote(
            package=validated,
            approval=approval,
            session_token=self.token,
            client_ip="192.168.11.20",
            receipt=validation.validation_receipt,
        )
        still_enterprise = self.store.active(validated.item_id)
        self.assertEqual(still_enterprise["knowledge_sha256"], base_row["knowledge_sha256"])
        self.assertEqual(still_enterprise["level"], "enterprise")
        approved = evaluator.compile(outcome.candidate_id, approval=approval)
        self.assertEqual(approved.next_transition, "enterprise")
        gate.promote(
            package=approved,
            approval=approval,
            session_token=self.token,
            client_ip="192.168.11.20",
            receipt=validation.validation_receipt,
        )
        active = self.store.active(approved.item_id)
        self.assertEqual(active["knowledge_sha256"], approved.candidate_knowledge_sha256)
        self.assertEqual(active["level"], "enterprise")

    def test_security_activation_keeps_phase4e_domain_entitlement(self):
        _active, _row, approval, outcome = self.stage_phase4j_revision(
            "security", domain="security"
        )
        authority = self.phase4k_authority()
        evaluator = DeterministicRevisionEvaluator(self.store, authority, self.receipts)
        first = evaluator.compile(outcome.candidate_id, approval=approval)
        validation = RevisionValidationGate(
            self.store, authority, self.receipts
        ).validate_candidate(first, approval=approval)
        validated = evaluator.compile(outcome.candidate_id, approval=approval)
        promotion = AuthenticatedLearningPromotionService(
            self.auth, self.store, authority, self.reviewer_policy(domains=())
        )
        with self.assertRaisesRegex(
            LearningPromotionAuthorizationError, "DOMAIN_REVIEW_NOT_AUTHORIZED"
        ):
            RevisionActivationGate(
                self.store, authority, self.receipts, promotion
            ).promote(
                package=validated,
                approval=approval,
                session_token=self.token,
                client_ip="192.168.11.20",
                receipt=validation.validation_receipt,
            )
        current = self.store.active(validated.item_id)
        self.assertEqual(current["knowledge_sha256"], validated.base_knowledge_sha256)

    def test_phase4h_comparison_is_observational_only(self):
        _active, _row, approval, outcome = self.stage_phase4j_revision("effectiveness")
        package = DeterministicRevisionEvaluator(
            self.store, self.phase4k_authority(), self.receipts
        ).compile(outcome.candidate_id, approval=approval)
        base = KnowledgeEffectivenessSignal(
            item_id=package.item_id,
            knowledge_sha256=package.base_knowledge_sha256,
            domain=package.domain,
            unique_task_observations=4,
            unique_reuse_receipts=4,
            isolated_task_observations=4,
            confounded_task_observations=0,
            verified_success_after_reuse=1,
            failed_after_reuse=3,
            waiting_human_after_reuse=0,
            pending_after_reuse=0,
            done_unverified_after_reuse=0,
            isolated_verified_success=1,
            isolated_failed=3,
            isolated_waiting_human=0,
            isolated_done_unverified=0,
            advisory_signal=SIGNAL_REVIEW,
        )
        revised = KnowledgeEffectivenessSignal(
            item_id=package.item_id,
            knowledge_sha256=package.candidate_knowledge_sha256,
            domain=package.domain,
            unique_task_observations=5,
            unique_reuse_receipts=5,
            isolated_task_observations=5,
            confounded_task_observations=0,
            verified_success_after_reuse=4,
            failed_after_reuse=1,
            waiting_human_after_reuse=0,
            pending_after_reuse=0,
            done_unverified_after_reuse=0,
            isolated_verified_success=4,
            isolated_failed=1,
            isolated_waiting_human=0,
            isolated_done_unverified=0,
            advisory_signal="SUPPORT_OBSERVED",
        )
        payload = compare_revision_effectiveness(
            package, base=base, revised=revised
        ).to_payload()
        self.assertEqual(payload["interpretation"], INTERPRETATION)
        self.assertEqual(payload["authority"], "review_only_no_learning_store_mutation")
        self.assertEqual(payload["isolated_verified_success_delta"], 3)
        self.assertEqual(payload["isolated_failed_delta"], -2)
        self.assertNotIn("better", payload)
        self.assertNotIn("promote", payload)

    def test_validation_expectation_rejects_wrong_mutation_kind(self):
        authority = self.phase4k_authority()
        checkpoint = authority.verify(self.store)
        staging = LearningStagingGateway(self.store, authority)
        with self.assertRaisesRegex(LearningCheckpointError, "MUTATION_KIND_MISMATCH"):
            with authority.expect_revision_validation(
                sequence=checkpoint.sequence,
                checkpoint_sha256=checkpoint.checkpoint_sha256,
                state_sha256=checkpoint.state_sha256,
            ):
                staging.stage(self.candidate("wrong-kind"))


if __name__ == "__main__":
    unittest.main()
