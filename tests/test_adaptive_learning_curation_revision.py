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
    CurationRevisionAuthorizationError,
    CurationRevisionBoundCheckpointAuthority,
    CurationRevisionCoordinator,
    CurationRevisionError,
    CurationRevisionReceiptStore,
)
from three_agent.adaptive_learning_curation_revision_contract import (
    CurationRevisionContractError,
    CurationRevisionResult,
    parse_strict_curation_revision_result,
)
from three_agent.adaptive_learning_effectiveness import (
    SIGNAL_DOMAIN_REVIEW,
    SIGNAL_INSUFFICIENT,
    SIGNAL_REVIEW,
    SIGNAL_SUPPORT,
    KnowledgeEffectivenessSignal,
    LearningEffectivenessSnapshot,
)
from three_agent.adaptive_learning_promotion import (
    LearningReviewerAuthorizationPolicy,
    LearningReviewerGrant,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.workspace_auth import WorkspaceAuthStore

NOW = "2026-09-01T05:00:00Z"
STORE_ID = "learning-store:phase4j"
KEY_ID = "key:v1"
KEY = b"phase-4j-checkpoint-key-material-00000001"


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class FakeRunner:
    def __init__(self, result: CurationRevisionResult, callback=None):
        self.result = result.validate()
        self.callback = callback
        self.calls = 0
        self.packets = []

    def run(self, packet):
        packet.validate()
        self.calls += 1
        self.packets.append(packet)
        if self.callback is not None:
            self.callback()
        return self.result


class AdaptiveLearningCurationRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = AdaptiveLearningStore(self.root / "learning.db")
        self.authority = CurationRevisionBoundCheckpointAuthority(
            self.root / "checkpoint" / "journal.jsonl",
            self.root / "trusted-head" / "head.json",
            HmacCheckpointKeyring({KEY_ID: KEY}, active_key_id=KEY_ID),
            store_id=STORE_ID,
        )
        self.authority.bootstrap(self.store)
        self.learner = LearningStagingGateway(self.store, self.authority)
        self.operator = LearningOperatorGateway(self.store, self.authority)

        self.auth = WorkspaceAuthStore(self.root / "workspace.db")
        self.auth.initialize()
        self.reviewer = self.auth.create_user(
            username="curation.reviewer",
            password="abcdefghijklmnop",
            display_name="Curation Reviewer",
            department="R&D",
            role="user",
        )
        logged = self.auth.login("curation.reviewer", "abcdefghijklmnop", "192.168.11.20")
        assert logged is not None
        self.token = logged[0]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def result(*, no_value: bool = False, same=None) -> CurationRevisionResult:
        if no_value:
            return CurationRevisionResult(
                result="NO_REVISION_VALUE",
                title="",
                content="",
                scope="",
                revision_reason="Observed evidence does not justify a durable revision.",
            ).validate()
        if same is not None:
            return CurationRevisionResult(
                result="REVISION_CANDIDATE",
                title=same.title,
                content=same.content,
                scope=same.scope,
                revision_reason="No effective change.",
            ).validate()
        return CurationRevisionResult(
            result="REVISION_CANDIDATE",
            title="Revised passive analysis procedure",
            content=(
                "Correlate verified passive observations, state uncertainty explicitly, "
                "and require stronger evidence before treating a pattern as reusable."
            ),
            scope="local read-only analysis",
            revision_reason="Adverse isolated outcomes justify a narrower evidence threshold.",
        ).validate()

    def candidate(
        self,
        name: str,
        *,
        domain: str = "analyst",
        sensitivity: str = "confidential",
    ) -> KnowledgeCandidate:
        task_id = f"task:phase4j:{name}"
        evidence = EvidenceReference(
            ref_id=f"evidence:phase4j:{name}",
            sha256=sha(f"evidence:{name}"),
            source_type="task_artifact",
            source_task_id=task_id,
            sensitivity=sensitivity,
            collection_mode="offline",
            created_at=NOW,
        )
        experience = ExperienceRecord(
            experience_id=f"experience:phase4j:{name}",
            domain=domain,
            task_id=task_id,
            outcome="verified_success",
            sensitivity=sensitivity,
            summary=f"Verified reusable Phase 4J source experience {name}.",
            evidence=(evidence,),
            created_at=NOW,
        )
        return KnowledgeCandidate.from_experiences(
            candidate_id=f"knowledge:phase4j:{name}",
            domain=domain,
            kind="skill",
            title=f"Phase4J {name}",
            content=f"Verified reusable passive procedure {name}.",
            scope="local analysis only",
            sensitivity=sensitivity,
            risk_level="medium",
            ownership="learner_managed",
            action="create",
            execution_mode="analysis_only",
            experiences=(experience,),
            created_at=NOW,
        )

    @staticmethod
    def validation_receipt(candidate: KnowledgeCandidate, *, level: str) -> LearningValidationReceipt:
        return LearningValidationReceipt(
            receipt_id=f"receipt:phase4j:{candidate.candidate_id}:{level}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=(
                "reviewer:domain" if level == "approved" and candidate.domain in {"network", "security"} else None
            ),
            human_reviewer_id=("reviewer:human" if level == "approved" else None),
            created_at=NOW,
        )

    def active_item(self, name: str, *, domain="analyst", sensitivity="confidential"):
        candidate = self.candidate(name, domain=domain, sensitivity=sensitivity)
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

    @staticmethod
    def signal(row: dict, *, domain: str, advisory: str) -> KnowledgeEffectivenessSignal:
        if advisory == SIGNAL_REVIEW:
            unique = isolated = failed = isolated_failed = 2
        elif advisory == SIGNAL_DOMAIN_REVIEW:
            unique = isolated = failed = isolated_failed = 1
        elif advisory == SIGNAL_SUPPORT:
            unique = isolated = 3
            failed = isolated_failed = 0
        elif advisory == SIGNAL_INSUFFICIENT:
            unique = isolated = 1
            failed = isolated_failed = 0
        else:
            raise AssertionError(advisory)
        success = 3 if advisory == SIGNAL_SUPPORT else 0
        pending = 1 if advisory == SIGNAL_INSUFFICIENT else 0
        return KnowledgeEffectivenessSignal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain=domain,
            unique_task_observations=unique,
            unique_reuse_receipts=unique,
            isolated_task_observations=isolated,
            confounded_task_observations=0,
            verified_success_after_reuse=success,
            failed_after_reuse=failed,
            waiting_human_after_reuse=0,
            pending_after_reuse=pending,
            done_unverified_after_reuse=0,
            isolated_verified_success=success,
            isolated_failed=isolated_failed,
            isolated_waiting_human=0,
            isolated_done_unverified=0,
            advisory_signal=advisory,
        )

    def proposal(self, row: dict, *, domain="analyst", advisory=SIGNAL_REVIEW):
        signal = self.signal(row, domain=domain, advisory=advisory)
        snapshot = LearningEffectivenessSnapshot(
            signals=(signal,),
            unique_receipt_count=signal.unique_reuse_receipts,
            unique_task_count=signal.unique_task_observations,
        )
        proposal_set = DeterministicCurationProposalCompiler(
            self.store, self.authority
        ).compile(snapshot)
        return proposal_set, proposal_set.proposals[0]

    def policy(self, *, domains=()):
        return LearningReviewerAuthorizationPolicy(
            (
                LearningReviewerGrant(
                    user_id=self.reviewer["user_id"],
                    allowed_levels=("approved",),
                    reviewer_domains=tuple(domains),
                ),
            )
        )

    def approve(self, proposal_set, proposal, *, domains=()):
        service = AuthenticatedCurationRevisionApprovalService(
            self.auth,
            self.store,
            self.authority,
            self.policy(domains=domains),
        )
        return service.approve(
            proposal_set=proposal_set,
            proposal_id=proposal.proposal_id,
            session_token=self.token,
            client_ip="192.168.11.20",
        )

    def coordinator(self, runner):
        return CurationRevisionCoordinator(
            self.store,
            self.authority,
            runner,
            CurationRevisionReceiptStore(self.root / "revision-receipts"),
        )

    def test_authenticated_adverse_revision_stages_patch_but_does_not_activate(self):
        active, row = self.active_item("success")
        proposal_set, proposal = self.proposal(row)
        approval = self.approve(proposal_set, proposal)
        runner = FakeRunner(self.result())

        outcome = self.coordinator(runner).revise_and_stage(
            proposal_set=proposal_set,
            approval=approval,
        )
        self.assertEqual(outcome.result, "STAGED")
        self.assertEqual(runner.calls, 1)
        self.assertIsNotNone(outcome.candidate_id)

        current = self.store.active(active.candidate_id)
        self.assertIsNotNone(current)
        self.assertEqual(current["knowledge_sha256"], row["knowledge_sha256"])
        self.assertEqual(current["candidate"]["content"], active.content)

        with self.store.connect() as conn:
            staged = conn.execute(
                "SELECT * FROM learning_versions WHERE candidate_id=? AND level='candidate'",
                (outcome.candidate_id,),
            ).fetchone()
        self.assertIsNotNone(staged)
        staged_candidate = self.store._candidate_from_row(staged)
        self.assertEqual(staged_candidate.action, "patch")
        self.assertEqual(staged_candidate.target_item_id, active.candidate_id)
        self.assertEqual(staged_candidate.base_item_sha256, row["knowledge_sha256"])
        self.assertEqual(staged_candidate.domain, active.domain)
        self.assertEqual(staged_candidate.kind, active.kind)
        self.assertEqual(staged_candidate.sensitivity, active.sensitivity)
        self.assertEqual(staged_candidate.execution_mode, active.execution_mode)
        self.assertEqual(staged_candidate.ownership, "learner_managed")
        self.assertEqual(staged_candidate.source_experience_hashes, active.source_experience_hashes)
        self.assertIn(approval.sha256, staged_candidate.evidence_hashes)

    def test_observe_and_support_proposals_cannot_enter_revision(self):
        _active, row = self.active_item("non-adverse")
        for advisory in (SIGNAL_INSUFFICIENT, SIGNAL_SUPPORT):
            proposal_set, proposal = self.proposal(row, advisory=advisory)
            service = AuthenticatedCurationRevisionApprovalService(
                self.auth, self.store, self.authority, self.policy()
            )
            with self.assertRaisesRegex(CurationRevisionError, "ACTION_FORBIDDEN"):
                service.approve(
                    proposal_set=proposal_set,
                    proposal_id=proposal.proposal_id,
                    session_token=self.token,
                    client_ip="192.168.11.20",
                )

    def test_reviewer_allowlist_is_required_and_role_is_not_authority(self):
        _active, row = self.active_item("auth")
        proposal_set, proposal = self.proposal(row)
        service = AuthenticatedCurationRevisionApprovalService(
            self.auth,
            self.store,
            self.authority,
            LearningReviewerAuthorizationPolicy(()),
        )
        with self.assertRaisesRegex(
            CurationRevisionAuthorizationError, "REVIEWER_NOT_AUTHORIZED"
        ):
            service.approve(
                proposal_set=proposal_set,
                proposal_id=proposal.proposal_id,
                session_token=self.token,
                client_ip="192.168.11.20",
            )

    def test_security_revision_requires_explicit_domain_reviewer_entitlement(self):
        _active, row = self.active_item("security", domain="security")
        proposal_set, proposal = self.proposal(
            row, domain="security", advisory=SIGNAL_DOMAIN_REVIEW
        )
        with self.assertRaisesRegex(
            CurationRevisionAuthorizationError, "DOMAIN_REVIEW_NOT_AUTHORIZED"
        ):
            self.approve(proposal_set, proposal, domains=())
        approval = self.approve(proposal_set, proposal, domains=("security",))
        self.assertTrue(approval.domain_review_satisfied)

    def test_stale_proposal_set_fails_before_revision_model(self):
        _active, row = self.active_item("stale")
        proposal_set, proposal = self.proposal(row)
        other = self.candidate("stale-other")
        self.learner.stage(other)
        service = AuthenticatedCurationRevisionApprovalService(
            self.auth, self.store, self.authority, self.policy()
        )
        with self.assertRaisesRegex(
            CurationRevisionAuthorizationError, "PROPOSAL_SET_STALE"
        ):
            service.approve(
                proposal_set=proposal_set,
                proposal_id=proposal.proposal_id,
                session_token=self.token,
                client_ip="192.168.11.20",
            )

    def test_secret_active_knowledge_fails_before_runner(self):
        _active, row = self.active_item("secret", sensitivity="secret")
        proposal_set, proposal = self.proposal(row)
        approval = self.approve(proposal_set, proposal)
        runner = FakeRunner(self.result())
        with self.assertRaisesRegex(CurationRevisionError, "SECRET_NOT_SUPPORTED"):
            self.coordinator(runner).revise_and_stage(
                proposal_set=proposal_set, approval=approval
            )
        self.assertEqual(runner.calls, 0)

    def test_no_change_revision_is_rejected_and_not_staged(self):
        active, row = self.active_item("no-change")
        proposal_set, proposal = self.proposal(row)
        approval = self.approve(proposal_set, proposal)
        runner = FakeRunner(self.result(same=active))
        with self.assertRaisesRegex(CurationRevisionError, "NO_CHANGE"):
            self.coordinator(runner).revise_and_stage(
                proposal_set=proposal_set, approval=approval
            )
        with self.store.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM learning_versions WHERE candidate_id LIKE 'candidate:%' AND item_id=? AND level='candidate'",
                (active.candidate_id,),
            ).fetchone()["n"]
        self.assertEqual(int(count), 0)

    def test_checkpoint_change_during_model_is_blocked_inside_stage_lock(self):
        _active, row = self.active_item("race")
        proposal_set, proposal = self.proposal(row)
        approval = self.approve(proposal_set, proposal)
        other = self.candidate("race-other")
        runner = FakeRunner(self.result(), callback=lambda: self.learner.stage(other))
        with self.assertRaisesRegex(
            LearningCheckpointError, "CURATION_REVISION_EXPECTED_SEQUENCE_MISMATCH"
        ):
            self.coordinator(runner).revise_and_stage(
                proposal_set=proposal_set, approval=approval
            )
        self.assertEqual(runner.calls, 1)

    def test_no_revision_value_receipt_prevents_repeat_model_call(self):
        _active, row = self.active_item("dedupe")
        proposal_set, proposal = self.proposal(row)
        approval = self.approve(proposal_set, proposal)
        runner = FakeRunner(self.result(no_value=True))
        coordinator = self.coordinator(runner)
        first = coordinator.revise_and_stage(proposal_set=proposal_set, approval=approval)
        self.assertEqual(first.result, "NO_REVISION_VALUE")
        self.assertEqual(runner.calls, 1)
        with self.assertRaisesRegex(CurationRevisionError, "ALREADY_COMPLETED"):
            coordinator.revise_and_stage(proposal_set=proposal_set, approval=approval)
        self.assertEqual(runner.calls, 1)

    def test_strict_result_rejects_markdown_extra_fields_and_locked_metadata(self):
        with self.assertRaisesRegex(
            CurationRevisionContractError, "WORKER_OUTPUT_INVALID"
        ):
            parse_strict_curation_revision_result(
                '```json\n{"schema_version":"workspace-learning-curation-revision-result/v1"}\n```'
            )
        with self.assertRaisesRegex(
            CurationRevisionContractError, "SCHEMA_FIELDS_INVALID"
        ):
            parse_strict_curation_revision_result(
                '{"schema_version":"workspace-learning-curation-revision-result/v1",'
                '"result":"REVISION_CANDIDATE","title":"x","content":"y","scope":"z",'
                '"revision_reason":"r","domain":"security"}'
            )

    def test_packet_contains_only_bounded_reference_and_locked_authority_metadata(self):
        active, row = self.active_item("packet")
        proposal_set, proposal = self.proposal(row)
        approval = self.approve(proposal_set, proposal)
        runner = FakeRunner(self.result(no_value=True))
        self.coordinator(runner).revise_and_stage(
            proposal_set=proposal_set, approval=approval
        )
        packet = runner.packets[0]
        self.assertEqual(packet.current_content, active.content)
        self.assertEqual(packet.domain, active.domain)
        self.assertEqual(packet.kind, active.kind)
        self.assertEqual(packet.execution_mode, active.execution_mode)
        self.assertEqual(packet.capability_grants, ())
        rendered = repr(packet.to_payload())
        for forbidden in (
            self.token,
            "password=",
            "raw_prompt",
            "conversation",
            "/var/lib/workspace",
            "https://",
        ):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()