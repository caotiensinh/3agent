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
from three_agent.adaptive_learning_curation import (
    ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW,
    ACTION_KEEP_ACTIVE_REVIEW,
    ACTION_OBSERVE_MORE,
    ACTION_REVISE_OR_ARCHIVE_REVIEW,
    DeterministicCurationProposalCompiler,
    LearningCurationError,
)
from three_agent.adaptive_learning_effectiveness import (
    INTERPRETATION,
    SIGNAL_DOMAIN_REVIEW,
    SIGNAL_INSUFFICIENT,
    SIGNAL_REVIEW,
    SIGNAL_SUPPORT,
    KnowledgeEffectivenessSignal,
    LearningEffectivenessSnapshot,
)
from three_agent.adaptive_learning_store import AdaptiveLearningStore

NOW = "2026-09-01T00:00:00Z"
STORE_ID = "learning-store:phase4i"
KEY_ID = "key:v1"
KEY = b"phase-4i-checkpoint-key-material-00000001"


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class LearningCurationProposalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = AdaptiveLearningStore(self.root / "learning.db")
        self.authority = LearningCheckpointAuthority(
            self.root / "checkpoint" / "journal.jsonl",
            self.root / "trusted-head" / "head.json",
            HmacCheckpointKeyring({KEY_ID: KEY}, active_key_id=KEY_ID),
            store_id=STORE_ID,
        )
        self.authority.bootstrap(self.store)
        self.learner = LearningStagingGateway(self.store, self.authority)
        self.operator = LearningOperatorGateway(self.store, self.authority)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def candidate(self, name: str, *, domain: str = "analyst") -> KnowledgeCandidate:
        task_id = f"task:phase4i:{name}"
        evidence = EvidenceReference(
            ref_id=f"evidence:phase4i:{name}",
            sha256=sha(f"evidence:{name}"),
            source_type="task_artifact",
            source_task_id=task_id,
            sensitivity="confidential",
            collection_mode="offline",
            created_at=NOW,
            vendor_family="workspace",
            version="1",
        )
        experience = ExperienceRecord(
            experience_id=f"experience:phase4i:{name}",
            domain=domain,
            task_id=task_id,
            outcome="verified_success",
            sensitivity="confidential",
            summary=f"Verified reusable Phase 4I experience {name}.",
            evidence=(evidence,),
            created_at=NOW,
        )
        return KnowledgeCandidate.from_experiences(
            candidate_id=f"knowledge:phase4i:{name}",
            domain=domain,
            kind="skill",
            title=f"Phase4I {name}",
            content=f"Verified reusable procedure content {name}.",
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
    def receipt(
        candidate: KnowledgeCandidate,
        *,
        level: str,
        domain: str,
    ) -> LearningValidationReceipt:
        human = "reviewer:human" if level in {"approved", "enterprise"} else None
        domain_reviewer = (
            "reviewer:domain"
            if level in {"approved", "enterprise"} and domain in {"network", "security"}
            else None
        )
        return LearningValidationReceipt(
            receipt_id=f"receipt:phase4i:{candidate.candidate_id}:{level}",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=domain_reviewer,
            human_reviewer_id=human,
            created_at=NOW,
        )

    def active_item(
        self,
        name: str,
        *,
        domain: str = "analyst",
        enterprise: bool = False,
    ) -> tuple[KnowledgeCandidate, dict]:
        candidate = self.candidate(name, domain=domain)
        self.learner.stage(candidate)
        self.operator.promote(
            candidate.candidate_id,
            target_level="validated",
            receipt=self.receipt(candidate, level="validated", domain=domain),
        )
        row = self.operator.promote(
            candidate.candidate_id,
            target_level="approved",
            receipt=self.receipt(candidate, level="approved", domain=domain),
        )
        if enterprise:
            row = self.operator.promote(
                candidate.candidate_id,
                target_level="enterprise",
                receipt=self.receipt(candidate, level="enterprise", domain=domain),
            )
        return candidate, row

    @staticmethod
    def signal(
        *,
        item_id: str,
        knowledge_sha256: str,
        domain: str,
        advisory: str,
    ) -> KnowledgeEffectivenessSignal:
        if advisory == SIGNAL_SUPPORT:
            unique = isolated = success = isolated_success = 3
            failed = waiting = pending = unverified = 0
            isolated_failed = isolated_waiting = isolated_unverified = 0
        elif advisory == SIGNAL_REVIEW:
            unique = isolated = failed = isolated_failed = 2
            success = waiting = pending = unverified = 0
            isolated_success = isolated_waiting = isolated_unverified = 0
        elif advisory == SIGNAL_DOMAIN_REVIEW:
            unique = isolated = failed = isolated_failed = 1
            success = waiting = pending = unverified = 0
            isolated_success = isolated_waiting = isolated_unverified = 0
        elif advisory == SIGNAL_INSUFFICIENT:
            unique = isolated = pending = 1
            success = failed = waiting = unverified = 0
            isolated_success = isolated_failed = isolated_waiting = isolated_unverified = 0
        else:
            raise AssertionError(advisory)
        return KnowledgeEffectivenessSignal(
            item_id=item_id,
            knowledge_sha256=knowledge_sha256,
            domain=domain,
            unique_task_observations=unique,
            unique_reuse_receipts=unique,
            isolated_task_observations=isolated,
            confounded_task_observations=0,
            verified_success_after_reuse=success,
            failed_after_reuse=failed,
            waiting_human_after_reuse=waiting,
            pending_after_reuse=pending,
            done_unverified_after_reuse=unverified,
            isolated_verified_success=isolated_success,
            isolated_failed=isolated_failed,
            isolated_waiting_human=isolated_waiting,
            isolated_done_unverified=isolated_unverified,
            advisory_signal=advisory,
        )

    @staticmethod
    def snapshot(*signals: KnowledgeEffectivenessSignal) -> LearningEffectivenessSnapshot:
        max_tasks = max((signal.unique_task_observations for signal in signals), default=0)
        max_receipts = max((signal.unique_reuse_receipts for signal in signals), default=0)
        return LearningEffectivenessSnapshot(
            signals=tuple(signals),
            unique_receipt_count=max_receipts,
            unique_task_count=max_tasks,
        )

    def compile_one(
        self,
        row: dict,
        *,
        domain: str = "analyst",
        advisory: str = SIGNAL_INSUFFICIENT,
    ):
        signal = self.signal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain=domain,
            advisory=advisory,
        )
        result = DeterministicCurationProposalCompiler(
            self.store, self.authority
        ).compile(self.snapshot(signal))
        self.assertEqual(len(result.proposals), 1)
        return result, result.proposals[0]

    def test_support_yields_keep_active_review_not_promotion(self):
        _candidate, row = self.active_item("support")
        result, proposal = self.compile_one(row, advisory=SIGNAL_SUPPORT)

        self.assertEqual(proposal.curation_action, ACTION_KEEP_ACTIVE_REVIEW)
        self.assertEqual(proposal.active_level, "approved")
        self.assertTrue(proposal.human_review_required)
        self.assertFalse(proposal.domain_review_required)
        self.assertEqual(proposal.capability_grants, ())
        self.assertEqual(result.capability_grants, ())
        for forbidden in ("promote", "enterprise", "stage", "archive", "rollback"):
            self.assertFalse(hasattr(proposal, forbidden), forbidden)

    def test_insufficient_evidence_can_only_observe_more(self):
        _candidate, row = self.active_item("observe")
        _result, proposal = self.compile_one(row, advisory=SIGNAL_INSUFFICIENT)
        self.assertEqual(proposal.curation_action, ACTION_OBSERVE_MORE)
        self.assertFalse(proposal.human_review_required)
        self.assertFalse(proposal.domain_review_required)

    def test_analyst_adverse_signal_requires_human_revision_review(self):
        _candidate, row = self.active_item("analyst-review")
        _result, proposal = self.compile_one(row, advisory=SIGNAL_REVIEW)
        self.assertEqual(proposal.curation_action, ACTION_REVISE_OR_ARCHIVE_REVIEW)
        self.assertTrue(proposal.human_review_required)
        self.assertFalse(proposal.domain_review_required)

    def test_security_adverse_signal_requires_human_and_domain_review(self):
        _candidate, row = self.active_item("security-review", domain="security")
        _result, proposal = self.compile_one(
            row,
            domain="security",
            advisory=SIGNAL_DOMAIN_REVIEW,
        )
        self.assertEqual(
            proposal.curation_action,
            ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW,
        )
        self.assertTrue(proposal.human_review_required)
        self.assertTrue(proposal.domain_review_required)

    def test_enterprise_observe_more_still_requires_human_review(self):
        _candidate, row = self.active_item("enterprise", enterprise=True)
        _result, proposal = self.compile_one(row, advisory=SIGNAL_INSUFFICIENT)
        self.assertEqual(proposal.active_level, "enterprise")
        self.assertEqual(proposal.curation_action, ACTION_OBSERVE_MORE)
        self.assertTrue(proposal.human_review_required)
        self.assertFalse(proposal.domain_review_required)

    def test_security_enterprise_always_requires_domain_review(self):
        _candidate, row = self.active_item(
            "security-enterprise",
            domain="security",
            enterprise=True,
        )
        _result, proposal = self.compile_one(
            row,
            domain="security",
            advisory=SIGNAL_INSUFFICIENT,
        )
        self.assertTrue(proposal.human_review_required)
        self.assertTrue(proposal.domain_review_required)

    def test_stale_exact_sha_fails_closed(self):
        _candidate, row = self.active_item("stale")
        signal = self.signal(
            item_id=str(row["item_id"]),
            knowledge_sha256=sha("not-current"),
            domain="analyst",
            advisory=SIGNAL_SUPPORT,
        )
        with self.assertRaisesRegex(LearningCurationError, "CURATION_TARGET_SHA_MISMATCH"):
            DeterministicCurationProposalCompiler(
                self.store, self.authority
            ).compile(self.snapshot(signal))

    def test_archived_or_unpromoted_target_cannot_be_curated(self):
        candidate, row = self.active_item("archive")
        self.operator.archive(
            candidate.candidate_id,
            expected_current_sha256=str(row["knowledge_sha256"]),
        )
        signal = self.signal(
            item_id=candidate.candidate_id,
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain="analyst",
            advisory=SIGNAL_REVIEW,
        )
        with self.assertRaisesRegex(LearningCurationError, "CURATION_TARGET_NOT_ACTIVE"):
            DeterministicCurationProposalCompiler(
                self.store, self.authority
            ).compile(self.snapshot(signal))

        staged = self.candidate("staged-only")
        staged_row = self.learner.stage(staged)
        staged_signal = self.signal(
            item_id=staged.candidate_id,
            knowledge_sha256=str(staged_row["knowledge_sha256"]),
            domain="analyst",
            advisory=SIGNAL_INSUFFICIENT,
        )
        with self.assertRaisesRegex(LearningCurationError, "CURATION_TARGET_NOT_ACTIVE"):
            DeterministicCurationProposalCompiler(
                self.store, self.authority
            ).compile(self.snapshot(staged_signal))

    def test_domain_mismatch_fails_closed(self):
        _candidate, row = self.active_item("domain")
        signal = self.signal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain="general",
            advisory=SIGNAL_INSUFFICIENT,
        )
        with self.assertRaisesRegex(LearningCurationError, "CURATION_TARGET_DOMAIN_MISMATCH"):
            DeterministicCurationProposalCompiler(
                self.store, self.authority
            ).compile(self.snapshot(signal))

    def test_same_snapshot_and_active_state_is_idempotent_metadata_only(self):
        candidate, row = self.active_item("deterministic")
        signal = self.signal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain="analyst",
            advisory=SIGNAL_SUPPORT,
        )
        snapshot = self.snapshot(signal)
        compiler = DeterministicCurationProposalCompiler(self.store, self.authority)
        first = compiler.compile(snapshot).to_payload()
        second = compiler.compile(snapshot).to_payload()
        self.assertEqual(first, second)
        self.assertEqual(
            first["proposal_set_sha256"],
            second["proposal_set_sha256"],
        )

        serialized = json.dumps(first, sort_keys=True)
        for forbidden in (
            candidate.content,
            candidate.title,
            candidate.scope,
            "raw_request",
            "prompt",
            "model_output",
            "password=secret",
            "/var/lib/workspace",
            "evidence:phase4i",
        ):
            self.assertNotIn(forbidden, serialized)

        for forbidden_method in (
            "promote",
            "archive",
            "rollback",
            "stage",
            "delete",
            "remediate",
            "rotate_key",
            "sign",
        ):
            self.assertFalse(hasattr(compiler, forbidden_method), forbidden_method)

    def test_signal_identity_is_bound_into_proposal(self):
        _candidate, row = self.active_item("signal-bind")
        support_signal = self.signal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain="analyst",
            advisory=SIGNAL_SUPPORT,
        )
        insufficient_signal = self.signal(
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            domain="analyst",
            advisory=SIGNAL_INSUFFICIENT,
        )
        compiler = DeterministicCurationProposalCompiler(self.store, self.authority)
        support = compiler.compile(self.snapshot(support_signal)).proposals[0]
        insufficient = compiler.compile(self.snapshot(insufficient_signal)).proposals[0]
        self.assertNotEqual(
            support.effectiveness_signal_sha256,
            insufficient.effectiveness_signal_sha256,
        )
        self.assertNotEqual(support.proposal_id, insufficient.proposal_id)
        self.assertEqual(support.interpretation, INTERPRETATION)


if __name__ == "__main__":
    unittest.main()
