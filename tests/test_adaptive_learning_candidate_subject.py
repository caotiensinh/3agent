import unittest

from three_agent.adaptive_learning_candidate_subject import (
    CandidateSkillEvaluationSubject,
    CandidateSkillEvaluationSubjectError,
)
from three_agent.adaptive_learning_contract import KnowledgeCandidate


class FakePackage:
    def __init__(self, candidate):
        self.result = "PASS"
        self.kind = "skill"
        self.candidate_id = candidate.candidate_id
        self.candidate_sha256 = candidate.sha256
        self.candidate_knowledge_sha256 = "sha256:" + "c" * 64
        self.item_id = candidate.target_item_id
        self.base_knowledge_sha256 = candidate.base_item_sha256
        self.domain = candidate.domain
        self.evaluation_sha256 = "sha256:" + "d" * 64

    def validate(self):
        return self


class CandidateSkillEvaluationSubjectTests(unittest.TestCase):
    def candidate(self):
        return KnowledgeCandidate(
            candidate_id="candidate:revision-1",
            domain="general",
            kind="skill",
            title="Evidence review procedure",
            content="Review the available evidence, preserve uncertainty, and stop for human review when evidence is incomplete.",
            scope="offline-heldout-evaluation",
            sensitivity="internal",
            risk_level="low",
            ownership="learner_managed",
            action="patch",
            execution_mode="offline",
            source_experience_ids=("experience:1",),
            source_experience_hashes=("sha256:" + "1" * 64,),
            source_domains=("general",),
            source_sensitivities=("internal",),
            source_task_ids=("task:1",),
            source_outcomes=("verified_success",),
            evidence_ref_ids=("evidence:1",),
            evidence_hashes=("sha256:" + "2" * 64,),
            target_item_id="knowledge:skill-1",
            base_item_sha256="sha256:" + "b" * 64,
            created_at="2026-09-09T00:00:00Z",
        ).validate()

    def test_exact_phase4k_pass_builds_deterministic_subject(self):
        candidate = self.candidate()
        package = FakePackage(candidate)
        first = CandidateSkillEvaluationSubject.from_revision(package, candidate)
        second = CandidateSkillEvaluationSubject.from_revision(package, candidate)
        self.assertEqual(first.subject_sha256, second.subject_sha256)
        self.assertEqual(first.candidate_sha256, candidate.sha256)
        self.assertEqual(first.base_knowledge_sha256, candidate.base_item_sha256)
        self.assertEqual(first.revision_evaluation_sha256, package.evaluation_sha256)
        self.assertGreater(first.skill_size_bytes, 0)

    def test_phase4k_fail_is_rejected(self):
        candidate = self.candidate()
        package = FakePackage(candidate)
        package.result = "FAIL"
        with self.assertRaisesRegex(
            CandidateSkillEvaluationSubjectError, "CANDIDATE_SUBJECT_PHASE4K_PASS_REQUIRED"
        ):
            CandidateSkillEvaluationSubject.from_revision(package, candidate)

    def test_candidate_sha_mismatch_is_rejected(self):
        candidate = self.candidate()
        package = FakePackage(candidate)
        package.candidate_sha256 = "sha256:" + "e" * 64
        with self.assertRaisesRegex(
            CandidateSkillEvaluationSubjectError, "CANDIDATE_SUBJECT_PHASE4K_BINDING_MISMATCH"
        ):
            CandidateSkillEvaluationSubject.from_revision(package, candidate)

    def test_item_binding_mismatch_is_rejected(self):
        candidate = self.candidate()
        package = FakePackage(candidate)
        package.item_id = "knowledge:other"
        with self.assertRaisesRegex(
            CandidateSkillEvaluationSubjectError, "CANDIDATE_SUBJECT_PHASE4K_BINDING_MISMATCH"
        ):
            CandidateSkillEvaluationSubject.from_revision(package, candidate)

    def test_base_sha_binding_mismatch_is_rejected(self):
        candidate = self.candidate()
        package = FakePackage(candidate)
        package.base_knowledge_sha256 = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
            CandidateSkillEvaluationSubjectError, "CANDIDATE_SUBJECT_PHASE4K_BINDING_MISMATCH"
        ):
            CandidateSkillEvaluationSubject.from_revision(package, candidate)

    def test_non_skill_package_is_rejected(self):
        candidate = self.candidate()
        package = FakePackage(candidate)
        package.kind = "memory"
        with self.assertRaisesRegex(
            CandidateSkillEvaluationSubjectError, "CANDIDATE_SUBJECT_SKILL_PATCH_REQUIRED"
        ):
            CandidateSkillEvaluationSubject.from_revision(package, candidate)

    def test_subject_has_no_mutation_surface(self):
        subject = CandidateSkillEvaluationSubject.from_revision(FakePackage(self.candidate()), self.candidate())
        for name in ("promote", "stage", "archive", "rollback", "materialize", "execute"):
            self.assertFalse(hasattr(subject, name))


if __name__ == "__main__":
    unittest.main()
