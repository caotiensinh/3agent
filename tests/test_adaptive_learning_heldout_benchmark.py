from __future__ import annotations

import unittest

from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
)
from three_agent.adaptive_learning_heldout_benchmark import (
    HELDOUT_AUTHORITY,
    HELDOUT_SELECTION_POLICY,
    HeldOutBenchmarkCaseRef,
    HeldOutBenchmarkError,
    HeldOutSkillBenchmark,
    HeldOutSkillBenchmarkBinding,
)

NOW = "2026-09-09T00:00:00Z"
SOURCE_REF = "a" * 40
H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64
H4 = "sha256:" + "4" * 64


def skill_candidate(*, task_id: str = "task:train", kind: str = "skill") -> KnowledgeCandidate:
    evidence = EvidenceReference(
        ref_id="evidence:train",
        sha256=H1,
        source_type="syslog",
        source_task_id=task_id,
        sensitivity="confidential",
        collection_mode="passive",
        created_at=NOW,
        vendor_family="Cisco CBS250",
        version="3.x",
    )
    experience = ExperienceRecord(
        experience_id="experience:train",
        domain="network",
        task_id=task_id,
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified passive diagnostic procedure.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return KnowledgeCandidate.from_experiences(
        candidate_id="candidate:heldout",
        domain="network",
        kind=kind,
        title="Held-out benchmark candidate",
        content="Correlate read-only interface state with endpoint evidence and preserve uncertainty.",
        scope="offline-read-only-analysis",
        sensitivity="confidential",
        risk_level="high",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only",
        experiences=(experience,),
        created_at=NOW,
    )


def benchmark(*, first_hash: str = H2, first_task: str = "task:holdout-1") -> HeldOutSkillBenchmark:
    return HeldOutSkillBenchmark(
        benchmark_id="benchmark:network-skill-v1",
        source_ref=SOURCE_REF,
        domain="network",
        kind="skill",
        cases=(
            HeldOutBenchmarkCaseRef(
                case_id="case:001",
                case_sha256=first_hash,
                source_task_id=first_task,
                domain="network",
                kind="skill",
            ),
            HeldOutBenchmarkCaseRef(
                case_id="case:002",
                case_sha256=H3,
                source_task_id="task:holdout-2",
                domain="network",
                kind="skill",
            ),
        ),
    ).validate()


class HeldOutSkillBenchmarkTests(unittest.TestCase):
    def test_benchmark_is_content_addressed_and_metadata_only(self):
        item = benchmark()
        payload = item.to_payload()
        self.assertTrue(payload["benchmark_sha256"].startswith("sha256:"))
        self.assertEqual(payload["selection_policy"], HELDOUT_SELECTION_POLICY)
        self.assertEqual(payload["authority"], HELDOUT_AUTHORITY)
        rendered = str(payload)
        self.assertNotIn("procedure body", rendered)
        self.assertNotIn("score", payload)
        self.assertNotIn("promote", payload)

    def test_benchmark_hash_is_deterministic(self):
        self.assertEqual(benchmark().benchmark_sha256, benchmark().benchmark_sha256)

    def test_case_scope_mismatch_fails_closed(self):
        item = HeldOutSkillBenchmark(
            benchmark_id="benchmark:mismatch",
            source_ref=SOURCE_REF,
            domain="network",
            kind="skill",
            cases=(
                HeldOutBenchmarkCaseRef(
                    case_id="case:mismatch",
                    case_sha256=H2,
                    source_task_id="task:holdout",
                    domain="security",
                    kind="skill",
                ),
            ),
        )
        with self.assertRaisesRegex(HeldOutBenchmarkError, "SCOPE_MISMATCH"):
            item.validate()

    def test_duplicate_case_hash_fails_closed(self):
        item = HeldOutSkillBenchmark(
            benchmark_id="benchmark:duplicate",
            source_ref=SOURCE_REF,
            domain="network",
            kind="skill",
            cases=(
                HeldOutBenchmarkCaseRef("case:001", H2, "task:holdout-1", "network", "skill"),
                HeldOutBenchmarkCaseRef("case:002", H2, "task:holdout-2", "network", "skill"),
            ),
        )
        with self.assertRaisesRegex(HeldOutBenchmarkError, "CASE_SHA_DUPLICATE"):
            item.validate()

    def test_exact_candidate_binding_is_deterministic(self):
        candidate = skill_candidate()
        item = benchmark()
        left = HeldOutSkillBenchmarkBinding.bind(item, candidate)
        right = HeldOutSkillBenchmarkBinding.bind(item, candidate)
        self.assertEqual(left.binding_sha256, right.binding_sha256)
        self.assertEqual(left.candidate_sha256, candidate.sha256)
        self.assertEqual(left.benchmark_sha256, item.benchmark_sha256)
        self.assertEqual(left.source_overlap_count, 0)

    def test_training_task_overlap_is_rejected(self):
        candidate = skill_candidate(task_id="task:holdout-1")
        with self.assertRaisesRegex(HeldOutBenchmarkError, "HELDOUT_SOURCE_OVERLAP"):
            HeldOutSkillBenchmarkBinding.bind(benchmark(), candidate)

    def test_candidate_evidence_hash_overlap_is_rejected(self):
        candidate = skill_candidate()
        with self.assertRaisesRegex(HeldOutBenchmarkError, "HELDOUT_SOURCE_OVERLAP"):
            HeldOutSkillBenchmarkBinding.bind(benchmark(first_hash=H1), candidate)

    def test_forged_nonzero_overlap_binding_is_rejected(self):
        bound = HeldOutSkillBenchmarkBinding.bind(benchmark(), skill_candidate())
        forged = HeldOutSkillBenchmarkBinding(
            **{
                **bound.__dict__,
                "source_overlap_count": 1,
            }
        )
        with self.assertRaisesRegex(HeldOutBenchmarkError, "OVERLAP_INVALID"):
            forged.validate()

    def test_invalid_source_ref_is_rejected(self):
        item = HeldOutSkillBenchmark(
            benchmark_id="benchmark:bad-source",
            source_ref="main",
            domain="network",
            kind="skill",
            cases=(
                HeldOutBenchmarkCaseRef("case:001", H2, "task:holdout", "network", "skill"),
            ),
        )
        with self.assertRaisesRegex(HeldOutBenchmarkError, "SOURCE_REF_INVALID"):
            item.validate()

    def test_binding_projection_contains_no_candidate_body_or_runtime_authority(self):
        candidate = skill_candidate()
        payload = HeldOutSkillBenchmarkBinding.bind(benchmark(), candidate).to_payload()
        rendered = str(payload)
        self.assertNotIn(candidate.content, rendered)
        for forbidden in ("stage", "promote", "archive", "rollback", "materialize", "execute"):
            self.assertNotIn(forbidden, payload)
        self.assertEqual(payload["authority"], HELDOUT_AUTHORITY)

    def test_empty_benchmark_is_rejected(self):
        item = HeldOutSkillBenchmark(
            benchmark_id="benchmark:empty",
            source_ref=SOURCE_REF,
            domain="network",
            kind="skill",
            cases=(),
        )
        with self.assertRaisesRegex(HeldOutBenchmarkError, "CASE_COUNT_INVALID"):
            item.validate()

    def test_duplicate_heldout_task_identity_is_rejected(self):
        item = HeldOutSkillBenchmark(
            benchmark_id="benchmark:duplicate-task",
            source_ref=SOURCE_REF,
            domain="network",
            kind="skill",
            cases=(
                HeldOutBenchmarkCaseRef("case:001", H2, "task:same", "network", "skill"),
                HeldOutBenchmarkCaseRef("case:002", H3, "task:same", "network", "skill"),
            ),
        )
        with self.assertRaisesRegex(HeldOutBenchmarkError, "TASK_ID_DUPLICATE"):
            item.validate()


if __name__ == "__main__":
    unittest.main()
