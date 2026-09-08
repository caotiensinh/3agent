from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
)
from three_agent.adaptive_learning_evidence_diversity import (
    EVIDENCE_DIVERSITY_AUTHORITY,
    INDEPENDENCE_SEMANTICS,
    DeterministicEvidenceDiversityEvaluator,
    EvidenceDiversityError,
    EvidenceDiversityPolicy,
)

NOW = "2026-09-09T00:00:00Z"


def sha(char: str) -> str:
    return "sha256:" + char * 64


def experience(
    suffix: str,
    *,
    task_id: str,
    source_type: str = "syslog",
    collection_mode: str = "passive",
    evidence_hash: str | None = None,
) -> ExperienceRecord:
    ref = EvidenceReference(
        ref_id=f"evidence:{suffix}",
        sha256=evidence_hash or sha(suffix[0]),
        source_type=source_type,
        source_task_id=task_id,
        sensitivity="confidential",
        collection_mode=collection_mode,
        created_at=NOW,
        vendor_family="Cisco CBS250",
        version="3.x",
    )
    return ExperienceRecord(
        experience_id=f"experience:{suffix}",
        domain="network",
        task_id=task_id,
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified read-only diagnostic evidence.",
        evidence=(ref,),
        created_at=NOW,
    ).validate()


def candidate(experiences: tuple[ExperienceRecord, ...]) -> KnowledgeCandidate:
    return KnowledgeCandidate.from_experiences(
        candidate_id="candidate:diversity",
        domain="network",
        kind="skill",
        title="Evidence-diverse read-only procedure",
        content="Correlate read-only observations and preserve uncertainty before conclusion.",
        scope="offline-read-only-analysis",
        sensitivity="confidential",
        risk_level="high",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only",
        experiences=experiences,
        created_at=NOW,
    )


class EvidenceDiversityPolicyTests(unittest.TestCase):
    def test_validated_profile_accepts_one_verified_source_task(self):
        source = (experience("1", task_id="task:one"),)
        result = DeterministicEvidenceDiversityEvaluator.evaluate(
            candidate(source), source, EvidenceDiversityPolicy.for_profile("validated")
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.independent_task_count, 1)
        self.assertEqual(result.reason_codes, ())

    def test_approved_profile_requires_two_independent_tasks(self):
        first = experience("1", task_id="task:same", evidence_hash=sha("1"))
        second = experience("2", task_id="task:same", evidence_hash=sha("2"))
        source = (first, second)
        result = DeterministicEvidenceDiversityEvaluator.evaluate(
            candidate(source), source, EvidenceDiversityPolicy.for_profile("approved")
        )
        self.assertFalse(result.passed)
        self.assertIn("INSUFFICIENT_INDEPENDENT_TASKS", result.reason_codes)
        self.assertEqual(result.independent_task_count, 1)
        self.assertEqual(result.unique_evidence_hash_count, 2)

    def test_approved_profile_accepts_two_independent_real_tasks(self):
        source = (
            experience("1", task_id="task:one", evidence_hash=sha("1")),
            experience("2", task_id="task:two", evidence_hash=sha("2")),
        )
        result = DeterministicEvidenceDiversityEvaluator.evaluate(
            candidate(source), source, EvidenceDiversityPolicy.for_profile("approved")
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.non_synthetic_task_count, 2)

    def test_enterprise_profile_requires_source_type_diversity(self):
        source = (
            experience("1", task_id="task:one", source_type="syslog", evidence_hash=sha("1")),
            experience("2", task_id="task:two", source_type="syslog", evidence_hash=sha("2")),
            experience("3", task_id="task:three", source_type="syslog", evidence_hash=sha("3")),
        )
        result = DeterministicEvidenceDiversityEvaluator.evaluate(
            candidate(source), source, EvidenceDiversityPolicy.for_profile("enterprise")
        )
        self.assertFalse(result.passed)
        self.assertIn("INSUFFICIENT_SOURCE_TYPE_DIVERSITY", result.reason_codes)

    def test_enterprise_profile_accepts_three_tasks_two_source_types(self):
        source = (
            experience("1", task_id="task:one", source_type="syslog", evidence_hash=sha("1")),
            experience("2", task_id="task:two", source_type="device_snapshot", evidence_hash=sha("2")),
            experience("3", task_id="task:three", source_type="syslog", evidence_hash=sha("3")),
        )
        result = DeterministicEvidenceDiversityEvaluator.evaluate(
            candidate(source), source, EvidenceDiversityPolicy.for_profile("enterprise")
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.unique_source_type_count, 2)
        self.assertEqual(result.independent_task_count, 3)

    def test_synthetic_only_evidence_cannot_satisfy_approved_profile(self):
        source = (
            experience(
                "1",
                task_id="task:synthetic-one",
                source_type="synthetic_fixture",
                collection_mode="synthetic",
                evidence_hash=sha("1"),
            ),
            experience(
                "2",
                task_id="task:synthetic-two",
                source_type="synthetic_fixture",
                collection_mode="synthetic",
                evidence_hash=sha("2"),
            ),
        )
        result = DeterministicEvidenceDiversityEvaluator.evaluate(
            candidate(source), source, EvidenceDiversityPolicy.for_profile("approved")
        )
        self.assertFalse(result.passed)
        self.assertIn("SYNTHETIC_ONLY_EVIDENCE", result.reason_codes)
        self.assertIn("INSUFFICIENT_NON_SYNTHETIC_TASKS", result.reason_codes)

    def test_mixed_synthetic_and_real_sources_remain_counted_explicitly(self):
        source = (
            experience("1", task_id="task:real", evidence_hash=sha("1")),
            experience(
                "2",
                task_id="task:synthetic",
                source_type="synthetic_fixture",
                collection_mode="synthetic",
                evidence_hash=sha("2"),
            ),
        )
        result = DeterministicEvidenceDiversityEvaluator.evaluate(
            candidate(source), source, EvidenceDiversityPolicy.for_profile("approved")
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.synthetic_task_count, 1)
        self.assertEqual(result.non_synthetic_task_count, 1)

    def test_custom_threshold_fails_when_unique_evidence_is_below_minimum(self):
        source = (
            experience("1", task_id="task:one", evidence_hash=sha("1")),
            experience("2", task_id="task:two", evidence_hash=sha("2")),
        )
        policy = EvidenceDiversityPolicy(
            profile="approved",
            min_independent_tasks=2,
            min_unique_evidence_hashes=3,
            min_source_types=1,
            min_collection_modes=1,
            min_non_synthetic_tasks=1,
        ).validate()
        result = DeterministicEvidenceDiversityEvaluator.evaluate(candidate(source), source, policy)
        self.assertFalse(result.passed)
        self.assertIn("INSUFFICIENT_UNIQUE_EVIDENCE", result.reason_codes)

    def test_candidate_experience_lineage_mismatch_fails_closed(self):
        source = (experience("1", task_id="task:one"),)
        item = candidate(source)
        forged = replace(item, source_experience_ids=("experience:forged",))
        forged.validate()
        with self.assertRaisesRegex(EvidenceDiversityError, "EXPERIENCE_ID_LINEAGE_MISMATCH"):
            DeterministicEvidenceDiversityEvaluator.evaluate(
                forged, source, EvidenceDiversityPolicy.for_profile("validated")
            )

    def test_candidate_task_lineage_mismatch_fails_closed(self):
        source = (experience("1", task_id="task:one"),)
        item = candidate(source)
        forged = replace(item, source_task_ids=("task:forged",))
        forged.validate()
        with self.assertRaisesRegex(EvidenceDiversityError, "SOURCE_TASK_LINEAGE_MISMATCH"):
            DeterministicEvidenceDiversityEvaluator.evaluate(
                forged, source, EvidenceDiversityPolicy.for_profile("validated")
            )

    def test_assessment_is_deterministic_metadata_only_and_runtime_inert(self):
        source = (
            experience("1", task_id="task:one", evidence_hash=sha("1")),
            experience("2", task_id="task:two", evidence_hash=sha("2")),
        )
        item = candidate(source)
        policy = EvidenceDiversityPolicy.for_profile("approved")
        left = DeterministicEvidenceDiversityEvaluator.evaluate(item, source, policy)
        right = DeterministicEvidenceDiversityEvaluator.evaluate(item, source, policy)
        self.assertEqual(left.assessment_sha256, right.assessment_sha256)
        payload = left.to_payload()
        self.assertEqual(payload["authority"], EVIDENCE_DIVERSITY_AUTHORITY)
        self.assertEqual(payload["independence_semantics"], INDEPENDENCE_SEMANTICS)
        rendered = str(payload)
        self.assertNotIn(item.content, rendered)
        self.assertNotIn("summary", payload)
        for forbidden in ("stage", "promote", "archive", "rollback", "materialize", "execute"):
            self.assertNotIn(forbidden, payload)

    def test_invalid_policy_threshold_is_rejected(self):
        policy = EvidenceDiversityPolicy(
            profile="approved",
            min_independent_tasks=1,
            min_unique_evidence_hashes=1,
            min_source_types=1,
            min_collection_modes=1,
            min_non_synthetic_tasks=2,
        )
        with self.assertRaisesRegex(EvidenceDiversityError, "NON_SYNTHETIC_THRESHOLD_INVALID"):
            policy.validate()


if __name__ == "__main__":
    unittest.main()
