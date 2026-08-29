import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.evaluation_lab import EvaluationCorpus, EvaluationReplay
from three_agent.metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID
from three_agent.promotion_gate import (
    PROMOTION_CLASSES,
    PROMOTION_EVIDENCE_SCHEMA,
    PromotionEvidence,
    PromotionGateError,
    PromotionPipeline,
    PromotionPolicy,
    build_repository_replay_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "evaluation" / "promotion_policy_v1.json"
GOLDEN = ROOT / "evaluation" / "golden_control_plane_v1.json"
REGRESSION = ROOT / "evaluation" / "regression_control_plane_v1.json"
ADVERSARIAL = ROOT / "evaluation" / "adversarial_security_v1.json"
BASELINE = "a" * 40
CANDIDATE = "b" * 40


def replay(path: Path, source_ref: str) -> dict:
    corpus = EvaluationCorpus.load(path)
    return EvaluationReplay().replay(corpus, source_ref=source_ref)


def repository_evidence() -> list[PromotionEvidence]:
    rows = []
    for path, evidence_id in (
        (GOLDEN, "golden-replay-evidence"),
        (REGRESSION, "regression-replay-evidence"),
        (ADVERSARIAL, "adversarial-replay-evidence"),
    ):
        rows.append(
            build_repository_replay_evidence(
                replay(path, BASELINE),
                replay(path, CANDIDATE),
                evidence_id=evidence_id,
            )
        )
    return rows


def external_evidence(spec) -> PromotionEvidence:
    digest = "sha256:" + hashlib.sha256(spec.class_id.encode("utf-8")).hexdigest()
    commitment = None
    if spec.holdout_commitment_required:
        commitment = "sha256:" + hashlib.sha256(
            (spec.class_id + ":labels").encode("utf-8")
        ).hexdigest()
    payload = {
        "schema_version": PROMOTION_EVIDENCE_SCHEMA,
        "evidence_id": f"{spec.class_id}-evidence",
        "corpus_class": spec.class_id,
        "corpus_id": f"{spec.class_id}-v1",
        "corpus_sha256": digest,
        "metric_registry_id": METRIC_REGISTRY_ID,
        "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
        "baseline_ref": BASELINE,
        "candidate_ref": CANDIDATE,
        "checks": {check: True for check in spec.required_checks},
        "security_passed": True,
        "evidence_refs": [f"evidence:{spec.class_id}:v1"],
        "label_commitment_sha256": commitment,
        "evaluator_attested": spec.evaluator_attestation_required,
    }
    return PromotionEvidence.from_payload(payload)


def complete_evidence(policy: PromotionPolicy) -> list[PromotionEvidence]:
    rows = repository_evidence()
    specs = policy.by_id()
    for class_id in ("replay", "edge_large_context", "efficiency_cache_concurrency"):
        rows.append(external_evidence(specs[class_id]))
    return rows


class PromotionGateTests(unittest.TestCase):
    def test_policy_requires_all_six_promotion_classes_and_current_metric_registry(self):
        policy = PromotionPolicy.load(POLICY)
        self.assertEqual(tuple(item.class_id for item in policy.classes), PROMOTION_CLASSES)
        self.assertEqual(policy.metric_registry_id, METRIC_REGISTRY_ID)
        self.assertTrue(policy.sha256.startswith("sha256:"))
        self.assertEqual(len(policy.classes), 6)

    def test_repository_replay_evidence_is_metadata_only_and_lineage_bound(self):
        evidence = repository_evidence()
        self.assertEqual({item.corpus_class for item in evidence}, {
            "golden", "regression", "adversarial_security"
        })
        for item in evidence:
            payload = item.to_payload()
            raw = json.dumps(payload, ensure_ascii=False)
            self.assertEqual(item.baseline_ref, BASELINE)
            self.assertEqual(item.candidate_ref, CANDIDATE)
            self.assertEqual(item.metric_registry_sha256, DEFAULT_METRIC_REGISTRY.sha256)
            self.assertNotIn("cases", payload)
            self.assertNotIn("actual", payload)
            self.assertNotIn("raw_prompt", payload)
            self.assertNotIn("repo:workspace", raw)
            self.assertTrue(all(ref.startswith("sha256:") for ref in item.evidence_refs))

    def test_missing_external_classes_fail_closed_without_waiver(self):
        policy = PromotionPolicy.load(POLICY)
        receipt = PromotionPipeline.evaluate(
            policy,
            repository_evidence(),
            repo_root=ROOT,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(receipt["accepted"])
        self.assertIn("replay:EVIDENCE_MISSING", receipt["failures"])
        self.assertIn("edge_large_context:EVIDENCE_MISSING", receipt["failures"])
        self.assertIn("efficiency_cache_concurrency:EVIDENCE_MISSING", receipt["failures"])
        self.assertFalse(receipt["security"]["waiver_path_available"])

    def test_complete_synthetic_evidence_accepts_only_when_all_gates_pass(self):
        policy = PromotionPolicy.load(POLICY)
        receipt = PromotionPipeline.evaluate(
            policy,
            complete_evidence(policy),
            repo_root=ROOT,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertTrue(receipt["accepted"])
        self.assertEqual(receipt["failures"], [])
        self.assertTrue(receipt["receipt_sha256"].startswith("sha256:"))
        self.assertTrue(all(row["passed"] for row in receipt["classes"].values()))

    def test_repository_corpus_hash_mismatch_blocks_promotion(self):
        policy = PromotionPolicy.load(POLICY)
        rows = complete_evidence(policy)
        golden_index = next(i for i, row in enumerate(rows) if row.corpus_class == "golden")
        rows[golden_index] = replace(rows[golden_index], corpus_sha256="sha256:" + "0" * 64)
        receipt = PromotionPipeline.evaluate(
            policy,
            rows,
            repo_root=ROOT,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(receipt["accepted"])
        self.assertIn(
            "golden:REPOSITORY_CORPUS_LINEAGE_MISMATCH",
            receipt["failures"],
        )

    def test_holdout_missing_commitment_or_attestation_blocks_promotion(self):
        policy = PromotionPolicy.load(POLICY)
        rows = complete_evidence(policy)
        replay_index = next(i for i, row in enumerate(rows) if row.corpus_class == "replay")
        rows[replay_index] = replace(
            rows[replay_index],
            label_commitment_sha256=None,
            evaluator_attested=False,
        )
        receipt = PromotionPipeline.evaluate(
            policy,
            rows,
            repo_root=ROOT,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(receipt["accepted"])
        self.assertIn("replay:HOLDOUT_LABEL_COMMITMENT_MISSING", receipt["failures"])
        self.assertIn("replay:EVALUATOR_ATTESTATION_MISSING", receipt["failures"])

    def test_metric_registry_mismatch_is_rejected_before_promotion(self):
        policy = PromotionPolicy.load(POLICY)
        spec = policy.by_id()["replay"]
        item = external_evidence(spec)
        payload = item.to_payload()
        payload["metric_registry_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(PromotionGateError, "fingerprint mismatch"):
            PromotionEvidence.from_payload(payload)

    def test_unexpected_raw_content_field_is_rejected(self):
        policy = PromotionPolicy.load(POLICY)
        payload = external_evidence(policy.by_id()["replay"]).to_payload()
        payload["raw_prompt"] = "CONFIDENTIAL BUSINESS TEXT"
        with self.assertRaisesRegex(PromotionGateError, "metadata-only"):
            PromotionEvidence.from_payload(payload)

    def test_rollback_must_equal_evaluated_baseline(self):
        policy = PromotionPolicy.load(POLICY)
        with self.assertRaisesRegex(PromotionGateError, "rollback_ref"):
            PromotionPipeline.evaluate(
                policy,
                complete_evidence(policy),
                repo_root=ROOT,
                baseline_ref=BASELINE,
                candidate_ref=CANDIDATE,
                rollback_ref="c" * 40,
            )

    def test_duplicate_class_evidence_cannot_manufacture_pass(self):
        policy = PromotionPolicy.load(POLICY)
        rows = complete_evidence(policy)
        rows.append(rows[0])
        receipt = PromotionPipeline.evaluate(
            policy,
            rows,
            repo_root=ROOT,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(receipt["accepted"])
        self.assertIn("DUPLICATE_EVIDENCE:golden", receipt["failures"])


if __name__ == "__main__":
    unittest.main()
