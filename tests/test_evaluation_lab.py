import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.evaluation_lab import (
    CORPUS_CLASSES,
    EVIDENCE_SCHEMA,
    EvaluationCorpus,
    EvaluationEvidence,
    EvaluationLabError,
    PromotionPipeline,
    metric_definitions_sha256,
)


BASELINE = "a" * 40
CANDIDATE = "b" * 40
OTHER = "c" * 40


class EvaluationLabTests(unittest.TestCase):
    @staticmethod
    def _corpus_path() -> Path:
        return Path(__file__).resolve().parents[1] / "evaluation" / "corpus_manifest_v1.json"

    def _corpus(self) -> EvaluationCorpus:
        return EvaluationCorpus.load(self._corpus_path())

    def _evidence(self, corpus: EvaluationCorpus, class_id: str) -> EvaluationEvidence:
        spec = corpus.by_id()[class_id]
        return EvaluationEvidence(
            evidence_id=f"evidence-{class_id.replace('_', '-')}",
            corpus_id=corpus.corpus_id,
            corpus_sha256=corpus.sha256,
            corpus_class=class_id,
            metric_schema_version=corpus.metric_schema_version,
            metric_definitions_sha256=metric_definitions_sha256(),
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            checks={check: True for check in spec.required_checks},
            security_passed=True,
            evidence_refs=("sha256:" + ("1" * 64),),
            label_commitment_sha256=(
                "sha256:" + ("2" * 64)
                if spec.label_policy == "external_holdout_required"
                else None
            ),
            holdout_evaluator=spec.label_policy == "external_holdout_required",
        )

    def test_versioned_corpus_declares_all_required_classes(self):
        corpus = self._corpus()
        self.assertEqual(tuple(item.class_id for item in corpus.classes), CORPUS_CLASSES)
        self.assertTrue(corpus.sha256.startswith("sha256:"))
        self.assertEqual(corpus.metric_schema_version, "workspace-evaluation-metrics/v1")
        self.assertTrue(all(item.required_for_promotion for item in corpus.classes))

    def test_optimizer_view_exposes_no_holdout_labels_or_commitments(self):
        corpus = self._corpus()
        view = corpus.optimizer_view()
        raw = json.dumps(view, ensure_ascii=False)
        self.assertNotIn("label_commitment_sha256", raw)
        self.assertNotIn("required_checks", raw)
        for item in view["classes"].values():
            self.assertFalse(item["holdout_labels_available_to_optimizer"])

    def test_all_six_class_receipts_are_required_for_promotion(self):
        corpus = self._corpus()
        evidence = [self._evidence(corpus, class_id) for class_id in CORPUS_CLASSES]
        accepted = PromotionPipeline.evaluate(
            corpus,
            evidence,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["rollback_ref"], BASELINE)
        self.assertTrue(accepted["receipt_sha256"].startswith("sha256:"))

        missing_replay = PromotionPipeline.evaluate(
            corpus,
            [row for row in evidence if row.corpus_class != "replay"],
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(missing_replay["accepted"])
        self.assertIn("replay:EVIDENCE_MISSING", missing_replay["failures"])

    def test_quality_or_security_regression_fails_closed(self):
        corpus = self._corpus()
        evidence = [self._evidence(corpus, class_id) for class_id in CORPUS_CLASSES]
        golden = next(row for row in evidence if row.corpus_class == "golden")
        bad_checks = dict(golden.checks)
        bad_checks["VERIFIED_TASK_SUCCESS_NON_DECREASE"] = False
        evidence[evidence.index(golden)] = replace(golden, checks=bad_checks)
        report = PromotionPipeline.evaluate(
            corpus,
            evidence,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(report["accepted"])
        self.assertIn(
            "golden:QUALITY_REGRESSION:VERIFIED_TASK_SUCCESS_NON_DECREASE",
            report["failures"],
        )

        clean = [self._evidence(corpus, class_id) for class_id in CORPUS_CLASSES]
        adversarial = next(
            row for row in clean if row.corpus_class == "adversarial_security"
        )
        clean[clean.index(adversarial)] = replace(adversarial, security_passed=False)
        report = PromotionPipeline.evaluate(
            corpus,
            clean,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(report["accepted"])
        self.assertIn(
            "adversarial_security:SECURITY_GATE_FAILED",
            report["failures"],
        )

    def test_holdout_class_requires_external_commitment_and_evaluator_attestation(self):
        corpus = self._corpus()
        evidence = [self._evidence(corpus, class_id) for class_id in CORPUS_CLASSES]
        replay = next(row for row in evidence if row.corpus_class == "replay")
        evidence[evidence.index(replay)] = replace(
            replay,
            label_commitment_sha256=None,
            holdout_evaluator=False,
        )
        report = PromotionPipeline.evaluate(
            corpus,
            evidence,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        self.assertFalse(report["accepted"])
        self.assertIn(
            "replay:HOLDOUT_LABEL_COMMITMENT_MISSING",
            report["failures"],
        )
        self.assertIn(
            "replay:HOLDOUT_EVALUATOR_NOT_ATTESTED",
            report["failures"],
        )

    def test_rollback_must_equal_evaluated_baseline(self):
        corpus = self._corpus()
        evidence = [self._evidence(corpus, class_id) for class_id in CORPUS_CLASSES]
        with self.assertRaisesRegex(EvaluationLabError, "rollback_ref"):
            PromotionPipeline.evaluate(
                corpus,
                evidence,
                baseline_ref=BASELINE,
                candidate_ref=CANDIDATE,
                rollback_ref=OTHER,
            )

    def test_evidence_parser_rejects_raw_content_refs_and_wrong_metric_lineage(self):
        corpus = self._corpus()
        spec = corpus.by_id()["regression"]
        payload = {
            "schema_version": EVIDENCE_SCHEMA,
            "evidence_id": "bad-evidence",
            "corpus_id": corpus.corpus_id,
            "corpus_sha256": corpus.sha256,
            "corpus_class": "regression",
            "metric_schema_version": corpus.metric_schema_version,
            "metric_definitions_sha256": metric_definitions_sha256(),
            "baseline_ref": BASELINE,
            "candidate_ref": CANDIDATE,
            "checks": {check: True for check in spec.required_checks},
            "security_passed": True,
            "evidence_refs": ["PRIVATE SECRET EVIDENCE BODY"],
            "label_commitment_sha256": None,
            "holdout_evaluator": False,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(EvaluationLabError, "compact IDs"):
                EvaluationEvidence.load(path)

            payload["evidence_refs"] = ["sha256:" + ("3" * 64)]
            payload["metric_definitions_sha256"] = "sha256:" + ("4" * 64)
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(EvaluationLabError, "fingerprint mismatch"):
                EvaluationEvidence.load(path)

    def test_promotion_receipt_is_metadata_only(self):
        corpus = self._corpus()
        evidence = [self._evidence(corpus, class_id) for class_id in CORPUS_CLASSES]
        report = PromotionPipeline.evaluate(
            corpus,
            evidence,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            rollback_ref=BASELINE,
        )
        raw = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("request", raw.casefold())
        self.assertNotIn("prompt", raw.casefold())
        self.assertNotIn("evidence body", raw.casefold())
        self.assertNotIn("label_value", raw)


if __name__ == "__main__":
    unittest.main()
