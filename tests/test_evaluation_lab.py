import json
import tempfile
import unittest
from pathlib import Path

from three_agent.evaluation_lab import (
    CORPUS_SCHEMA,
    EvaluationCorpus,
    EvaluationCorpusError,
    EvaluationReplay,
)


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "evaluation" / "golden_control_plane_v1.json"
SOURCE_REF = "a" * 40


class EvaluationLabTests(unittest.TestCase):
    def test_repository_golden_corpus_replays_cleanly(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        self.assertTrue(report["passed"])
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["passed_count"], report["case_count"])
        self.assertEqual(report["corpus_id"], "workspace-control-plane-golden-v1")
        self.assertTrue(report["corpus_sha256"].startswith("sha256:"))

    def test_corpus_hash_is_stable_for_same_semantics(self):
        first = EvaluationCorpus.load(GOLDEN)
        second = EvaluationCorpus.load(GOLDEN)
        self.assertEqual(first.sha256, second.sha256)

    def test_tampered_golden_expectation_fails_replay(self):
        payload = json.loads(GOLDEN.read_text(encoding="utf-8"))
        payload["cases"][0]["expected"]["network_scope"] = "deny"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            corpus = EvaluationCorpus.load(path)
            report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        self.assertFalse(report["passed"])
        failed = [item for item in report["cases"] if not item["passed"]]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["case_id"], "internal-general-small-first")
        self.assertEqual(failed[0]["mismatch_keys"], ["network_scope"])

    def test_invalid_source_ref_fails_closed(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        with self.assertRaisesRegex(EvaluationCorpusError, "40-hex"):
            EvaluationReplay().replay(corpus, source_ref="main")

    def test_duplicate_case_ids_are_rejected(self):
        payload = {
            "schema_version": CORPUS_SCHEMA,
            "corpus_id": "duplicate-test",
            "cases": [
                {
                    "case_id": "same",
                    "inputs": {"task_type": "general"},
                    "expected": {"accepted": True},
                },
                {
                    "case_id": "same",
                    "inputs": {"task_type": "general"},
                    "expected": {"accepted": True},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(EvaluationCorpusError, "unique"):
                EvaluationCorpus.load(path)

    def test_unknown_expected_fields_are_rejected(self):
        payload = {
            "schema_version": CORPUS_SCHEMA,
            "corpus_id": "unknown-field-test",
            "cases": [
                {
                    "case_id": "one",
                    "inputs": {"task_type": "general"},
                    "expected": {"accepted": True, "raw_secret": "must-not-exist"},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unknown.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(EvaluationCorpusError, "unsupported expected"):
                EvaluationCorpus.load(path)

    def test_rejected_policy_cases_are_golden_outcomes_not_errors(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        rejected = [case for case in corpus.cases if case.expected == {"accepted": False}]
        self.assertGreaterEqual(len(rejected), 2)
        replay = EvaluationReplay()
        for case in rejected:
            result = replay.replay_case(case)
            self.assertTrue(result["passed"])
            self.assertEqual(result["actual"], {"accepted": False})


if __name__ == "__main__":
    unittest.main()
