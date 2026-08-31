from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_evaluation import (
    AdaptiveLearningEvaluationReplay,
    LEARNING_REPLAY_SCHEMA,
    LearningEvaluationCorpus,
    LearningEvaluationError,
)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evaluation" / "adaptive_learning_offline_v1.json"
SOURCE_REF = "a" * 40


class AdaptiveLearningEvaluationTests(unittest.TestCase):
    def test_offline_corpus_is_broad_and_strict(self):
        corpus = LearningEvaluationCorpus.load(CORPUS)
        self.assertGreaterEqual(len(corpus.cases), 12)
        self.assertTrue(corpus.sha256.startswith("sha256:"))
        self.assertEqual(
            {case.domain for case in corpus.cases},
            {"network", "security", "analyst"},
        )

    def test_full_offline_replay_passes(self):
        corpus = LearningEvaluationCorpus.load(CORPUS)
        result = AdaptiveLearningEvaluationReplay.replay(corpus, source_ref=SOURCE_REF)
        self.assertEqual(result["schema_version"], LEARNING_REPLAY_SCHEMA)
        self.assertTrue(result["passed"])
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(result["passed_count"], result["case_count"])

    def test_replay_output_is_metadata_only(self):
        corpus = LearningEvaluationCorpus.load(CORPUS)
        result = AdaptiveLearningEvaluationReplay.replay(corpus, source_ref=SOURCE_REF)
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("content", encoded)
        self.assertNotIn("raw_prompt", encoded)
        self.assertNotIn("Cisco", encoded)
        for row in result["cases"]:
            self.assertEqual(set(row), {"case_id", "passed", "accepted", "reason_codes"})

    def test_wrong_expected_result_causes_replay_failure(self):
        payload = LearningEvaluationCorpus.load(CORPUS).to_payload()
        payload["cases"][0]["expected"]["accepted"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            corpus = LearningEvaluationCorpus.load(path)
            result = AdaptiveLearningEvaluationReplay.replay(corpus, source_ref=SOURCE_REF)
        self.assertFalse(result["passed"])
        self.assertEqual(result["failed_count"], 1)

    def test_unknown_case_field_is_rejected(self):
        payload = LearningEvaluationCorpus.load(CORPUS).to_payload()
        payload["cases"][0]["network_authority"] = "full"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(LearningEvaluationError):
                LearningEvaluationCorpus.load(path)

    def test_source_ref_must_be_exact_git_sha(self):
        corpus = LearningEvaluationCorpus.load(CORPUS)
        with self.assertRaises(LearningEvaluationError):
            AdaptiveLearningEvaluationReplay.replay(corpus, source_ref="main")


if __name__ == "__main__":
    unittest.main()
