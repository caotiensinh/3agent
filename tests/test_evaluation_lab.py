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
REGRESSION = ROOT / "evaluation" / "regression_control_plane_v1.json"
ADVERSARIAL = ROOT / "evaluation" / "adversarial_security_v1.json"
SOURCE_REF = "a" * 40


class EvaluationLabTests(unittest.TestCase):
    def test_repository_golden_corpus_replays_cleanly(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        self.assertTrue(report["passed"])
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["passed_count"], report["case_count"])
        self.assertEqual(report["corpus_id"], "workspace-control-plane-golden-v1")
        self.assertEqual(report["corpus_class"], "golden")
        self.assertTrue(report["corpus_sha256"].startswith("sha256:"))

    def test_legacy_golden_payload_shape_and_hash_input_remain_unchanged(self):
        raw = json.loads(GOLDEN.read_text(encoding="utf-8"))
        corpus = EvaluationCorpus.load(GOLDEN)
        self.assertIsNone(corpus.declared_corpus_class)
        self.assertEqual(corpus.corpus_class, "golden")
        self.assertEqual(corpus.to_payload(), raw)
        self.assertNotIn("corpus_class", corpus.to_payload())

    def test_repository_regression_corpus_replays_security_metadata_cleanly(self):
        corpus = EvaluationCorpus.load(REGRESSION)
        report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        self.assertTrue(report["passed"])
        self.assertEqual(report["corpus_class"], "regression")
        by_id = {item["case_id"]: item for item in report["cases"]}
        secret = by_id["secret-analysis-deny-egress-cache-and-raw-logs"]["actual"]
        self.assertEqual(secret["network_scope"], "deny")
        self.assertEqual(secret["cache_mode"], "deny")
        self.assertEqual(secret["logging_raw_prompt"], "deny")
        self.assertEqual(secret["logging_raw_tool_output"], "deny")
        self.assertTrue(secret["model_trusted_local_only"])
        self.assertEqual(secret["max_steps"], 8)
        self.assertEqual(secret["max_tool_calls"], 12)
        self.assertEqual(secret["max_wall_time_ms"], 600000)
        code_fix = by_id["internal-code-fix-write-scope-and-tools"]["actual"]
        self.assertEqual(code_fix["allowed_sources"], ["repo:workspace"])
        self.assertEqual(code_fix["write_scope"], ["repo:staging"])
        self.assertEqual(code_fix["max_steps"], 6)
        self.assertEqual(code_fix["max_tool_calls"], 10)
        self.assertEqual(code_fix["max_wall_time_ms"], 300000)

    def test_repository_adversarial_corpus_tracks_sanitized_restricted_egress_boundary(self):
        corpus = EvaluationCorpus.load(ADVERSARIAL)
        report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        self.assertTrue(report["passed"])
        self.assertEqual(report["corpus_class"], "adversarial_security")
        self.assertGreaterEqual(report["case_count"], 8)

        cases_by_id = {case.case_id: case for case in corpus.cases}
        results_by_id = {item["case_id"]: item for item in report["cases"]}
        restricted = results_by_id["reject-restricted-public-web"]
        self.assertTrue(restricted["actual"]["accepted"])
        self.assertEqual(restricted["actual"]["network_scope"], "allowlisted_egress")
        self.assertIn("web_gateway", restricted["actual"]["allowed_tools"])

        rejected = [
            case
            for case in corpus.cases
            if case.case_id != "reject-restricted-public-web"
        ]
        self.assertTrue(all(case.expected == {"accepted": False} for case in rejected))
        self.assertTrue(
            all(results_by_id[case.case_id]["actual"] == {"accepted": False} for case in rejected)
        )
        self.assertEqual(cases_by_id["reject-restricted-public-web"].expected["accepted"], True)

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

    def test_tampered_regression_security_boundary_fails_replay(self):
        payload = json.loads(REGRESSION.read_text(encoding="utf-8"))
        payload["cases"][1]["expected"]["cache_mode"] = "prefix_allowed"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered-regression.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            corpus = EvaluationCorpus.load(path)
            report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        failed = [item for item in report["cases"] if not item["passed"]]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["mismatch_keys"], ["cache_mode"])

    def test_tampered_complete_execution_budget_fails_regression_replay(self):
        payload = json.loads(REGRESSION.read_text(encoding="utf-8"))
        expected = payload["cases"][2]["expected"]
        expected["max_steps"] += 1
        expected["max_tool_calls"] += 1
        expected["max_wall_time_ms"] += 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered-budget.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            corpus = EvaluationCorpus.load(path)
            report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        failed = [item for item in report["cases"] if not item["passed"]]
        self.assertEqual(len(failed), 1)
        self.assertEqual(
            failed[0]["mismatch_keys"],
            ["max_steps", "max_tool_calls", "max_wall_time_ms"],
        )

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

    def test_unknown_corpus_class_is_rejected(self):
        payload = {
            "schema_version": CORPUS_SCHEMA,
            "corpus_id": "bad-class-test",
            "corpus_class": "optimizer_private_labels",
            "cases": [
                {
                    "case_id": "one",
                    "inputs": {"task_type": "general"},
                    "expected": {"accepted": True},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad-class.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(EvaluationCorpusError, "corpus_class"):
                EvaluationCorpus.load(path)

    def test_golden_policy_outcomes_track_sanitized_egress_and_no_llm_rejection(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        by_id = {case.case_id: case for case in corpus.cases}

        rejected = [case for case in corpus.cases if case.expected == {"accepted": False}]
        self.assertEqual({case.case_id for case in rejected}, {"reject-no-llm-extra-tool"})
        result = EvaluationReplay().replay_case(rejected[0])
        self.assertTrue(result["passed"])
        self.assertEqual(result["actual"], {"accepted": False})

        confidential_web = EvaluationReplay().replay_case(by_id["reject-confidential-public-web"])
        self.assertTrue(confidential_web["passed"])
        self.assertTrue(confidential_web["actual"]["accepted"])
        self.assertEqual(confidential_web["actual"]["network_scope"], "allowlisted_egress")
        self.assertIn("web_gateway", confidential_web["actual"]["allowed_tools"])


if __name__ == "__main__":
    unittest.main()
