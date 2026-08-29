import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.evaluation_profiles import (
    EvaluationProfile,
    EvaluationProfileError,
    EvaluationProfileResult,
    PROFILE_RESULT_SCHEMA,
    build_profile_promotion_evidence,
)
from three_agent.external_evaluator_handoff import (
    EDGE_LARGE_CONTEXT_PROFILE_ID,
    EXTERNAL_EVALUATOR_HANDOFF_SCHEMA,
    ExternalEvaluatorHandoff,
    build_external_evaluator_handoff,
    validate_external_result_against_handoff,
)
from three_agent.metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID


ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "evaluation" / "edge_large_context_profile_v1.json"
BASELINE = "a" * 40
CANDIDATE = "b" * 40


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def result_payload(profile: EvaluationProfile) -> dict:
    return {
        "schema_version": PROFILE_RESULT_SCHEMA,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.sha256,
        "corpus_class": profile.corpus_class,
        "metric_registry_id": METRIC_REGISTRY_ID,
        "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
        "baseline_ref": BASELINE,
        "candidate_ref": CANDIDATE,
        "security_passed": True,
        "evaluator_attested": True,
        "evaluator_ref": "external-evaluator:edge-v1",
        "label_commitment_sha256": _sha("external-holdout-labels"),
        "cases": [
            {
                "case_id": case.case_id,
                "checks": {check: True for check in case.required_checks},
                "evidence_refs": [f"artifact:{case.case_id}:v1"],
            }
            for case in profile.cases
        ],
    }


def load_result(payload: dict) -> EvaluationProfileResult:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "result.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return EvaluationProfileResult.load(path)


class D705ExternalEvaluatorHandoffTests(unittest.TestCase):
    def setUp(self):
        self.profile = EvaluationProfile.load(EDGE)
        self.assertEqual(self.profile.profile_id, EDGE_LARGE_CONTEXT_PROFILE_ID)
        self.handoff = build_external_evaluator_handoff(
            self.profile,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
        )

    def test_handoff_is_exact_metadata_only_contract(self):
        payload = self.handoff.to_payload()
        raw = json.dumps(payload, ensure_ascii=False)
        self.assertEqual(
            payload["schema_version"], EXTERNAL_EVALUATOR_HANDOFF_SCHEMA
        )
        self.assertEqual(payload["profile_id"], EDGE_LARGE_CONTEXT_PROFILE_ID)
        self.assertEqual(payload["profile_sha256"], self.profile.sha256)
        self.assertEqual(payload["metric_registry_id"], METRIC_REGISTRY_ID)
        self.assertEqual(
            payload["metric_registry_sha256"], DEFAULT_METRIC_REGISTRY.sha256
        )
        self.assertEqual(payload["baseline_ref"], BASELINE)
        self.assertEqual(payload["candidate_ref"], CANDIDATE)
        self.assertEqual(
            [row["case_id"] for row in payload["cases"]],
            [case.case_id for case in self.profile.cases],
        )
        self.assertNotIn('"evaluator_attested": true', raw)
        self.assertNotIn('"label_commitment_sha256":', raw)
        self.assertNotIn("raw_prompt", raw)
        self.assertNotIn("expected_answer", raw)
        self.assertNotIn("model_response", raw)
        self.assertNotIn("holdout_labels", raw)
        self.assertNotIn("credential", raw.lower())

    def test_handoff_unknown_fields_fail_closed(self):
        payload = self.handoff.to_payload()
        payload["raw_prompt"] = "CONFIDENTIAL"
        with self.assertRaisesRegex(
            EvaluationProfileError, "unsupported fields"
        ):
            ExternalEvaluatorHandoff.from_payload(
                payload,
                profile=self.profile,
            )

    def test_missing_evaluator_attestation_is_rejected(self):
        payload = result_payload(self.profile)
        payload.pop("evaluator_attested")
        with self.assertRaisesRegex(
            EvaluationProfileError, "unsupported fields"
        ):
            load_result(payload)

        payload = result_payload(self.profile)
        payload["evaluator_attested"] = False
        with self.assertRaisesRegex(
            EvaluationProfileError, "evaluator_attested must be true"
        ):
            load_result(payload)

    def test_missing_external_label_commitment_is_rejected(self):
        payload = result_payload(self.profile)
        payload["label_commitment_sha256"] = None
        result = load_result(payload)
        with self.assertRaisesRegex(
            EvaluationProfileError, "label commitment"
        ):
            validate_external_result_against_handoff(
                self.profile,
                self.handoff,
                result,
            )

    def test_wrong_profile_sha_is_rejected(self):
        payload = result_payload(self.profile)
        payload["profile_sha256"] = "sha256:" + "0" * 64
        result = load_result(payload)
        with self.assertRaisesRegex(
            EvaluationProfileError, "profile SHA-256"
        ):
            validate_external_result_against_handoff(
                self.profile,
                self.handoff,
                result,
            )

    def test_wrong_metric_registry_is_rejected(self):
        payload = result_payload(self.profile)
        payload["metric_registry_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            EvaluationProfileError, "fingerprint mismatch"
        ):
            load_result(payload)

        payload = self.handoff.to_payload()
        payload["metric_registry_id"] = "workspace-wrong-registry-v1"
        with self.assertRaisesRegex(
            EvaluationProfileError, "metric registry id mismatch"
        ):
            ExternalEvaluatorHandoff.from_payload(
                payload,
                profile=self.profile,
            )

    def test_baseline_equal_candidate_is_rejected(self):
        payload = result_payload(self.profile)
        payload["candidate_ref"] = BASELINE
        with self.assertRaisesRegex(
            EvaluationProfileError, "must differ"
        ):
            load_result(payload)

        with self.assertRaisesRegex(
            EvaluationProfileError, "must differ"
        ):
            build_external_evaluator_handoff(
                self.profile,
                baseline_ref=BASELINE,
                candidate_ref=BASELINE,
            )

    def test_missing_case_is_rejected(self):
        payload = result_payload(self.profile)
        payload["cases"].pop()
        result = load_result(payload)
        with self.assertRaisesRegex(
            EvaluationProfileError, "case set"
        ):
            validate_external_result_against_handoff(
                self.profile,
                self.handoff,
                result,
            )

    def test_extra_case_is_rejected(self):
        payload = result_payload(self.profile)
        extra = dict(payload["cases"][0])
        extra["case_id"] = "unexpected-extra-case"
        payload["cases"].append(extra)
        result = load_result(payload)
        with self.assertRaisesRegex(
            EvaluationProfileError, "case set"
        ):
            validate_external_result_against_handoff(
                self.profile,
                self.handoff,
                result,
            )

    def test_failed_required_check_is_rejected(self):
        payload = result_payload(self.profile)
        first_check = next(iter(payload["cases"][0]["checks"]))
        payload["cases"][0]["checks"][first_check] = False
        result = load_result(payload)
        with self.assertRaisesRegex(
            EvaluationProfileError, "required check failed"
        ):
            validate_external_result_against_handoff(
                self.profile,
                self.handoff,
                result,
            )

    def test_unknown_or_raw_content_fields_are_rejected(self):
        for key in (
            "raw_prompt",
            "raw_expected_answer",
            "raw_model_response",
            "confidential_content",
            "credentials",
            "evidence_blob",
            "holdout_labels",
        ):
            payload = result_payload(self.profile)
            payload[key] = "forbidden"
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    EvaluationProfileError, "unsupported fields"
                ):
                    load_result(payload)

        payload = result_payload(self.profile)
        payload["cases"][0]["raw_model_response"] = "forbidden"
        with self.assertRaisesRegex(
            EvaluationProfileError, "unsupported fields"
        ):
            load_result(payload)

    def test_external_result_must_match_exact_handoff_refs(self):
        payload = result_payload(self.profile)
        payload["candidate_ref"] = "c" * 40
        result = load_result(payload)
        with self.assertRaisesRegex(
            EvaluationProfileError, "candidate_ref does not match handoff"
        ):
            validate_external_result_against_handoff(
                self.profile,
                self.handoff,
                result,
            )

    def test_valid_metadata_only_external_result_can_enter_existing_adapter(self):
        result = load_result(result_payload(self.profile))
        admitted = validate_external_result_against_handoff(
            self.profile,
            self.handoff,
            result,
        )
        evidence = build_profile_promotion_evidence(
            self.profile,
            admitted,
            evidence_id="d705-external-result",
        )
        payload = evidence.to_payload()
        raw = json.dumps(payload, ensure_ascii=False)
        self.assertEqual(payload["corpus_id"], self.profile.profile_id)
        self.assertEqual(payload["corpus_sha256"], self.profile.sha256)
        self.assertEqual(payload["baseline_ref"], BASELINE)
        self.assertEqual(payload["candidate_ref"], CANDIDATE)
        self.assertTrue(payload["evaluator_attested"])
        self.assertEqual(
            payload["label_commitment_sha256"],
            _sha("external-holdout-labels"),
        )
        self.assertNotIn("raw_prompt", raw)
        self.assertNotIn("expected_answer", raw)
        self.assertNotIn("model_response", raw)


if __name__ == "__main__":
    unittest.main()
