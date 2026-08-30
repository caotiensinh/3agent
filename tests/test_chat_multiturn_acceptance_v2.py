from __future__ import annotations

import unittest

from three_agent import chat_multiturn_acceptance as acceptance
from three_agent.chat_service_fidelity_v2 import ContractAwareProjectChatService
from three_agent.chat_multiturn_acceptance_v2 import (
    DiagnosticContractAwareProjectChatService,
    DiagnosticRecordingLLM,
    RuntimePromptEvidence,
    _job_failure_code,
    install_runtime_hooks,
    safe_response_validation_reason,
    safe_runtime_failure_code,
    safe_top_level_failure,
    summarize_runtime_evidence,
)
from three_agent.llm import LocalLLMError
from three_agent.resource_budget import ResourceAdmissionError, ResourceBusyError


class SuccessDelegate:
    def generate(self, system_prompt, user_prompt, **kwargs):
        del system_prompt, user_prompt, kwargs
        return "ok"


class FailureDelegate:
    def __init__(self, exc):
        self.exc = exc

    def generate(self, system_prompt, user_prompt, **kwargs):
        del system_prompt, user_prompt, kwargs
        raise self.exc


def evidence(*, succeeded: bool, failure_code: str = "") -> RuntimePromptEvidence:
    return RuntimePromptEvidence(
        sha256="sha256:test",
        chars=10,
        current_request_boundary=True,
        follow_up_policy=False,
        standalone_policy=True,
        recent_context=False,
        unavailable_context=False,
        succeeded=succeeded,
        failure_code=failure_code,
    )


class RuntimeEvidenceTests(unittest.TestCase):
    def test_successful_delegate_marks_model_returned(self):
        recorder = DiagnosticRecordingLLM(SuccessDelegate())
        self.assertEqual(recorder.generate("system", "<CURRENT_USER_REQUEST>x</CURRENT_USER_REQUEST>"), "ok")
        self.assertEqual(len(recorder.calls), 1)
        self.assertTrue(recorder.calls[0].succeeded)
        self.assertEqual(recorder.calls[0].failure_code, "")

    def test_permission_failure_is_sanitized_and_reraised(self):
        secret = "/secret/operator/path"
        recorder = DiagnosticRecordingLLM(FailureDelegate(PermissionError(secret)))
        with self.assertRaises(PermissionError):
            recorder.generate("system", "<CURRENT_USER_REQUEST>private prompt</CURRENT_USER_REQUEST>")
        self.assertEqual(recorder.calls[0].failure_code, "runtime_permission")
        self.assertFalse(recorder.calls[0].succeeded)
        self.assertNotIn(secret, repr(recorder.calls[0]))
        self.assertNotIn("private prompt", repr(recorder.calls[0]))

    def test_runtime_failure_classifier_uses_stable_codes_only(self):
        cases = (
            (ResourceBusyError("sensitive"), "resource_busy"),
            (ResourceAdmissionError("sensitive"), "resource_admission"),
            (PermissionError("sensitive"), "runtime_permission"),
            (LocalLLMError("Local LLM request failed: <urlopen error [Errno 111] Connection refused>"), "llm_endpoint_unreachable"),
            (LocalLLMError("Local LLM returned an empty response"), "llm_empty_response"),
            (LocalLLMError("Local LLM request failed: HTTP Error 503"), "llm_http_server_error"),
            (RuntimeError("sensitive"), "runtime_error"),
        )
        for exc, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(safe_runtime_failure_code(exc), expected)

    def test_response_validation_reason_is_allowlisted_and_normalized(self):
        for reason in (
            "empty_response",
            "requested_format_mismatch",
            "target_language_mismatch",
            "workflow_wrapper_leak",
            "output_contract_empty",
            "output_contract_non_bullet_text",
            "output_contract_multiple_sentences",
            "output_contract_invalid_json",
            "output_contract_not_single_number",
        ):
            with self.subTest(reason=reason):
                self.assertEqual(safe_response_validation_reason(reason), reason)

        self.assertEqual(
            safe_response_validation_reason("output_contract_chars:931_gt_840"),
            "output_contract_chars_limit",
        )
        self.assertEqual(
            safe_response_validation_reason("output_contract_lines:5_gt_3"),
            "output_contract_lines_limit",
        )
        self.assertEqual(
            safe_response_validation_reason("output_contract_bullets:4_not_3"),
            "output_contract_bullet_count",
        )

    def test_response_validation_reason_never_exposes_arbitrary_text(self):
        secret = "TOP_SECRET_DO_NOT_PERSIST"
        for value in (
            secret,
            f"target_language_mismatch {secret}",
            f"output_contract_chars:931_gt_840 {secret}",
            f"ValueError: {secret}",
        ):
            with self.subTest(value=value):
                code = safe_response_validation_reason(value)
                self.assertNotIn(secret, code)
                self.assertIn(code, {"", "response_validation_unknown"})
        self.assertEqual(
            safe_response_validation_reason("output_contract_future_rule:sensitive-detail"),
            "response_validation_unknown",
        )

    def test_failed_call_wins_over_response_validation(self):
        turn = {"failures": ["job_status:failed"]}
        self.assertEqual(
            _job_failure_code(turn, [evidence(succeeded=False, failure_code="runtime_permission")]),
            "runtime_permission",
        )
        self.assertEqual(
            _job_failure_code(turn, [evidence(succeeded=True)]),
            "response_validation",
        )
        self.assertEqual(_job_failure_code(turn, []), "pre_model_failure")
        self.assertEqual(_job_failure_code({"failures": []}, [evidence(succeeded=True)]), "")

    def test_summary_distinguishes_attempt_from_successful_model_return(self):
        failed = {
            "results": [{
                "turns": [{
                    "attempts": 1,
                    "job_failure_code": "runtime_permission",
                    "response_validation_reason": "",
                    "prompt_evidence": {"succeeded": False, "failure_code": "runtime_permission"},
                }]
            }]
        }
        summarize_runtime_evidence(failed)
        self.assertTrue(failed["model_call_attempted"])
        self.assertFalse(failed["live_model_executed"])
        self.assertEqual(failed["runtime_failure_codes"], ["runtime_permission"])
        self.assertEqual(failed["response_validation_reasons"], [])

        successful = {
            "results": [{
                "turns": [{
                    "attempts": 1,
                    "job_failure_code": "response_validation",
                    "response_validation_reason": "output_contract_bullet_count",
                    "prompt_evidence": {"succeeded": True, "failure_code": ""},
                }]
            }]
        }
        summarize_runtime_evidence(successful)
        self.assertTrue(successful["model_call_attempted"])
        self.assertTrue(successful["live_model_executed"])
        self.assertEqual(successful["runtime_failure_codes"], ["response_validation"])
        self.assertEqual(
            successful["response_validation_reasons"],
            ["output_contract_bullet_count"],
        )

    def test_top_level_failure_never_persists_raw_exception(self):
        secret = "SECRET_TOKEN_AND_PATH"
        report = safe_top_level_failure(PermissionError(secret), live=True)
        rendered = repr(report)
        self.assertEqual(report["failure_code"], "runtime_permission")
        self.assertFalse(report["live_model_executed"])
        self.assertFalse(report["model_call_attempted"])
        self.assertNotIn(secret, rendered)
        self.assertEqual(report["response_validation_reasons"], [])
        self.assertFalse(report["privacy"]["raw_prompts_in_report"])
        self.assertFalse(report["privacy"]["raw_answers_in_report"])
        self.assertFalse(report["privacy"]["public_egress_enabled"])
        self.assertFalse(report["privacy"]["production_database_mutated"])

    def test_runtime_hooks_keep_observational_production_service_path(self):
        original_service = acceptance.ContextAwareProjectChatService
        original_recorder = acceptance.RecordingLLM
        original_run_case = acceptance.run_case
        original_run_live_suite = acceptance.run_live_suite
        try:
            install_runtime_hooks()
            self.assertIs(
                acceptance.ContextAwareProjectChatService,
                DiagnosticContractAwareProjectChatService,
            )
            self.assertTrue(
                issubclass(
                    DiagnosticContractAwareProjectChatService,
                    ContractAwareProjectChatService,
                )
            )
            self.assertIs(acceptance.RecordingLLM, DiagnosticRecordingLLM)
        finally:
            acceptance.ContextAwareProjectChatService = original_service
            acceptance.RecordingLLM = original_recorder
            acceptance.run_case = original_run_case
            acceptance.run_live_suite = original_run_live_suite

    def test_authoritative_corpus_hash_remains_exact(self):
        self.assertEqual(
            acceptance.corpus_sha256(),
            "sha256:45c1269adb4bd89816b7b423104ad30740f08f885ed38e5c22e0b5a0c97258df",
        )


if __name__ == "__main__":
    unittest.main()
