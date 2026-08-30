from __future__ import annotations

import unittest
from types import SimpleNamespace

from three_agent.chat_simple_e2e_acceptance import (
    CASES,
    contract_summary,
    frontend_contract_errors,
    run_case,
)


class _Recorder:
    def __init__(self, calls=None):
        self.calls = list(calls or [])


class _ImmediateService:
    def __init__(self, job):
        self.job = job
        self.submitted_kwargs = None

    def submit(self, message, **kwargs):
        self.submitted_kwargs = {"message": message, **kwargs}
        return SimpleNamespace(job_id=self.job.job_id, stages=list(self.job.stages))

    def get(self, job_id):
        if job_id != self.job.job_id:
            return None
        return self.job


class SimpleChatE2EAcceptanceTests(unittest.TestCase):
    def test_contract_contains_exactly_vi_ja_en_simple_cases(self):
        self.assertEqual([case.expected_language for case in CASES], ["vi", "ja", "en"])
        self.assertEqual(len(CASES), 3)
        for case in CASES:
            self.assertTrue(case.prompt.strip())

    def test_frontend_default_chat_has_no_agent_stage_cards(self):
        self.assertEqual(frontend_contract_errors(), ())
        summary = contract_summary()
        self.assertTrue(summary["valid"])
        self.assertTrue(summary["frontend_contract_passed"])

    def test_contract_report_never_persists_raw_prompts_or_answers(self):
        privacy = contract_summary()["privacy"]
        self.assertFalse(privacy["raw_prompts_in_report"])
        self.assertFalse(privacy["raw_answers_in_report"])
        self.assertFalse(privacy["production_database_mutated"])
        self.assertFalse(privacy["public_egress_enabled"])

    def test_direct_answer_stage_passes_without_workflow_stages(self):
        job = SimpleNamespace(
            job_id="job-direct",
            status="completed",
            language="vi",
            answer="Tôi là WorkSpace, trợ lý AI cục bộ hỗ trợ công việc nội bộ.",
            error=None,
            stages=[{"id": "answer", "label": "Direct local answer", "status": "completed"}],
        )
        service = _ImmediateService(job)
        recorder = _Recorder([SimpleNamespace(succeeded=True, failure_code="")])

        result = run_case(service, recorder, CASES[0], timeout_seconds=1.0)

        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["route"], "direct_chat")
        self.assertEqual(result["initial_stage_ids"], ["answer"])
        self.assertEqual(service.submitted_kwargs["request_mode"], "chat")
        self.assertEqual(service.submitted_kwargs["effort"], "standard")
        self.assertEqual(service.submitted_kwargs["upload_ids"], [])

    def test_research_pipeline_is_a_hard_failure_for_simple_chat(self):
        job = SimpleNamespace(
            job_id="job-wrong-route",
            status="failed",
            language="vi",
            answer="",
            error="ResourceAdmissionError: resource admission denied",
            stages=[
                {"id": "research", "label": "Research", "status": "blocked"},
                {"id": "presentation", "label": "Presentation", "status": "skipped"},
                {"id": "daily_report", "label": "Human Report", "status": "failed"},
            ],
        )
        service = _ImmediateService(job)
        recorder = _Recorder(
            [SimpleNamespace(succeeded=False, failure_code="resource_admission")]
        )

        result = run_case(service, recorder, CASES[0], timeout_seconds=1.0)

        self.assertFalse(result["passed"])
        self.assertEqual(result["route"], "unexpected")
        self.assertIn("route:workflow_stage_in_initial_response", result["failures"])
        self.assertIn("resource:admission_denied", result["failures"])
        self.assertEqual(result["failure_code"], "resource_admission")


if __name__ == "__main__":
    unittest.main()
