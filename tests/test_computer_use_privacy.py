import unittest

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.computer_use import ComputerActionRequest, ComputerObservation
from three_agent.computer_use_evidence import ComputerEvidenceError, build_computer_execution_observation
from three_agent.computer_use_privacy import (
    ComputerPrivacyError,
    REDACTED,
    retain_computer_result,
    sanitize_computer_content,
)
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64


def restricted_runtime():
    task_id = "TASK-COMPUTER-PRIVACY"
    contract = TaskContractCompiler().compile(
        task_id=task_id,
        task_type="analysis",
        sensitivity="restricted",
        risk_level="medium",
        allowed_sources=("evidence",),
        allowed_tools=("browser.dom.observe",),
        write_scope="none",
    )
    acceptance = AcceptanceContract(
        task_id=task_id,
        criteria=(
            AcceptanceCriterion(
                criterion_id="computer-privacy",
                statement="Retain only privacy-safe computer-use evidence",
                verifier="unit_test",
            ),
        ),
    )
    canonical = HarnessTaskCompiler().compile(
        user_prompt="Observe a restricted isolated browser surface.",
        task_contract=contract,
        acceptance_contract=acceptance,
    )
    context = TaskContextBuilder.build(
        task_contract=contract,
        canonical_task=canonical,
        session_id="SESSION-COMPUTER-PRIVACY",
        trace_id="TRACE-COMPUTER-PRIVACY",
        actor_id="ACTOR-COMPUTER-PRIVACY",
        purpose="computer privacy retention",
        project_id="PROJECT-COMPUTER-PRIVACY",
    )
    authority = TaskCapabilityAuthority.from_contract(contract)
    workflow = {
        "title": "Restricted computer evidence",
        "objective": "Preserve only privacy-safe browser evidence.",
        "trigger": "manual",
        "risk_level": "medium",
        "data_class": "restricted",
        "nodes": [
            {
                "id": "start",
                "label": "Start",
                "kind": "input",
                "action": "input",
                "depends_on": [],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "observe",
                "label": "Observe",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "done",
                "label": "Return",
                "kind": "output",
                "action": "output",
                "depends_on": ["observe"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Privacy-safe evidence"],
        "warnings": [],
    }
    plan = ExecutionPlanBuilder.build(
        task_context=context,
        parent_authority=authority,
        workflow_contract=workflow,
        node_bindings={
            "observe": ExecutionNodeBinding(
                allowed_sources=("evidence",),
                allowed_tools=("browser.dom.observe",),
                resource_budget=TaskResourceBudget(
                    wall_time_s=10,
                    model_tokens=100,
                    tool_calls=1,
                ),
            ),
        },
    )
    return authority, plan


def observations(task_id):
    pre = ComputerObservation(
        session_id="session:privacy",
        task_id=task_id,
        state_id="state:pre",
        state_sha256=H1,
        surface="browser",
        active_target_ref="browser:profile:isolated/tab:tab1",
        captured_at="2026-09-10T00:00:00Z",
        structured_observation={"title": "Before"},
    ).validate()
    post = ComputerObservation(
        session_id="session:privacy",
        task_id=task_id,
        state_id="state:post",
        state_sha256=H3,
        surface="browser",
        active_target_ref="browser:profile:isolated/tab:tab1",
        captured_at="2026-09-10T00:00:01Z",
        structured_observation={"title": "After"},
    ).validate()
    return pre, post


def action(plan):
    return ComputerActionRequest(
        session_id="session:privacy",
        action_id="action:privacy",
        task_id=plan.task_id,
        plan_fingerprint=plan.fingerprint,
        node_id="observe",
        operation="browser.dom.observe",
        effect="read",
        resource_kind="browser_document",
        resource_ref="browser:profile:isolated/tab:tab1",
        arguments={},
        state_precondition_sha256=H1,
        idempotency_key=H2,
        risk_class="R0_OBSERVE",
        requires_writer=False,
    ).validate()


class ComputerUsePrivacyTests(unittest.TestCase):
    def test_credentials_and_secure_values_are_redacted_recursively(self):
        sanitized = sanitize_computer_content(
            {
                "authorization": "Bearer secret-token",
                "nested": {
                    "type": "password",
                    "value": "hunter2",
                    "textContent": "hunter2",
                },
                "nodes": [{"cookie": "sid=secret-cookie"}],
            }
        )
        retained = str(sanitized)
        self.assertNotIn("secret-token", retained)
        self.assertNotIn("hunter2", retained)
        self.assertNotIn("secret-cookie", retained)
        self.assertIn(REDACTED, retained)

    def test_url_userinfo_query_and_fragment_are_not_retained(self):
        sanitized = sanitize_computer_content(
            {"url": "https://user:pass@example.test/path?token=secret#private"}
        )
        self.assertEqual(sanitized["url"], "https://example.test/path")

    def test_restricted_and_secret_results_are_metadata_only(self):
        raw = {"matched": 3, "token": "secret-value"}
        for sensitivity in ("restricted", "secret"):
            with self.subTest(sensitivity=sensitivity):
                retained = retain_computer_result(raw, sensitivity=sensitivity)
                self.assertEqual(retained["retention"], "metadata_only")
                self.assertTrue(retained["sanitized_result_sha256"].startswith("sha256:"))
                self.assertNotIn("matched", retained)
                self.assertNotIn("secret-value", str(retained))

    def test_internal_result_retains_structure_but_not_credentials(self):
        retained = retain_computer_result(
            {"matched": 3, "password": "secret-value"},
            sensitivity="internal",
        )
        self.assertEqual(retained["matched"], 3)
        self.assertEqual(retained["password"], REDACTED)

    def test_continuous_capture_payload_is_rejected(self):
        with self.assertRaisesRegex(
            ComputerPrivacyError,
            "COMPUTER_CONTINUOUS_CAPTURE_RETENTION_FORBIDDEN",
        ):
            sanitize_computer_content({"screen-recording-bytes": "base64-video"})

    def test_restricted_evidence_adapter_does_not_retain_raw_result(self):
        authority, plan = restricted_runtime()
        pre, post = observations(plan.task_id)
        observation = build_computer_execution_observation(
            plan=plan,
            node_id="observe",
            parent_authority=authority,
            action=action(plan),
            pre_observation=pre,
            post_observation=post,
            status="SUCCEEDED",
            started_at="2026-09-10T00:00:00Z",
            finished_at="2026-09-10T00:00:01Z",
            executor_ref="fake-executor:v1",
            route="dom",
            result={"matched": 3, "password": "do-not-retain"},
        )
        retained = observation.normalized_output["computer_use"]["result"]
        self.assertEqual(retained["retention"], "metadata_only")
        self.assertNotIn("do-not-retain", str(observation.normalized_output))
        self.assertNotIn("matched", retained)

    def test_evidence_adapter_rejects_continuous_capture_result(self):
        authority, plan = restricted_runtime()
        pre, post = observations(plan.task_id)
        with self.assertRaisesRegex(
            ComputerEvidenceError,
            "COMPUTER_EVIDENCE_PRIVACY_REJECTED",
        ):
            build_computer_execution_observation(
                plan=plan,
                node_id="observe",
                parent_authority=authority,
                action=action(plan),
                pre_observation=pre,
                post_observation=post,
                status="SUCCEEDED",
                started_at="2026-09-10T00:00:00Z",
                finished_at="2026-09-10T00:00:01Z",
                executor_ref="fake-executor:v1",
                route="dom",
                result={"continuous-video": "base64-video"},
            )


if __name__ == "__main__":
    unittest.main()
