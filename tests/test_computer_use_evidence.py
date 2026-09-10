import unittest

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.computer_use import ComputerActionRequest, ComputerObservation
from three_agent.computer_use_evidence import (
    ComputerEvidenceError,
    build_computer_execution_observation,
)
from three_agent.execution_observation import ObservationCost
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64


def workflow():
    return {
        "title": "Computer observation binding",
        "objective": "Observe a governed browser surface and preserve bounded evidence.",
        "trigger": "manual",
        "risk_level": "medium",
        "data_class": "internal",
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
                "label": "Observe browser",
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
        "outputs": ["Bounded observation"],
        "warnings": [],
    }


class ComputerUseEvidenceTests(unittest.TestCase):
    @staticmethod
    def runtime():
        task_id = "TASK-COMPUTER-EVIDENCE"
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="medium",
            allowed_sources=("evidence",),
            allowed_tools=("browser.dom.observe",),
            write_scope="none",
        )
        acceptance = AcceptanceContract(
            task_id=task_id,
            criteria=(
                AcceptanceCriterion(
                    criterion_id="computer-evidence",
                    statement="Bind computer-use observations into runtime evidence",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Observe the isolated browser surface.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-COMPUTER-EVIDENCE",
            trace_id="TRACE-COMPUTER-EVIDENCE",
            actor_id="ACTOR-COMPUTER-EVIDENCE",
            purpose="computer evidence binding",
            project_id="PROJECT-COMPUTER-EVIDENCE",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=workflow(),
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

    @staticmethod
    def observations(task_id):
        pre = ComputerObservation(
            session_id="session:computer",
            task_id=task_id,
            state_id="state:pre",
            state_sha256=H1,
            surface="browser",
            active_target_ref="browser:profile:isolated/tab:tab1",
            captured_at="2026-09-10T00:00:00Z",
            structured_observation={"title": "Before"},
            screenshot_sha256=H2,
        ).validate()
        post = ComputerObservation(
            session_id="session:computer",
            task_id=task_id,
            state_id="state:post",
            state_sha256=H3,
            surface="browser",
            active_target_ref="browser:profile:isolated/tab:tab1",
            captured_at="2026-09-10T00:00:01Z",
            structured_observation={"title": "After"},
            screenshot_sha256=H3,
        ).validate()
        return pre, post

    @staticmethod
    def action(plan, task_id):
        return ComputerActionRequest(
            session_id="session:computer",
            action_id="action:observe",
            task_id=task_id,
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

    def test_adapter_builds_canonical_execution_observation(self):
        authority, plan = self.runtime()
        item = self.action(plan, plan.task_id)
        pre, post = self.observations(plan.task_id)
        observation = build_computer_execution_observation(
            plan=plan,
            node_id="observe",
            parent_authority=authority,
            action=item,
            pre_observation=pre,
            post_observation=post,
            status="SUCCEEDED",
            started_at="2026-09-10T00:00:00Z",
            finished_at="2026-09-10T00:00:01Z",
            executor_ref="fake-executor:v1",
            route="dom",
            result={"matched_nodes": 3},
            cost=ObservationCost(wall_time_s=1, tool_calls=1),
        )
        payload = observation.normalized_output["computer_use"]
        self.assertEqual(payload["action_fingerprint"], item.fingerprint)
        self.assertEqual(payload["pre_state_sha256"], H1)
        self.assertEqual(payload["post_state_sha256"], H3)
        self.assertEqual(payload["pre_screenshot_sha256"], H2)
        self.assertEqual(payload["route"], "dom")
        self.assertEqual(observation.plan_fingerprint, plan.fingerprint)

    def test_adapter_rejects_stale_pre_state(self):
        authority, plan = self.runtime()
        item = self.action(plan, plan.task_id)
        pre, post = self.observations(plan.task_id)
        stale = ComputerObservation(
            session_id=pre.session_id,
            task_id=pre.task_id,
            state_id=pre.state_id,
            state_sha256=H2,
            surface=pre.surface,
            active_target_ref=pre.active_target_ref,
            captured_at=pre.captured_at,
            structured_observation=pre.structured_observation,
            screenshot_sha256=pre.screenshot_sha256,
        ).validate()
        with self.assertRaisesRegex(ComputerEvidenceError, "COMPUTER_EVIDENCE_OBSERVATION_INVALID"):
            build_computer_execution_observation(
                plan=plan,
                node_id="observe",
                parent_authority=authority,
                action=item,
                pre_observation=stale,
                post_observation=post,
                status="SUCCEEDED",
                started_at="2026-09-10T00:00:00Z",
                finished_at="2026-09-10T00:00:01Z",
                executor_ref="fake-executor:v1",
                route="dom",
            )

    def test_adapter_rejects_cross_session_post_observation(self):
        authority, plan = self.runtime()
        item = self.action(plan, plan.task_id)
        pre, post = self.observations(plan.task_id)
        wrong = ComputerObservation(
            session_id="session:other",
            task_id=post.task_id,
            state_id=post.state_id,
            state_sha256=post.state_sha256,
            surface=post.surface,
            active_target_ref=post.active_target_ref,
            captured_at=post.captured_at,
            structured_observation=post.structured_observation,
            screenshot_sha256=post.screenshot_sha256,
        ).validate()
        with self.assertRaisesRegex(ComputerEvidenceError, "COMPUTER_EVIDENCE_POST_SESSION_MISMATCH"):
            build_computer_execution_observation(
                plan=plan,
                node_id="observe",
                parent_authority=authority,
                action=item,
                pre_observation=pre,
                post_observation=wrong,
                status="SUCCEEDED",
                started_at="2026-09-10T00:00:00Z",
                finished_at="2026-09-10T00:00:01Z",
                executor_ref="fake-executor:v1",
                route="dom",
            )

    def test_adapter_preserves_execution_observation_budget_enforcement(self):
        authority, plan = self.runtime()
        item = self.action(plan, plan.task_id)
        pre, post = self.observations(plan.task_id)
        with self.assertRaisesRegex(ValueError, "OBSERVATION_TOOL_CALLS_EXCEED_NODE_BUDGET"):
            build_computer_execution_observation(
                plan=plan,
                node_id="observe",
                parent_authority=authority,
                action=item,
                pre_observation=pre,
                post_observation=post,
                status="SUCCEEDED",
                started_at="2026-09-10T00:00:00Z",
                finished_at="2026-09-10T00:00:01Z",
                executor_ref="fake-executor:v1",
                route="dom",
                cost=ObservationCost(tool_calls=2),
            )


if __name__ == "__main__":
    unittest.main()
