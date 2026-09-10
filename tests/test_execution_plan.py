import unittest
from dataclasses import FrozenInstanceError, replace

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_plan import (
    ExecutionNodeBinding,
    ExecutionPlanBuilder,
    ExecutionPlanError,
)
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler


def sample_workflow():
    return {
        "title": "Runtime execution plan",
        "objective": "Collect evidence, validate it, obtain approval, and return a result.",
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
                "id": "research",
                "label": "Collect evidence",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "check",
                "label": "Validate evidence",
                "kind": "validation",
                "action": "validate",
                "depends_on": ["research"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "approve",
                "label": "Human approval",
                "kind": "approval",
                "action": "human_approval",
                "depends_on": ["check"],
                "condition": "validation passed",
                "approval_required": True,
            },
            {
                "id": "done",
                "label": "Return result",
                "kind": "output",
                "action": "output",
                "depends_on": ["approve"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Validated result"],
        "warnings": [],
    }


class ExecutionPlanConvergenceTests(unittest.TestCase):
    @staticmethod
    def _bindings(*, task_id="TASK-PLAN-1", risk_level="medium"):
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level=risk_level,
            allowed_sources=("repo", "evidence"),
            allowed_tools=("search_docs", "read_file", "run_tests"),
            write_scope="none",
        )
        acceptance = AcceptanceContract(
            task_id=task_id,
            criteria=(
                AcceptanceCriterion(
                    criterion_id="result",
                    statement="Produce a validated runtime execution plan",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Converge the WorkSpace runtime execution plan.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-PLAN-1",
            trace_id="TRACE-PLAN-1",
            actor_id="ACTOR-PLAN-1",
            purpose="runtime execution planning",
            project_id="PROJECT-1",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        return contract, context, authority

    def test_plan_is_deterministic_and_never_authorizes_execution(self):
        _, context, authority = self._bindings()
        binding_a = ExecutionNodeBinding(
            allowed_sources=("repo", "evidence", "repo"),
            allowed_tools=("read_file", "search_docs", "read_file"),
            resource_budget=TaskResourceBudget(
                wall_time_s=10,
                model_tokens=200,
                tool_calls=1,
            ),
            evidence_requirements=("evidence:source", "evidence:source"),
        )
        binding_b = ExecutionNodeBinding(
            allowed_sources=("evidence", "repo"),
            allowed_tools=("search_docs", "read_file"),
            resource_budget=TaskResourceBudget(
                wall_time_s=10,
                model_tokens=200,
                tool_calls=1,
            ),
            evidence_requirements=("evidence:source",),
        )

        first = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=sample_workflow(),
            node_bindings={"research": binding_a},
        )
        second = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=sample_workflow(),
            node_bindings={"research": binding_b},
        )

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(
            [node.node_id for node in first.nodes],
            ["start", "research", "check", "approve", "done"],
        )
        self.assertFalse(first.execution_authorized)
        self.assertEqual(first.execution_mode, "plan_only")
        self.assertTrue(all(node.canonical_dict()["execution_authorized"] is False for node in first.nodes))
        with self.assertRaises(FrozenInstanceError):
            first.execution_authorized = True
        with self.assertRaises(ValueError):
            replace(first, execution_authorized=True)

    def test_plan_binds_exact_task_context_and_parent_authority(self):
        _, context, authority = self._bindings()
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=sample_workflow(),
        )

        self.assertEqual(plan.task_id, context.task_id)
        self.assertEqual(plan.task_context_fingerprint, context.fingerprint)
        self.assertEqual(
            plan.task_context_identity_fingerprint,
            context.identity_fingerprint,
        )
        self.assertEqual(plan.parent_authority_fingerprint, authority.fingerprint)
        rebound = plan.rebind_authorities(authority)
        self.assertEqual(set(rebound), {node.node_id for node in plan.nodes})
        self.assertTrue(all(rebound[node.node_id].fingerprint == node.authority_fingerprint for node in plan.nodes))

    def test_parent_authority_mismatch_fails_closed(self):
        _, context, _ = self._bindings(task_id="TASK-PLAN-PARENT")
        _, _, other_authority = self._bindings(task_id="TASK-PLAN-OTHER")

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "EXECUTION_PLAN_PARENT_TASK_MISMATCH|EXECUTION_PLAN_PARENT_AUTHORITY_MISMATCH",
        ):
            ExecutionPlanBuilder.build(
                task_context=context,
                parent_authority=other_authority,
                workflow_contract=sample_workflow(),
            )

    def test_existing_workflow_cycle_validation_is_reused(self):
        _, context, authority = self._bindings()
        workflow = sample_workflow()
        workflow["nodes"][0]["depends_on"] = ["done"]

        with self.assertRaisesRegex(ExecutionPlanError, "INVALID_WORKFLOW_CONTRACT"):
            ExecutionPlanBuilder.build(
                task_context=context,
                parent_authority=authority,
                workflow_contract=workflow,
            )

    def test_node_authority_cannot_exceed_parent(self):
        _, context, authority = self._bindings()
        binding = ExecutionNodeBinding(
            allowed_sources=("repo", "internet"),
            allowed_tools=("search_docs",),
        )

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "EXECUTION_NODE_AUTHORITY_ESCALATION:research",
        ):
            ExecutionPlanBuilder.build(
                task_context=context,
                parent_authority=authority,
                workflow_contract=sample_workflow(),
                node_bindings={"research": binding},
            )

    def test_node_budget_cannot_exceed_task_budget(self):
        _, context, authority = self._bindings()
        binding = ExecutionNodeBinding(
            resource_budget=TaskResourceBudget(
                wall_time_s=context.resource_budget.wall_time_s + 1,
                model_tokens=0,
                tool_calls=0,
            ),
        )

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "EXECUTION_NODE_BUDGET_EXCEEDS_TASK_WALL_TIME_S",
        ):
            ExecutionPlanBuilder.build(
                task_context=context,
                parent_authority=authority,
                workflow_contract=sample_workflow(),
                node_bindings={"research": binding},
            )

    def test_aggregate_node_budget_cannot_exceed_task_budget(self):
        _, context, authority = self._bindings()
        half_plus_one = (context.resource_budget.wall_time_s // 2) + 1
        binding = ExecutionNodeBinding(
            resource_budget=TaskResourceBudget(
                wall_time_s=half_plus_one,
                model_tokens=0,
                tool_calls=0,
            ),
        )

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "EXECUTION_PLAN_BUDGET_EXCEEDS_TASK_WALL_TIME_S",
        ):
            ExecutionPlanBuilder.build(
                task_context=context,
                parent_authority=authority,
                workflow_contract=sample_workflow(),
                node_bindings={"research": binding, "check": binding},
            )

    def test_approval_node_is_fail_closed_even_if_workflow_flag_is_false(self):
        _, context, authority = self._bindings()
        workflow = sample_workflow()
        workflow["nodes"][3]["approval_required"] = False

        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=workflow,
            node_bindings={
                "approve": ExecutionNodeBinding(approval_required=False),
            },
        )

        approval = next(node for node in plan.nodes if node.node_id == "approve")
        self.assertTrue(approval.approval_required)
        self.assertFalse(approval.canonical_dict()["execution_authorized"])

    def test_workflow_cannot_underclassify_canonical_task_risk(self):
        _, context, authority = self._bindings(risk_level="high")
        workflow = sample_workflow()
        workflow["risk_level"] = "medium"

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "EXECUTION_PLAN_RISK_UNDERCLASSIFIED",
        ):
            ExecutionPlanBuilder.build(
                task_context=context,
                parent_authority=authority,
                workflow_contract=workflow,
            )


if __name__ == "__main__":
    unittest.main()
