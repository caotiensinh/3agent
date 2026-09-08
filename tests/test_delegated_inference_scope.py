import unittest
from types import SimpleNamespace

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.inference_scope import (
    current_capability_authority,
    current_inference_scope,
    current_model_authority,
    delegated_inference_scope,
    inference_scope,
)
from three_agent.model_authority import ModelAuthorityDenied, TaskModelAuthority
from three_agent.task_contract import TaskContractCompiler


class DelegatedInferenceScopeTests(unittest.TestCase):
    def test_child_scope_reuses_budget_and_narrows_both_authorities(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-SUBAGENT",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
            write_scope=("src", "tests"),
        )
        root_model = TaskModelAuthority.from_contract(contract)
        root_capability = TaskCapabilityAuthority.from_contract(contract)
        budget = SimpleNamespace(task_id=contract.task_id)

        with inference_scope(
            contract.task_id,
            agent_id="orchestrator",
            stage="plan",
            execution_budget=budget,
            model_authority=root_model,
            capability_authority=root_capability,
        ) as root:
            with delegated_inference_scope(
                agent_id="review_lane",
                stage="inspect",
                allowed_sources=(),
                allowed_tools=("read_file", "run_tests"),
                write_scope="none",
                network_scope="deny",
                max_model_tier="specialist",
            ) as child:
                self.assertEqual(child.task_id, root.task_id)
                self.assertIs(child.execution_budget, budget)
                self.assertTrue(current_model_authority().is_subset_of(root_model))
                self.assertTrue(current_capability_authority().is_subset_of(root_capability))
                self.assertEqual(current_capability_authority().write_scope, "none")
                self.assertEqual(current_capability_authority().network_scope, "deny")
                self.assertEqual(current_inference_scope().agent_id, "review_lane")
            self.assertIs(current_model_authority(), root_model)
            self.assertIs(current_capability_authority(), root_capability)
        self.assertIsNone(current_inference_scope())

    def test_child_scope_cannot_widen_parent_capability(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-SUBAGENT-DENY",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        root_model = TaskModelAuthority.from_contract(contract)
        root_capability = TaskCapabilityAuthority.from_contract(contract)
        with inference_scope(
            contract.task_id,
            agent_id="orchestrator",
            stage="plan",
            model_authority=root_model,
            capability_authority=root_capability,
        ):
            with self.assertRaises((ModelAuthorityDenied, PermissionError)):
                with delegated_inference_scope(
                    agent_id="unsafe_lane",
                    stage="execute",
                    allowed_tools=root_model.allowed_tools + ("apply_patch",),
                    write_scope=("src",),
                    network_scope="allowlisted_egress",
                ):
                    pass

    def test_nested_delegation_remains_monotonic(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-NESTED-LANES",
            task_type="code_review",
            sensitivity="internal",
            risk_level="medium",
        )
        root_model = TaskModelAuthority.from_contract(contract)
        root_capability = TaskCapabilityAuthority.from_contract(contract)
        with inference_scope(
            contract.task_id,
            agent_id="orchestrator",
            stage="plan",
            model_authority=root_model,
            capability_authority=root_capability,
        ):
            with delegated_inference_scope(
                agent_id="lane_a",
                stage="inspect",
                allowed_tools=("read_file", "run_tests"),
                network_scope="deny",
            ):
                lane_a_model = current_model_authority()
                lane_a_capability = current_capability_authority()
                with delegated_inference_scope(
                    agent_id="lane_b",
                    stage="read_only",
                    allowed_tools=("read_file",),
                    network_scope="deny",
                    max_model_tier="small",
                ):
                    self.assertTrue(current_model_authority().is_subset_of(lane_a_model))
                    self.assertTrue(current_capability_authority().is_subset_of(lane_a_capability))
                    self.assertEqual(current_capability_authority().allowed_tools, ("read_file",))

    def test_no_llm_parent_cannot_delegate_model_access(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-NO-LLM-CHILD",
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
            deterministic_only=True,
        )
        authority = TaskModelAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            ModelAuthorityDenied,
            "DELEGATED_MODEL_AUTHORITY_WIDENED|NO_LLM_AUTHORITY_INVALID",
        ):
            authority.delegate(initial_model_tier="small", max_model_tier="small")


if __name__ == "__main__":
    unittest.main()
