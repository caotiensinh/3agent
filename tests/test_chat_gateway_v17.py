from __future__ import annotations

import ast
import inspect
import textwrap
import unittest

from three_agent.chat_gateway import WorkflowV3HTTPHandler
from three_agent.chat_gateway import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    ContextAwareWorkflowV3HTTPHandler,
)
from three_agent.chat_gateway import (
    HTML_V17,
    ContinuitySecurityAwareProjectChatService,
    WorkflowV4ContextApplication,
    WorkflowV4ContextHTTPHandler,
)
from three_agent.chat_service_fidelity import ContractAwareProjectChatService
from three_agent.version import DISPLAY_VERSION


class WorkflowV4ContextGatewayTests(unittest.TestCase):
    def test_v17_layers_on_current_multiturn_gateway(self):
        self.assertTrue(
            issubclass(WorkflowV4ContextHTTPHandler, ContextAwareWorkflowV3HTTPHandler)
        )
        self.assertEqual(
            WorkflowV4ContextHTTPHandler.server_version,
            "WorkSpaceChat/ver.0.0.2",
        )
        self.assertIn(DISPLAY_VERSION, HTML_V17)
        self.assertIn("Workflow Studio", HTML_V17)
        self.assertIn("workflowV4PrepareBtn", HTML_V17)
        self.assertNotIn("workflowV3PrepareBtn", HTML_V17)
        self.assertNotIn("cdn.jsdelivr", HTML_V17)
        self.assertNotIn("unpkg.com", HTML_V17)

    def test_product_application_uses_budget_hardened_v4_controller(self):
        source = inspect.getsource(WorkflowV4ContextApplication.__init__)
        self.assertIn(
            "self.workflow_v4 = BudgetedWorkflowStateMachineV4Controller(service.orchestrator)",
            source,
        )
        self.assertIn("self.workflow_v3 = self.workflow_v4", source)
        self.assertNotIn(
            "self.workflow_v4 = WorkflowStateMachineV4Controller(service.orchestrator)",
            source,
        )

    def test_prepare_is_admin_gated_and_uses_v4_controller(self):
        source = inspect.getsource(WorkflowV4ContextHTTPHandler._prepare_dispatch)
        self.assertIn("self._require_admin()", source)
        self.assertIn("self.app.workflow_v4.prepare", source)
        self.assertIn("BLOCKED_BY_V4_ADMISSION", source)

    def test_inherited_mutations_keep_hardened_admin_boundary(self):
        for method in (
            WorkflowV4ContextHTTPHandler._execute_dispatch,
            WorkflowV4ContextHTTPHandler._checkpoint,
            WorkflowV4ContextHTTPHandler._workflow_state,
        ):
            self.assertIn("self._require_admin()", inspect.getsource(method))
        self.assertTrue(issubclass(WorkflowV4ContextHTTPHandler, WorkflowV3HTTPHandler))

    def test_health_preserves_multiturn_context_and_adds_budgeted_v4(self):
        source = textwrap.dedent(inspect.getsource(WorkflowV4ContextHTTPHandler.do_GET))
        tree = ast.parse(source)
        health_contract = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            keys = {
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
            if {
                "workflow_execution_version",
                "conversation_context_policy",
            }.issubset(keys):
                health_contract = {
                    key.value: value
                    for key, value in zip(node.keys, node.values)
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                }
                break

        self.assertIsNotNone(health_contract)
        assert health_contract is not None

        def signature(node: ast.AST) -> tuple[str, object]:
            if isinstance(node, ast.Constant):
                return ("constant", node.value)
            if isinstance(node, ast.Name):
                return ("name", node.id)
            return ("ast", ast.dump(node, include_attributes=False))

        expected = {
            "version": ("name", "DISPLAY_VERSION"),
            "workflow_execution_version": ("constant", "v4"),
            "workflow_execution_risk": ("constant", "low_only"),
            "workflow_execution_trigger": ("constant", "manual_only"),
            "workflow_schedule_execution": ("constant", False),
            "workflow_event_execution": ("constant", False),
            "workflow_branch_joins": ("constant", True),
            "workflow_bounded_parallel_dag": ("constant", True),
            "workflow_parallel_regions": ("constant", 1),
            "workflow_parallel_max_branches": (
                "name",
                "WORKFLOW_V4_MAX_PARALLEL_BRANCHES",
            ),
            "workflow_parallel_max_workers": (
                "name",
                "WORKFLOW_V4_MAX_PARALLEL_WORKERS",
            ),
            "workflow_parallel_budget_scope": (
                "constant",
                "atomic_parent_and_child",
            ),
            "workflow_parallel_budget_multiplication": ("constant", False),
            "workflow_parallel_nested": ("constant", False),
            "workflow_parallel_active_replay": ("constant", False),
            "public_query_final_dlp": ("constant", True),
            "direct_chat": ("constant", True),
            "response_language_current_request_precedence": ("constant", True),
            "response_output_contract": (
                "name",
                "OUTPUT_CONTRACT_POLICY_VERSION",
            ),
            "response_output_contract_current_request_only": ("constant", True),
            "response_generation_bounded": ("constant", True),
            "conversation_context_policy": (
                "name",
                "CONVERSATION_CONTEXT_POLICY_VERSION",
            ),
            "conversation_context_reference_gated": ("constant", True),
            "conversation_context_completed_only": ("constant", True),
            "standalone_request_history_injected": ("constant", False),
            "follow_up_language_continuity": ("constant", True),
            "follow_up_reference_anchoring": ("constant", True),
        }
        self.assertEqual(
            {key: signature(health_contract[key]) for key in expected},
            expected,
        )
        self.assertEqual(
            CONVERSATION_CONTEXT_POLICY_VERSION,
            "deterministic-reference-gated/v2",
        )

    def test_canonical_main_preserves_v17_contract_and_uses_latest_service(self):
        from three_agent import chat_gateway

        source = inspect.getsource(chat_gateway.main)
        self.assertIn("ContinuitySecurityAwareProjectChatService", source)
        self.assertIn("SecurityE2EApplication", source)
        self.assertNotIn("ContractAwareProjectChatService(orchestrator", source)
        self.assertNotIn("WorkflowV4ContextApplication(service", source)
        self.assertTrue(
            issubclass(
                ContinuitySecurityAwareProjectChatService,
                ContractAwareProjectChatService,
            )
        )


if __name__ == "__main__":
    unittest.main()
