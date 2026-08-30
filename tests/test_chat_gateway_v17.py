from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway_v15 import WorkflowV3HTTPHandler
from three_agent.chat_gateway_v16 import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    ContextAwareProjectChatService,
    ContextAwareWorkflowV3HTTPHandler,
)
from three_agent.chat_gateway_v17 import (
    HTML_V17,
    WorkflowV4ContextApplication,
    WorkflowV4ContextHTTPHandler,
)
from three_agent.version import DISPLAY_VERSION


class WorkflowV4ContextGatewayTests(unittest.TestCase):
    def test_v17_layers_on_current_multiturn_gateway(self):
        self.assertTrue(
            issubclass(WorkflowV4ContextHTTPHandler, ContextAwareWorkflowV3HTTPHandler)
        )
        self.assertEqual(
            WorkflowV4ContextHTTPHandler.server_version,
            "WorkSpaceChat/ver.0.0.1",
        )
        self.assertIn(DISPLAY_VERSION, HTML_V17)
        self.assertIn("Workflow Studio", HTML_V17)
        self.assertIn("workflowV4PrepareBtn", HTML_V17)
        self.assertNotIn("workflowV3PrepareBtn", HTML_V17)
        self.assertNotIn("cdn.jsdelivr", HTML_V17)
        self.assertNotIn("unpkg.com", HTML_V17)

    def test_product_application_uses_budget_hardened_v4_controller(self):
        source = inspect.getsource(WorkflowV4ContextApplication.__init__)
        self.assertIn("BudgetedWorkflowStateMachineV4Controller", source)
        self.assertIn("self.workflow_v3 = self.workflow_v4", source)
        self.assertNotIn("WorkflowStateMachineV4Controller(service.orchestrator)", source)

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
        source = inspect.getsource(WorkflowV4ContextHTTPHandler.do_GET)
        for token in (
            '"version": DISPLAY_VERSION',
            '"workflow_execution_version": "v4"',
            '"workflow_execution_risk": "low_only"',
            '"workflow_execution_trigger": "manual_only"',
            '"workflow_schedule_execution": False',
            '"workflow_event_execution": False',
            '"workflow_branch_joins": True',
            '"workflow_bounded_parallel_dag": True',
            '"workflow_parallel_regions": 1',
            '"workflow_parallel_max_branches": WORKFLOW_V4_MAX_PARALLEL_BRANCHES',
            '"workflow_parallel_max_workers": WORKFLOW_V4_MAX_PARALLEL_WORKERS',
            '"workflow_parallel_budget_scope": "atomic_parent_and_child"',
            '"workflow_parallel_budget_multiplication": False',
            '"workflow_parallel_nested": False',
            '"workflow_parallel_active_replay": False',
            '"public_query_final_dlp": True',
            '"direct_chat": True',
            '"response_language_current_request_precedence": True',
            '"conversation_context_policy": CONVERSATION_CONTEXT_POLICY_VERSION',
            '"conversation_context_reference_gated": True',
            '"conversation_context_completed_only": True',
            '"standalone_request_history_injected": False',
            '"follow_up_language_continuity": True',
        ):
            self.assertIn(token, source)
        self.assertEqual(
            CONVERSATION_CONTEXT_POLICY_VERSION,
            "deterministic-reference-gated/v1",
        )

    def test_main_uses_context_aware_service_not_legacy_direct_chat_service(self):
        from three_agent import chat_gateway_v17

        source = inspect.getsource(chat_gateway_v17.main)
        self.assertIn("ContextAwareProjectChatService", source)
        self.assertIn("WorkflowV4ContextApplication", source)
        self.assertIn("WorkflowV4ContextHTTPHandler", source)


if __name__ == "__main__":
    unittest.main()
