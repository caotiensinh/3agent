from __future__ import annotations

import ast
import inspect
import textwrap
import unittest

from three_agent.chat_gateway import IntentAwareWorkflowDispatchHTTPHandler
from three_agent.chat_gateway import HTML_V15, WorkflowV3HTTPHandler


class WorkflowV3GatewayTests(unittest.TestCase):
    def test_gateway_layers_on_current_chat_fidelity_gateway(self):
        self.assertTrue(
            issubclass(WorkflowV3HTTPHandler, IntentAwareWorkflowDispatchHTTPHandler)
        )
        self.assertEqual(WorkflowV3HTTPHandler.server_version, "WorkSpaceChat/0.16")
        self.assertIn("Workflow Studio", HTML_V15)
        self.assertIn("/api/workflows/compile", HTML_V15)
        self.assertIn('id="lang"', HTML_V15)
        self.assertIn('option value="auto" selected', HTML_V15)

    def test_canonical_frontend_preserves_one_explicit_execution_controller(self):
        for token in (
            "workflowV4PrepareBtn",
            "workflowV4StartBtn",
            "workflowV4LoadBtn",
            "workflowV4ApproveBtn",
            "workflowV4RejectBtn",
            "/api/workflows/prepare-dispatch",
            "/checkpoint",
            "/state",
            "AUTHORIZE",
            "APPROVE",
            "REJECT",
        ):
            self.assertIn(token, HTML_V15)
        self.assertNotIn("workflowPrepareDispatchBtn", HTML_V15)
        self.assertNotIn("workflowAuthorizeDispatchBtn", HTML_V15)
        self.assertNotIn("cdn.jsdelivr", HTML_V15)
        self.assertNotIn("unpkg.com", HTML_V15)

    def test_all_v3_mutations_and_state_recovery_are_admin_gated(self):
        methods = (
            WorkflowV3HTTPHandler._prepare_dispatch,
            WorkflowV3HTTPHandler._execute_dispatch,
            WorkflowV3HTTPHandler._checkpoint,
            WorkflowV3HTTPHandler._workflow_state,
        )
        for method in methods:
            self.assertIn("self._require_admin()", inspect.getsource(method))

        for method in (
            WorkflowV3HTTPHandler._execute_dispatch,
            WorkflowV3HTTPHandler._checkpoint,
        ):
            tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
            self.assertTrue(
                any(
                    isinstance(node, ast.Subscript)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "admin"
                    and isinstance(node.slice, ast.Constant)
                    and node.slice.value == "user_id"
                    for node in ast.walk(tree)
                )
            )

    def test_health_declares_narrow_v3_and_preserves_current_chat_features(self):
        source = textwrap.dedent(inspect.getsource(WorkflowV3HTTPHandler.do_GET))
        tree = ast.parse(source)
        health_contract = None
        required_keys = {
            "workflow_execution_version",
            "workflow_execution_risk",
            "workflow_execution_trigger",
            "workflow_pause_resume",
            "workflow_persistent_checkpoint",
            "workflow_branching",
            "workflow_decision_conditions",
            "workflow_approval_conditions",
            "workflow_failure_rejection_terminal",
            "workflow_branch_joins",
            "prompt_compiler",
            "public_query_compiler",
            "public_query_final_dlp",
            "direct_chat",
            "direct_chat_public_web",
            "response_language_auto",
            "response_language_current_request_precedence",
            "response_language_validation",
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            keys = {
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
            if required_keys.issubset(keys):
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
            if isinstance(node, ast.List) and all(
                isinstance(item, ast.Constant) for item in node.elts
            ):
                return ("list", tuple(item.value for item in node.elts))
            return ("ast", ast.dump(node, include_attributes=False))

        expected = {
            "workflow_execution_version": ("constant", "v3"),
            "workflow_execution_risk": ("constant", "low_only"),
            "workflow_execution_trigger": ("constant", "manual_only"),
            "workflow_pause_resume": ("constant", True),
            "workflow_persistent_checkpoint": ("constant", True),
            "workflow_branching": ("constant", "deterministic_only"),
            "workflow_decision_conditions": ("list", ("passed", "failed")),
            "workflow_approval_conditions": ("list", ("approved", "rejected")),
            "workflow_failure_rejection_terminal": ("constant", True),
            "workflow_branch_joins": ("constant", False),
            "prompt_compiler": ("name", "PROMPT_COMPILER_VERSION"),
            "public_query_compiler": ("name", "PUBLIC_QUERY_COMPILER_VERSION"),
            "public_query_final_dlp": ("constant", True),
            "direct_chat": ("constant", True),
            "direct_chat_public_web": ("constant", False),
            "response_language_auto": ("constant", True),
            "response_language_current_request_precedence": ("constant", True),
            "response_language_validation": ("constant", True),
        }
        self.assertEqual(
            {key: signature(health_contract[key]) for key in expected},
            expected,
        )


if __name__ == "__main__":
    unittest.main()
