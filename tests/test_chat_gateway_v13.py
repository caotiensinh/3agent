from __future__ import annotations

import ast
import inspect
import textwrap
import unittest

from three_agent.chat_gateway import PromptAwareWorkflowStudioHTTPHandler
from three_agent.chat_gateway import HTML_V13, WorkflowDispatchHTTPHandler


class WorkflowDispatchGatewayTests(unittest.TestCase):
    def test_gateway_layers_on_prompt_aware_v12(self):
        self.assertTrue(
            issubclass(WorkflowDispatchHTTPHandler, PromptAwareWorkflowStudioHTTPHandler)
        )
        self.assertEqual(WorkflowDispatchHTTPHandler.server_version, "WorkSpaceChat/0.14")
        self.assertIn("Workflow Studio", HTML_V13)
        self.assertIn("/api/workflows/compile", HTML_V13)

    def test_frontend_preserves_explicit_prepare_and_authorize_boundary(self):
        self.assertIn("workflowV4PrepareBtn", HTML_V13)
        self.assertIn("workflowV4StartBtn", HTML_V13)
        self.assertIn("/api/workflows/prepare-dispatch", HTML_V13)
        self.assertIn("/execute", HTML_V13)
        self.assertIn("Type AUTHORIZE exactly", HTML_V13)
        self.assertIn("confirmation:'AUTHORIZE'", HTML_V13)
        self.assertNotIn("cdn.jsdelivr", HTML_V13)
        self.assertNotIn("unpkg.com", HTML_V13)

    def test_prepare_and_execute_are_admin_gated(self):
        prepare_source = inspect.getsource(WorkflowDispatchHTTPHandler._prepare_dispatch)
        execute_source = inspect.getsource(WorkflowDispatchHTTPHandler._execute_dispatch)
        self.assertIn("self._require_admin()", prepare_source)
        self.assertIn("self._require_admin()", execute_source)

        execute_tree = ast.parse(textwrap.dedent(execute_source))
        self.assertTrue(
            any(
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == "admin"
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "user_id"
                for node in ast.walk(execute_tree)
            )
        )

    def test_health_preserves_prompt_dlp_and_bounded_dispatch_semantically(self):
        source = textwrap.dedent(inspect.getsource(WorkflowDispatchHTTPHandler.do_GET))
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
                "workflow_execution",
                "workflow_execution_profile",
                "workflow_execution_risk",
                "workflow_execution_trigger",
                "workflow_execution_admin_approval",
                "prompt_compiler",
                "public_query_compiler",
                "public_query_final_dlp",
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
            "workflow_execution": ("constant", True),
            "workflow_execution_profile": (
                "constant",
                "workspace-fixed-analysis/v1",
            ),
            "workflow_execution_risk": ("constant", "low_only"),
            "workflow_execution_trigger": ("constant", "manual_only"),
            "workflow_execution_admin_approval": ("constant", True),
            "prompt_compiler": ("name", "PROMPT_COMPILER_VERSION"),
            "public_query_compiler": ("name", "PUBLIC_QUERY_COMPILER_VERSION"),
            "public_query_final_dlp": ("constant", True),
        }
        self.assertEqual(
            {key: signature(health_contract[key]) for key in expected},
            expected,
        )


if __name__ == "__main__":
    unittest.main()
