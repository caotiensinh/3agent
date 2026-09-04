from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from three_agent.chat_gateway_v14 import IntentAwareWorkflowDispatchHTTPHandler
from three_agent.chat_gateway_v15 import WorkflowV3Application, WorkflowV3HTTPHandler
from three_agent.version import PACKAGE_VERSION


class ChatGatewayV15ContractTests(unittest.TestCase):
    def test_v14_security_and_workflow_chain_is_preserved(self) -> None:
        self.assertTrue(
            issubclass(WorkflowV3HTTPHandler, IntentAwareWorkflowDispatchHTTPHandler)
        )
        self.assertEqual(WorkflowV3HTTPHandler.server_version, "WorkSpaceChat/0.16")
        self.assertTrue(callable(WorkflowV3Application))
        for method_name in (
            "_prepare_dispatch",
            "_execute_dispatch",
            "_checkpoint",
            "_workflow_state",
        ):
            self.assertTrue(callable(getattr(WorkflowV3HTTPHandler, method_name)))

    def test_workflow_v3_contract_is_bounded_and_admin_gated(self) -> None:
        health_source = inspect.getsource(WorkflowV3HTTPHandler.do_GET)
        for token in (
            '"workflow_execution_version": "v3"',
            '"workflow_execution_risk": "low_only"',
            '"workflow_execution_trigger": "manual_only"',
            '"workflow_execution_admin_approval": True',
            '"workflow_pause_resume": True',
            '"workflow_persistent_checkpoint": True',
            '"workflow_branching": "deterministic_only"',
            '"workflow_failure_rejection_terminal": True',
            '"workflow_branch_joins": False',
            '"direct_chat": True',
            '"response_language_current_request_precedence": True',
        ):
            self.assertIn(token, health_source)

        for method in (
            WorkflowV3HTTPHandler._prepare_dispatch,
            WorkflowV3HTTPHandler._execute_dispatch,
            WorkflowV3HTTPHandler._checkpoint,
            WorkflowV3HTTPHandler._workflow_state,
        ):
            self.assertIn("self._require_admin()", inspect.getsource(method))

    def test_package_entrypoints_use_current_chat_gateway(self) -> None:
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
        self.assertIn(f'version = "{PACKAGE_VERSION}"', pyproject)
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v22:main"', pyproject)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v22:main"', pyproject)
        self.assertIn('workspace-chat-acceptance = "three_agent.chat_acceptance:main"', pyproject)
        self.assertIn(
            'workspace-chat-multiturn-acceptance = "three_agent.chat_multiturn_acceptance:main"',
            pyproject,
        )

    def test_v14_remains_importable_as_rollback_boundary(self) -> None:
        self.assertEqual(
            IntentAwareWorkflowDispatchHTTPHandler.server_version,
            "WorkSpaceChat/0.15",
        )
        self.assertTrue(callable(IntentAwareWorkflowDispatchHTTPHandler._execute_dispatch))


if __name__ == "__main__":
    unittest.main()
