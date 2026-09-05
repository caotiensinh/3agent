from __future__ import annotations

import inspect
import unittest

from three_agent import chat_gateway
from three_agent.chat_gateway import SecurityMonitoringConfigApplication, SecurityMonitoringConfigHTTPHandler


class WorkflowDraftGatewayContractTests(unittest.TestCase):
    def test_v20_is_additive_on_hardened_v19_boundary(self) -> None:
        self.assertTrue(issubclass(chat_gateway.WorkflowDraftApplication, SecurityMonitoringConfigApplication))
        self.assertTrue(issubclass(chat_gateway.WorkflowDraftHTTPHandler, SecurityMonitoringConfigHTTPHandler))

    def test_draft_mutation_boundary_has_no_execution_controller_calls(self) -> None:
        source = inspect.getsource(chat_gateway.WorkflowDraftHTTPHandler)
        for forbidden in (
            ".workflow_v4.prepare(",
            ".workflow_v4.start(",
            ".workflow_v4.decide_checkpoint(",
            ".workflow_v3.prepare(",
            ".workflow_v3.start(",
            ".workflow_dispatch.execute(",
            ".dispatch(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("execution_authorized", source)
        self.assertIn("design_only", source)

    def test_draft_routes_are_authenticated_owner_scoped(self) -> None:
        source = inspect.getsource(chat_gateway.WorkflowDraftHTTPHandler)
        self.assertIn("/api/workflows/drafts", source)
        self.assertIn("self._authorized_local()", source)
        self.assertIn("self._owner_key()", source)
        self.assertIn("WORKFLOW_DRAFT_CONFLICT", source)


if __name__ == "__main__":
    unittest.main()
