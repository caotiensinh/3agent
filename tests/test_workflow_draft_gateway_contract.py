from __future__ import annotations

import inspect

from three_agent import chat_gateway_v20
from three_agent.chat_gateway_v19 import SecurityMonitoringConfigApplication, SecurityMonitoringConfigHTTPHandler


def test_v20_is_additive_on_hardened_v19_boundary():
    assert issubclass(chat_gateway_v20.WorkflowDraftApplication, SecurityMonitoringConfigApplication)
    assert issubclass(chat_gateway_v20.WorkflowDraftHTTPHandler, SecurityMonitoringConfigHTTPHandler)


def test_draft_mutation_boundary_has_no_execution_controller_calls():
    source = inspect.getsource(chat_gateway_v20.WorkflowDraftHTTPHandler)
    for forbidden in (
        ".workflow_v4.prepare(",
        ".workflow_v4.start(",
        ".workflow_v4.decide_checkpoint(",
        ".workflow_v3.prepare(",
        ".workflow_v3.start(",
        ".workflow_dispatch.execute(",
        ".dispatch(",
    ):
        assert forbidden not in source
    assert "execution_authorized" in source
    assert "design_only" in source


def test_draft_routes_are_authenticated_owner_scoped():
    source = inspect.getsource(chat_gateway_v20.WorkflowDraftHTTPHandler)
    assert "/api/workflows/drafts" in source
    assert "self._authorized_local()" in source
    assert "self._owner_key()" in source
    assert "WORKFLOW_DRAFT_CONFLICT" in source
