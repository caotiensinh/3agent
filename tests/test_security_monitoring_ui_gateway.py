from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway_v17 import (
    HTML_V17,
    WorkflowV4ContextApplication,
    WorkflowV4ContextHTTPHandler,
)
from three_agent.security_monitoring.ui_read_model import SecurityMonitoringUIReadModel


class SecurityMonitoringUIGatewayTests(unittest.TestCase):
    def test_product_html_uses_security_surface_without_regressing_chat_or_workflow(self):
        for token in (
            'id="securityAnalystBtn"',
            "SPECIALIZED",
            "Security Analyst",
            "Workflow Studio",
            "workflowV4PrepareBtn",
            "New chat",
        ):
            self.assertIn(token, HTML_V17)

    def test_application_initializes_one_query_only_read_model_from_explicit_environment(self):
        source = inspect.getsource(WorkflowV4ContextApplication.__init__)
        self.assertIn(
            "self.security_monitoring = SecurityMonitoringUIReadModel.from_environment()",
            source,
        )
        self.assertNotIn("MonitoringStore(", source)
        self.assertTrue(hasattr(SecurityMonitoringUIReadModel, "summary"))
        self.assertFalse(hasattr(SecurityMonitoringUIReadModel, "add_event"))
        self.assertFalse(hasattr(SecurityMonitoringUIReadModel, "add_finding"))

    def test_all_security_routes_are_get_only_and_authenticated(self):
        source = inspect.getsource(WorkflowV4ContextHTTPHandler.do_GET)
        for route in (
            "/api/security/summary",
            "/api/security/network",
            "/api/security/findings",
            "/api/security/events",
            "/api/security/assets",
            "/api/security/reports",
            "/api/security/admin",
        ):
            self.assertIn(route, source)
        helper = inspect.getsource(WorkflowV4ContextHTTPHandler._security_get)
        self.assertIn("self._authorized_local()", helper)
        self.assertIn("self._require_admin()", helper)
        self.assertIn('admin_only = view == "admin"', helper)
        self.assertNotIn("management_host", helper)
        self.assertNotIn("credential_ref", helper)
        self.assertNotIn("raw_log", helper)

        # v17 adds no POST implementation at all; existing inherited mutation paths
        # remain Workflow-only and no /api/security mutation route can be introduced.
        self.assertNotIn("do_POST", WorkflowV4ContextHTTPHandler.__dict__)

    def test_bad_query_and_storage_errors_are_generic_not_raw_exception_echoes(self):
        helper = inspect.getsource(WorkflowV4ContextHTTPHandler._security_get)
        self.assertIn("SECURITY_QUERY_INVALID", helper)
        self.assertIn("SECURITY_DATA_UNAVAILABLE", helper)
        self.assertNotIn("redact_sensitive_text(str(exc))", helper)
        self.assertNotIn("repr(exc)", helper)

    def test_health_contract_declares_read_only_visibility_aware_surface(self):
        source = inspect.getsource(WorkflowV4ContextHTTPHandler.do_GET)
        for token in (
            '"security_analyst": True',
            '"security_analyst_read_only": True',
            '"security_analyst_mutations": False',
            '"security_analyst_websocket": False',
            '"security_analyst_polling": "visibility_aware"',
        ):
            self.assertIn(token, source)


if __name__ == "__main__":
    unittest.main()
