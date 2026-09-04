from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway import (
    SecurityMonitoringApplication,
    SecurityMonitoringHTTPHandler,
)
from three_agent.security_monitoring.ui_read_model import SecurityMonitoringUIReadModel
from three_agent.workspace_frontend import WORKSPACE_HTML


class SecurityMonitoringUIGatewayTests(unittest.TestCase):
    def test_product_html_uses_security_surface_without_regressing_chat_or_workflow(self):
        for token in (
            'id="securityAnalystBtn"',
            "SPECIALIZED",
            "Security Analyst",
            "Workflow Studio",
            "workflowV4PrepareBtn",
            "New chat",
            "Figma",
            "Canva",
            "Gmail",
        ):
            self.assertIn(token, WORKSPACE_HTML)

    def test_application_initializes_query_only_read_model(self):
        source = inspect.getsource(SecurityMonitoringApplication.__init__)
        self.assertIn(
            "self.security_monitoring = SecurityMonitoringUIReadModel.from_environment()",
            source,
        )
        self.assertNotIn("MonitoringStore(", source)
        self.assertTrue(hasattr(SecurityMonitoringUIReadModel, "summary"))
        self.assertFalse(hasattr(SecurityMonitoringUIReadModel, "add_event"))
        self.assertFalse(hasattr(SecurityMonitoringUIReadModel, "add_finding"))

    def test_security_visibility_routes_are_authenticated_and_query_only(self):
        source = inspect.getsource(SecurityMonitoringHTTPHandler.do_GET)
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
        helper = inspect.getsource(SecurityMonitoringHTTPHandler._security_get)
        self.assertIn("self._authorized_local()", helper)
        self.assertIn("self._require_admin()", helper)
        for forbidden in ("management_host", "credential_ref", "raw_log"):
            self.assertNotIn(forbidden, helper)

    def test_bad_query_and_storage_errors_are_generic(self):
        helper = inspect.getsource(SecurityMonitoringHTTPHandler._security_get)
        self.assertIn("SECURITY_QUERY_INVALID", helper)
        self.assertIn("SECURITY_DATA_UNAVAILABLE", helper)
        self.assertNotIn("repr(exc)", helper)
        self.assertNotIn("str(exc)", helper)

    def test_only_security_post_route_is_bounded_pcap_approval_metadata(self):
        source = inspect.getsource(SecurityMonitoringHTTPHandler.do_POST)
        self.assertIn('/api/security/pcap/approve', source)
        self.assertIn("_security_pcap_approve", source)
        self.assertNotIn("tcpdump", source)
        self.assertNotIn("subprocess", source)
        helper = inspect.getsource(SecurityMonitoringHTTPHandler._security_pcap_approve)
        self.assertIn("dedicated_runner_required", helper)
        self.assertIn("PCAP_APPROVAL_CONFIRMATION_REQUIRED", helper)
        self.assertNotIn("execute_capture", helper)


if __name__ == "__main__":
    unittest.main()
