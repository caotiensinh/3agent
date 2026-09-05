from __future__ import annotations

import unittest

from three_agent import chat_gateway
from three_agent.workspace_frontend_security import (
    SECURITY_BOUNDARY_MARKUP,
    WORKSPACE_HTML_SECURITY_V3,
)


class SecurityMonitoringSOCBoundaryUITests(unittest.TestCase):
    def test_explicit_not_implemented_boundary_view_is_present(self):
        for token in (
            'data-security-tab="boundaries"',
            'id="securityBoundaryView"',
            "Not Implemented — Authority Boundaries",
            "Autonomous network discovery",
            "Autonomous active scan",
            "Automatic firewall or block action",
            "AI-triggered packet capture",
            "Shell or network command execution",
            "Autonomous remediation",
        ):
            self.assertIn(token, WORKSPACE_HTML_SECURITY_V3)
        self.assertEqual(SECURITY_BOUNDARY_MARKUP.count("NOT IMPLEMENTED"), 6)

    def test_boundary_view_is_static_and_cannot_mint_execution_authority(self):
        for forbidden in (
            "<button",
            "<input",
            "<form",
            "fetch(",
            "api(",
            "XMLHttpRequest",
            "WebSocket",
            "/api/",
            "onclick",
        ):
            self.assertNotIn(forbidden, SECURITY_BOUNDARY_MARKUP)

    def test_current_product_preserves_soc_configuration_and_admin_surfaces(self):
        for token in (
            'data-security-tab="soc"',
            'data-security-tab="boundaries"',
            "Configuration",
            "Administration",
            "/api/security/soc",
            "Workflow Studio",
        ):
            self.assertIn(token, WORKSPACE_HTML_SECURITY_V3)

    def test_gateway_serves_canonical_security_ui(self):
        self.assertEqual(chat_gateway.HTML_V17, WORKSPACE_HTML_SECURITY_V3)
        self.assertIn('data-security-tab="boundaries"', chat_gateway.HTML_V17)


if __name__ == "__main__":
    unittest.main()
