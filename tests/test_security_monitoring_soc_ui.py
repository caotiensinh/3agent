from __future__ import annotations

import inspect
import unittest

from three_agent import chat_gateway_v19
from three_agent.workspace_frontend_security_v2 import (
    SOC_SECURITY_JS,
    WORKSPACE_HTML_SECURITY_V2,
)


class SecurityMonitoringSOCUITests(unittest.TestCase):
    def test_soc_tab_layers_on_current_security_and_configuration_surface(self):
        for token in (
            'data-security-tab="soc"',
            'id="securitySocView"',
            "Findings",
            "Evidence",
            "Analyst assessment",
            "Configuration",
            "Administration",
            "Workflow Studio",
        ):
            self.assertIn(token, WORKSPACE_HTML_SECURITY_V2)

    def test_soc_ui_consumes_only_canonical_read_only_projection(self):
        for token in (
            "/api/security/soc",
            "risk_summary",
            "findings",
            "evidence_refs",
            "analyst_findings",
            "VERIFIED FACT",
            "INFERENCE",
            "UNKNOWN",
        ):
            self.assertIn(token, SOC_SECURITY_JS)
        for forbidden in (
            "method:'POST'",
            'method:"POST"',
            "/api/security/pcap/approve",
            "management_host",
            "credential_ref",
            "asset_refs",
            "correlation_key",
            "raw_log",
            "execute_capture",
        ):
            self.assertNotIn(forbidden, SOC_SECURITY_JS)

    def test_dynamic_soc_content_uses_text_content_not_html_injection(self):
        self.assertIn("textContent", SOC_SECURITY_JS)
        self.assertNotIn("innerHTML", SOC_SECURITY_JS)
        self.assertNotIn("insertAdjacentHTML", SOC_SECURITY_JS)

    def test_current_gateway_serves_composed_soc_ui_without_new_handler(self):
        source = inspect.getsource(chat_gateway_v19)
        self.assertIn("WORKSPACE_HTML_SECURITY_V2", source)
        self.assertIn("_v17.HTML_V17 = WORKSPACE_HTML_SECURITY_V2", source)
        self.assertNotIn('"/api/security/soc"', source)
        self.assertNotIn("build_soc_read_model", source)


if __name__ == "__main__":
    unittest.main()
