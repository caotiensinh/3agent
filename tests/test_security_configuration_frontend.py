from __future__ import annotations

import inspect
import unittest

from three_agent import chat_gateway_v18
from three_agent.workspace_frontend_v15 import WORKSPACE_HTML_V15


class SecurityConfigurationFrontendTests(unittest.TestCase):
    def test_configuration_center_is_exposed_in_admin_surface(self) -> None:
        for text in (
            "Security Configuration Center",
            "Configure Security Monitoring",
            "Approved Assets",
            "Monitoring Policy",
            "Configuration Audit",
            "ENABLE_APPROVED_REAL_NETWORK_MONITORING",
        ):
            self.assertIn(text, WORKSPACE_HTML_V15)

    def test_configuration_center_contains_no_raw_secret_input(self) -> None:
        self.assertNotIn('type="password" id="securityCfg', WORKSPACE_HTML_V15)
        self.assertIn("credential reference", WORKSPACE_HTML_V15.lower())
        self.assertIn("raw credentials", WORKSPACE_HTML_V15.lower())

    def test_gateway_config_routes_are_admin_bounded(self) -> None:
        source = inspect.getsource(chat_gateway_v18.SecurityMonitoringHTTPHandler)
        self.assertIn('"/api/security/config"', source)
        self.assertIn('"/api/security/config/audit"', source)
        self.assertIn("self._require_admin()", source)
        self.assertIn("SecurityConfigurationStore", inspect.getsource(chat_gateway_v18.SecurityMonitoringApplication))

    def test_save_does_not_add_network_execution_route(self) -> None:
        source = inspect.getsource(chat_gateway_v18.SecurityMonitoringHTTPHandler._security_config_save)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("capture", source.lower())
        self.assertIn("SecurityMonitoringUIReadModel.from_environment", source)


if __name__ == "__main__":
    unittest.main()
