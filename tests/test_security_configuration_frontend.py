from __future__ import annotations

import ast
import inspect
import re
import textwrap
import unittest

from three_agent import chat_gateway
from three_agent.workspace_frontend import WORKSPACE_HTML, config_markup


def _string_constants(obj: object) -> set[str]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(obj)))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def _called_attributes(obj: object) -> set[str]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(obj)))
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


class SecurityConfigurationFrontendTests(unittest.TestCase):
    def test_configuration_center_is_exposed_in_admin_surface(self) -> None:
        for marker in (
            'id="securityConfigTab"',
            'id="securityConfigView"',
            "Monitoring &amp; safety policy",
            "Approved asset inventory",
            "Configuration audit",
            "ENABLE_APPROVED_REAL_NETWORK_MONITORING",
        ):
            self.assertIn(marker, WORKSPACE_HTML)

    def test_configuration_center_contains_no_raw_secret_input(self) -> None:
        input_markup = "\n".join(
            re.findall(r"<input\b[^>]*>", config_markup, flags=re.IGNORECASE)
        ).lower()
        for forbidden in (
            "password",
            "community_string",
            "auth_key",
            "priv_key",
            "api_key",
            "secret_value",
        ):
            self.assertNotIn(forbidden, input_markup)
        self.assertIn("only opaque secret references are stored", config_markup.lower())
        self.assertIn("rejected by the backend contract", config_markup.lower())
        self.assertIn("credential reference", WORKSPACE_HTML.lower())

    def test_gateway_config_routes_are_admin_bounded(self) -> None:
        get_routes = _string_constants(chat_gateway.SecurityMonitoringHTTPHandler.do_GET)
        post_routes = _string_constants(chat_gateway.SecurityMonitoringHTTPHandler.do_POST)
        self.assertIn("/api/security/config", get_routes)
        self.assertIn("/api/security/config/audit", get_routes)
        self.assertIn("/api/security/config", post_routes)

        for handler in (
            chat_gateway.SecurityMonitoringHTTPHandler._security_config_get,
            chat_gateway.SecurityMonitoringHTTPHandler._security_config_audit,
            chat_gateway.SecurityMonitoringHTTPHandler._security_config_save,
        ):
            with self.subTest(handler=handler.__name__):
                self.assertIn("_require_admin", _called_attributes(handler))

        self.assertIn(
            "SecurityConfigurationStore",
            inspect.getsource(chat_gateway.SecurityMonitoringApplication),
        )

    def test_save_does_not_add_network_execution_route(self) -> None:
        source = inspect.getsource(chat_gateway.SecurityMonitoringHTTPHandler._security_config_save)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("capture", source.lower())
        self.assertIn("SecurityMonitoringUIReadModel.from_environment", source)


if __name__ == "__main__":
    unittest.main()
