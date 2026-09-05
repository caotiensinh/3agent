from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from three_agent.chat_gateway_v22 import (
    READONLY_MONITORING_ACTION_HEADER,
    READONLY_MONITORING_CONFIRMATION,
    SecurityActionHTTPHandler,
    _runtime_block_code,
)
from three_agent.workspace_frontend_security_actions_v1 import (
    WORKSPACE_HTML_SECURITY_ACTIONS_V1,
)


ROOT = Path(__file__).resolve().parents[1]


class SecurityMonitoringUIRunActionTests(unittest.TestCase):
    def test_current_frontend_exposes_explicit_admin_readonly_action(self) -> None:
        html = WORKSPACE_HTML_SECURITY_ACTIONS_V1
        for token in (
            'id="securityRunReadonly"',
            "/api/security/monitoring/run-readonly",
            "RUN_READONLY_MONITORING",
            "security-readonly-monitoring",
            "Run read-only monitoring",
        ):
            self.assertIn(token, html)
        for forbidden in (
            "management_host",
            "credential_ref",
            "tcpdump",
            "subprocess",
        ):
            self.assertNotIn(forbidden, html)

    def test_gateway_requires_admin_header_exact_payload_and_server_config_scope(self) -> None:
        source = inspect.getsource(SecurityActionHTTPHandler._security_run_readonly)
        self.assertIn("self._require_admin()", source)
        self.assertIn("X-Workspace-Action", source)
        self.assertIn('set(payload) != {"confirmation"}', source)
        self.assertIn("config_path.is_absolute()", source)
        self.assertIn("config_path.is_symlink()", source)
        self.assertIn("config_path.is_file()", source)
        self.assertIn("SecurityMonitoringService(config_path).run_hourly(execute_readonly=True)", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("tcpdump", source)
        self.assertNotIn("shell", source)

    def test_post_route_is_narrow_and_falls_through_to_existing_gateway(self) -> None:
        source = inspect.getsource(SecurityActionHTTPHandler.do_POST)
        self.assertIn('/api/security/monitoring/run-readonly', source)
        self.assertIn("_security_run_readonly", source)
        self.assertIn("super().do_POST()", source)

    def test_confirmation_constants_are_fixed(self) -> None:
        self.assertEqual(READONLY_MONITORING_CONFIRMATION, "RUN_READONLY_MONITORING")
        self.assertEqual(READONLY_MONITORING_ACTION_HEADER, "security-readonly-monitoring")

    def test_runtime_errors_are_reduced_to_bounded_codes(self) -> None:
        self.assertEqual(_runtime_block_code(RuntimeError("MONITORING_DISABLED")), "MONITORING_DISABLED")
        self.assertEqual(
            _runtime_block_code(RuntimeError("MONITORING_READINESS_BLOCKED:SECRET_REF_UNRESOLVED")),
            "MONITORING_READINESS_BLOCKED",
        )
        self.assertEqual(
            _runtime_block_code(RuntimeError("sensitive internal detail")),
            "SECURITY_MONITORING_RUN_BLOCKED",
        )

    def test_packaged_chat_entrypoints_use_v22_and_parallel_local_ui_is_absent(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v22:main"', text)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v22:main"', text)
        self.assertNotIn("workspace-security-ui", text)


if __name__ == "__main__":
    unittest.main()
