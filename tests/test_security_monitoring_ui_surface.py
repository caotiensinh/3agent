from __future__ import annotations

import inspect
import unittest

from three_agent import workspace_frontend_security, workspace_frontend_v14
from three_agent.workspace_frontend_v14 import WORKSPACE_HTML_V14


class SecurityAnalystUISurfaceTests(unittest.TestCase):
    def test_specialized_sidebar_and_all_v1_views_are_present(self):
        for token in (
            "SPECIALIZED",
            'id="securityAnalystBtn"',
            "Security Analyst",
            'data-security-tab="overview"',
            'data-security-tab="network"',
            'data-security-tab="findings"',
            'data-security-tab="events"',
            'data-security-tab="assets"',
            'data-security-tab="reports"',
            'data-security-tab="admin"',
        ):
            self.assertIn(token, WORKSPACE_HTML_V14)

    def test_surface_preserves_current_chat_and_connector_ui(self):
        for preserved in (
            "New chat",
            "Search chats",
            "Projects",
            "Workflow Studio",
            "workflowV4PrepareBtn",
            "Figma",
            "Canva",
            "Gmail",
            "workspaceSenderMark",
        ):
            self.assertIn(preserved, WORKSPACE_HTML_V14)
        for forbidden in (
            "cdn.jsdelivr",
            "unpkg.com",
            "React.createElement",
            "node_modules",
            "new WebSocket",
        ):
            self.assertNotIn(forbidden, WORKSPACE_HTML_V14)

    def test_badge_is_aggregate_only_and_polling_is_visibility_aware(self):
        source = inspect.getsource(workspace_frontend_security)
        self.assertIn("document.visibilityState==='visible'", source)
        self.assertIn("setInterval", source)
        self.assertIn("30000", source)
        self.assertIn("summary.high_critical_count", source)
        self.assertIn("summary.health", source)
        for forbidden in (
            "management_host",
            "credential_ref",
            "correlation_key",
            "message_sha256",
            "bundle_ref",
            "raw_log",
        ):
            self.assertNotIn(forbidden, source)

    def test_security_surface_exposes_no_network_mutation_action(self):
        source = inspect.getsource(workspace_frontend_security)
        for forbidden in (
            "remediate",
            "packet-capture",
            "start-pcap",
            "policy-update",
            "asset-update",
        ):
            self.assertNotIn(forbidden, source.lower())
        # V14 is composition-only; it must not add a second security execution path.
        composed = inspect.getsource(workspace_frontend_v14)
        self.assertNotIn("/api/security/pcap/approve", composed)
        self.assertNotIn("fetch('/api/security/", composed)


if __name__ == "__main__":
    unittest.main()
