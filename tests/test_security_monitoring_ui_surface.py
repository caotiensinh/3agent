from __future__ import annotations

import inspect
import unittest

from three_agent import workspace_frontend_v13
from three_agent.workspace_frontend_v13 import WORKSPACE_HTML_V13


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
            self.assertIn(token, WORKSPACE_HTML_V13)

    def test_surface_is_lightweight_and_preserves_existing_chat_workflow_ui(self):
        for preserved in (
            "New chat",
            "Search chats",
            "Projects",
            "Workflow Studio",
            "workflowV4PrepareBtn",
        ):
            self.assertIn(preserved, WORKSPACE_HTML_V13)
        for forbidden in (
            "cdn.jsdelivr",
            "unpkg.com",
            "React.createElement",
            "node_modules",
            "new WebSocket",
        ):
            self.assertNotIn(forbidden, WORKSPACE_HTML_V13)

    def test_badge_is_aggregate_only_and_polling_is_visibility_aware(self):
        source = inspect.getsource(workspace_frontend_v13)
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

    def test_security_surface_exposes_no_mutation_action(self):
        source = inspect.getsource(workspace_frontend_v13)
        self.assertNotIn("/api/security/", source.replace("/api/security/summary", "").replace("/api/security/findings", "").replace("/api/security/network", "").replace("/api/security/events", "").replace("/api/security/assets", "").replace("/api/security/reports", "").replace("/api/security/admin", ""))
        for forbidden in (
            "remediate",
            "packet-capture",
            "start-pcap",
            "policy-update",
            "asset-update",
        ):
            self.assertNotIn(forbidden, source.lower())


if __name__ == "__main__":
    unittest.main()
