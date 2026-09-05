from __future__ import annotations

import unittest
from http import HTTPStatus
from pathlib import Path

from three_agent.config import load_config
from three_agent.secure_chat_gateway import _secure_html, workspace_ui_capabilities
from three_agent.workspace_frontend import WORKSPACE_HTML


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_RESEARCH_PROFILE = ROOT / "config" / "local.public-research.example.json"


class SecureFrontendBackendBridgeTests(unittest.TestCase):
    def test_canonical_frontend_uses_native_secure_backend_bridge(self) -> None:
        html = _secure_html(WORKSPACE_HTML)

        self.assertIn("workspaceSecureBackendBridge", html)
        self.assertIn("workspaceInternetEgressConsent", html)
        self.assertIn("INTERNET_EGRESS_CONSENT_REQUIRED", html)
        self.assertIn("body[tokenField]=data.consent_token", html)
        self.assertIn("mode:state.requestMode", html)
        self.assertIn("/api/chat", html)
        self.assertIn("/api/jobs/", html)
        self.assertNotIn("window.fetch=", html)
        self.assertEqual(html.count("workspaceInternetEgressConsent"), 1)
        self.assertEqual(_secure_html(html), html)

    def test_capabilities_publish_exact_frontend_backend_contract(self) -> None:
        config = load_config(str(PUBLIC_RESEARCH_PROFILE))
        capabilities = workspace_ui_capabilities(config)
        bridge = capabilities["frontend_backend_bridge"]

        self.assertEqual(
            bridge["schema_version"],
            "workspace.frontend-backend-bridge/v1",
        )
        self.assertEqual(bridge["capabilities_endpoint"], "/api/capabilities")
        self.assertEqual(bridge["chat_endpoint"], "/api/chat")
        self.assertEqual(bridge["job_endpoint_template"], "/api/jobs/{job_id}")
        self.assertEqual(bridge["request_mode_field"], "mode")
        self.assertEqual(bridge["consent_token_field"], "egress_consent_token")
        self.assertEqual(bridge["consent_required_status"], HTTPStatus.CONFLICT)
        self.assertEqual(bridge["blocked_status"], HTTPStatus.UNPROCESSABLE_ENTITY)
        self.assertTrue(bridge["poll_jobs"])
        self.assertFalse(bridge["raw_prompt_public_egress"])
        self.assertFalse(bridge["uploads_public_egress"])

        web = capabilities["features"]["web_search"]
        self.assertTrue(web["enabled"])
        self.assertEqual(web["egress_boundary"], "sanitized_public_query_only")
        self.assertFalse(web["raw_prompt_public_egress"])
        self.assertFalse(web["upload_content_public_egress"])


if __name__ == "__main__":
    unittest.main()
