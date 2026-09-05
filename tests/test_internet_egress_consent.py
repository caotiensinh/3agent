from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.config import load_config
from three_agent.internet_egress_consent import (
    InternetEgressBlocked,
    InternetEgressConsentGuard,
    InternetEgressConsentRequired,
    preflight_public_egress,
    strict_public_search_query,
)
from three_agent.privacy import OutboundDLPError, SENSITIVITY_PUBLIC
from three_agent.secure_chat_gateway import (
    _CONSENT_SCRIPT,
    _requires_public_egress,
    _secure_html,
    workspace_ui_capabilities,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "config" / "local.public-research.example.json"


class InternetEgressConsentTests(unittest.TestCase):
    def test_public_query_is_allowed_without_consent(self):
        preflight = preflight_public_egress("Hikvision DS-2CD firmware release notes")

        self.assertEqual(preflight.state, "allow")
        self.assertEqual(preflight.sensitivity, SENSITIVITY_PUBLIC)
        self.assertFalse(preflight.warning_required)
        self.assertEqual(
            strict_public_search_query(preflight.sanitized_query),
            "Hikvision DS-2CD firmware release notes",
        )

    def test_password_username_and_private_ip_require_consent(self):
        raw = (
            "Find Hikvision DS-2CD troubleshooting information "
            "username=admin password=SuperSecret123! 192.168.11.196"
        )
        preflight = preflight_public_egress(raw)

        self.assertEqual(preflight.state, "consent_required")
        self.assertTrue(preflight.warning_required)
        self.assertGreaterEqual(preflight.removed_sensitive_fields, 2)
        self.assertNotIn("admin", preflight.sanitized_query)
        self.assertNotIn("SuperSecret123", preflight.sanitized_query)
        self.assertNotIn("192.168.11.196", preflight.sanitized_query)
        self.assertIn("Hikvision", preflight.sanitized_query)

    def test_labeled_id_is_removed_and_requires_consent(self):
        preflight = preflight_public_egress(
            "Search camera authentication issue user_id=EMP-001 device_id=CAM-00026 Hikvision"
        )

        self.assertEqual(preflight.state, "consent_required")
        self.assertIn("labeled_identifier", preflight.reasons)
        self.assertNotIn("EMP-001", preflight.sanitized_query)
        self.assertNotIn("CAM-00026", preflight.sanitized_query)
        self.assertIn("Hikvision", preflight.sanitized_query)

    def test_sensitive_raw_query_is_never_accepted_by_final_outbound_gate(self):
        with self.assertRaises(OutboundDLPError):
            strict_public_search_query(
                "Hikvision password=SuperSecret123 username=admin troubleshooting"
            )

    def test_consent_token_is_bound_to_exact_sender_prompt_mode_and_format(self):
        guard = InternetEgressConsentGuard(secret=b"x" * 32)
        raw = "Search Hikvision login issue username=admin password=Secret123!"
        preflight = guard.preflight(raw)
        token = guard.issue(
            preflight,
            sender="workspace-user:usr_aaaaaaaa",
            mode="web_search",
            output_format="source",
        )

        safe = guard.authorize(
            raw,
            sender="workspace-user:usr_aaaaaaaa",
            mode="web_search",
            output_format="source",
            consent_token=token,
        )
        self.assertNotIn("admin", safe)
        self.assertNotIn("Secret123", safe)

        with self.assertRaises(InternetEgressConsentRequired):
            guard.authorize(
                raw + " extra",
                sender="workspace-user:usr_aaaaaaaa",
                mode="web_search",
                output_format="source",
                consent_token=token,
            )
        with self.assertRaises(InternetEgressConsentRequired):
            guard.authorize(
                raw,
                sender="workspace-user:usr_bbbbbbbb",
                mode="web_search",
                output_format="source",
                consent_token=token,
            )

    def test_consent_token_expires_fail_closed(self):
        clock = [1000.0]
        guard = InternetEgressConsentGuard(
            ttl_seconds=30,
            secret=b"y" * 32,
            now=lambda: clock[0],
        )
        raw = "Search ONVIF issue username=operator password=Secret123!"
        preflight = guard.preflight(raw)
        token = guard.issue(
            preflight,
            sender="workspace-user:usr_aaaaaaaa",
            mode="web_search",
            output_format="source",
        )
        clock[0] = 1031.0

        with self.assertRaises(InternetEgressConsentRequired):
            guard.authorize(
                raw,
                sender="workspace-user:usr_aaaaaaaa",
                mode="web_search",
                output_format="source",
                consent_token=token,
            )

    def test_request_with_only_sensitive_material_is_blocked(self):
        guard = InternetEgressConsentGuard(secret=b"z" * 32)
        with self.assertRaises(InternetEgressBlocked):
            guard.authorize(
                "username=admin password=Secret123! user_id=EMP-001",
                sender="workspace-user:usr_aaaaaaaa",
                mode="web_search",
                output_format="source",
            )

    def test_direct_chat_stays_local_but_research_and_artifacts_require_egress_gate(self):
        self.assertFalse(_requires_public_egress("chat", "source"))
        self.assertTrue(_requires_public_egress("web_search", "source"))
        self.assertTrue(_requires_public_egress("deep_research", "source"))
        self.assertTrue(_requires_public_egress("chat", "pptx"))
        self.assertTrue(_requires_public_egress("chat", "pdf"))
        self.assertTrue(_requires_public_egress("chat", "all"))

    def test_capability_contract_marks_uploads_lan_only_and_search_sanitized_only(self):
        config = load_config(str(DEFAULT_PROFILE))
        capabilities = workspace_ui_capabilities(config)
        upload = capabilities["features"]["upload"]
        search = capabilities["features"]["web_search"]

        self.assertEqual(upload["data_boundary"], "lan_only")
        self.assertFalse(upload["raw_content_public_egress"])
        self.assertFalse(upload["public_query_derivation_from_uploads"])
        self.assertEqual(search["egress_boundary"], "sanitized_public_query_only")
        self.assertFalse(search["raw_prompt_public_egress"])
        self.assertFalse(search["upload_content_public_egress"])
        self.assertEqual(
            search["sensitive_prompt_behavior"],
            "block_warn_require_consent_then_sanitize",
        )

    def test_browser_consent_interceptor_states_nothing_was_sent_and_retries_with_token(self):
        html = _secure_html("<html><body><script>window.app=true</script></body></html>")

        self.assertIn("workspaceInternetEgressConsent", html)
        self.assertIn("Nothing has been sent to the Internet", html)
        self.assertIn("Uploaded files remain inside the LAN", html)
        self.assertIn("egress_consent_token", html)
        self.assertEqual(html.count("workspaceInternetEgressConsent"), 1)
        self.assertEqual(_secure_html(html), html)
        self.assertIn("INTERNET_EGRESS_CONSENT_REQUIRED", _CONSENT_SCRIPT)

    def test_console_chat_entrypoints_use_secure_gateway(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('workspace-chat = "three_agent.secure_chat_gateway:main"', pyproject)
        self.assertIn('three-agent-chat = "three_agent.secure_chat_gateway:main"', pyproject)


if __name__ == "__main__":
    unittest.main()
