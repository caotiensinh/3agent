from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class SecurityConsolePathRedactionTests(unittest.TestCase):
    def test_browser_summary_and_initialize_redact_internal_metadata(self) -> None:
        sensitive_path = "/srv/workspace/private/customer-a/security-monitoring"
        sensitive_profile = "prod-customer-a-monitoring"
        sensitive_fingerprint = "policy-fingerprint-private-456"

        class PathAwareService:
            def summary(self) -> dict[str, object]:
                return {
                    "status": "valid",
                    "enabled": True,
                    "allow_real_network": False,
                    "enabled_asset_count": 2,
                    "database_parent": sensitive_path,
                    "profile_id": sensitive_profile,
                    "policy_fingerprint": sensitive_fingerprint,
                }

            def initialize(self) -> dict[str, object]:
                return {
                    "status": "initialized",
                    "enabled_asset_count": 2,
                    "database_parent": sensitive_path,
                    "profile_id": sensitive_profile,
                    "policy_fingerprint": sensitive_fingerprint,
                }

        service = PathAwareService()
        for internal in (service.summary(), service.initialize()):
            internal_raw = json.dumps(internal, sort_keys=True)
            self.assertIn(sensitive_path, internal_raw)
            self.assertIn(sensitive_profile, internal_raw)
            self.assertIn(sensitive_fingerprint, internal_raw)

        csrf = "a" * 64
        server = build_server(
            "127.0.0.1",
            0,
            service,  # type: ignore[arg-type]
            csrf_token=csrf,
            csp_nonce="b" * 32,
            demo_mode=False,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=3
            )
            conn.request("GET", "/api/v1/security/monitoring/summary")
            response = conn.getresponse()
            summary_raw = response.read().decode("utf-8")
            summary = json.loads(summary_raw)
            summary_status = response.status
            conn.close()

            self.assertEqual(summary_status, 200)
            self.assertEqual(summary["status"], "valid")
            self.assertTrue(summary["enabled"])
            self.assertFalse(summary["allow_real_network"])
            self.assertEqual(summary["enabled_asset_count"], 2)
            self.assertNotIn("database_parent", summary)
            self.assertNotIn("profile_id", summary)
            self.assertNotIn("policy_fingerprint", summary)
            self.assertNotIn(sensitive_path, summary_raw)
            self.assertNotIn(sensitive_profile, summary_raw)
            self.assertNotIn(sensitive_fingerprint, summary_raw)

            initialize_body = json.dumps(
                {"confirm_initialize": True}
            ).encode("utf-8")
            conn = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=3
            )
            conn.request(
                "POST",
                "/api/v1/security/monitoring/initialize",
                body=initialize_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Workspace-CSRF": csrf,
                },
            )
            response = conn.getresponse()
            initialize_raw = response.read().decode("utf-8")
            initialized = json.loads(initialize_raw)
            initialize_status = response.status
            conn.close()

            self.assertEqual(initialize_status, 200)
            self.assertEqual(initialized["status"], "initialized")
            self.assertEqual(initialized["enabled_asset_count"], 2)
            self.assertNotIn("database_parent", initialized)
            self.assertNotIn("profile_id", initialized)
            self.assertNotIn("policy_fingerprint", initialized)
            self.assertNotIn(sensitive_path, initialize_raw)
            self.assertNotIn(sensitive_profile, initialize_raw)
            self.assertNotIn(sensitive_fingerprint, initialize_raw)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
