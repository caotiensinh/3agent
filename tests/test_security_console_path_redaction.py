from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class SecurityConsolePathRedactionTests(unittest.TestCase):
    def test_browser_summary_and_initialize_redact_internal_database_path(self) -> None:
        sensitive_path = "/srv/workspace/private/customer-a/security-monitoring"

        class PathAwareService:
            def summary(self) -> dict[str, object]:
                return {
                    "status": "valid",
                    "enabled": True,
                    "database_parent": sensitive_path,
                }

            def initialize(self) -> dict[str, object]:
                return {
                    "status": "initialized",
                    "enabled_asset_count": 2,
                    "database_parent": sensitive_path,
                }

        service = PathAwareService()
        self.assertEqual(service.summary()["database_parent"], sensitive_path)
        self.assertEqual(service.initialize()["database_parent"], sensitive_path)

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
            self.assertNotIn("database_parent", summary)
            self.assertNotIn(sensitive_path, summary_raw)

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
            self.assertNotIn(sensitive_path, initialize_raw)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
