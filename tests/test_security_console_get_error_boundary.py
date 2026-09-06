from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class SecurityConsoleGetErrorBoundaryTests(unittest.TestCase):
    def test_unexpected_get_failure_returns_fixed_internal_error(self) -> None:
        class SensitiveBackendFailure(Exception):
            pass

        sensitive_message = "/srv/workspace/private/customer-a/internal.db"

        class FailingService:
            def summary(self) -> dict[str, object]:
                raise SensitiveBackendFailure(sensitive_message)

        server = build_server(
            "127.0.0.1",
            0,
            FailingService(),  # type: ignore[arg-type]
            csrf_token="a" * 64,
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
            raw = response.read().decode("utf-8")
            payload = json.loads(raw)
            status = response.status
            conn.close()

            self.assertEqual(status, 500)
            self.assertEqual(
                payload,
                {"status": "error", "reason_code": "INTERNAL_ERROR"},
            )
            self.assertNotIn("SensitiveBackendFailure", raw)
            self.assertNotIn(sensitive_message, raw)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
