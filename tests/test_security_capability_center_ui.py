from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class _NoExecutionService:
    def __getattr__(self, name: str):
        raise AssertionError(f"root/capability-center routing must not call service method: {name}")


class SecurityCapabilityCenterUITests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = build_server(
            "127.0.0.1",
            0,
            _NoExecutionService(),  # type: ignore[arg-type]
            csrf_token="a" * 64,
            csp_nonce="b" * 32,
            demo_mode=True,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _get(self, path: str) -> tuple[int, str, dict[str, str]]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request("GET", path)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        conn.close()
        return status, raw, headers

    def test_root_exposes_capability_center_as_render_only_surface(self) -> None:
        status, page, headers = self._get("/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertIn("Capability Center", page)
        self.assertIn("Capability Center — Safe Activation Status", page)
        self.assertIn("capability_matrix", page)
        self.assertIn("cap-read-table", page)
        self.assertIn("cap-operations-table", page)
        self.assertIn("cap-collectors-table", page)
        self.assertIn("cap-restricted-table", page)
        self.assertIn("ACTIVE / READY", page)
        self.assertIn("Packet Capture", page)
        self.assertIn("Remediation", page)
        self.assertIn("textContent", page)
        self.assertNotIn("innerHTML", page)
        self.assertNotIn("fetch(\"/api/v1/security/monitoring/capability", page)

    def test_capability_center_does_not_create_an_execution_endpoint(self) -> None:
        status, raw, headers = self._get("/api/v1/security/monitoring/capability-center")
        self.assertEqual(status, 404)
        self.assertEqual(headers["cache-control"], "no-store")
        payload = json.loads(raw)
        self.assertEqual(payload["reason_code"], "ENDPOINT_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
