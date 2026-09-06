from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class _UnexpectedFailureService:
    def run_hourly(self, *, execute_readonly: bool = False) -> dict[str, object]:
        if execute_readonly is not True:
            raise AssertionError("run-hourly must preserve explicit read-only execution")
        raise ValueError("sensitive-run-detail")

    def initialize(self) -> dict[str, object]:
        raise LookupError("sensitive-initialize-detail")


class SecurityConsolePostErrorBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.csrf = "a" * 64
        self.server = build_server(
            "127.0.0.1",
            0,
            _UnexpectedFailureService(),  # type: ignore[arg-type]
            csrf_token=self.csrf,
            csp_nonce="b" * 32,
            demo_mode=False,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _post(self, path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
        body = json.dumps(payload).encode("utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Workspace-CSRF": self.csrf,
            },
        )
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        status = response.status
        conn.close()
        return status, json.loads(raw)

    def test_run_hourly_unexpected_failure_returns_bounded_internal_error(self) -> None:
        status, payload = self._post(
            "/api/v1/security/monitoring/run-hourly",
            {"confirm_readonly": True},
        )
        self.assertEqual(status, 500)
        self.assertEqual(payload, {"status": "error", "reason_code": "INTERNAL_ERROR"})
        self.assertNotIn("ValueError", json.dumps(payload))
        self.assertNotIn("sensitive-run-detail", json.dumps(payload))

    def test_initialize_unexpected_failure_returns_bounded_internal_error(self) -> None:
        status, payload = self._post(
            "/api/v1/security/monitoring/initialize",
            {"confirm_initialize": True},
        )
        self.assertEqual(status, 500)
        self.assertEqual(payload, {"status": "error", "reason_code": "INTERNAL_ERROR"})
        self.assertNotIn("LookupError", json.dumps(payload))
        self.assertNotIn("sensitive-initialize-detail", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
