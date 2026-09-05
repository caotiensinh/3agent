from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server, validate_loopback_host


class _FakeService:
    def __init__(self) -> None:
        self.run_calls = 0

    def summary(self) -> dict[str, object]:
        return {
            "enabled": True,
            "allow_real_network": True,
            "enabled_asset_count": 2,
            "contains_raw_credentials": False,
        }

    def readiness(self) -> dict[str, object]:
        return {
            "ready": True,
            "issues": [],
            "warnings": [],
            "network_test_executed": False,
            "secret_values_read": False,
            "packet_capture_executed": False,
            "remediation_executed": False,
        }

    def run_hourly(self, *, execute_readonly: bool) -> dict[str, object]:
        if not execute_readonly:
            raise AssertionError("console must only request explicit read-only execution")
        self.run_calls += 1
        return {
            "status": "completed",
            "failure_codes": [],
            "execute_mode": "readonly",
        }


class SecurityLocalConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = _FakeService()
        self.csrf = "a" * 64
        self.server = build_server(
            "127.0.0.1",
            0,
            self.service,  # type: ignore[arg-type]
            csrf_token=self.csrf,
            csp_nonce="b" * 32,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object] | str, dict[str, str]]:
        body = None
        request_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        raw = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        content_type = response_headers.get("content-type", "")
        if content_type.startswith("application/json"):
            decoded: dict[str, object] | str = json.loads(raw.decode("utf-8"))
        else:
            decoded = raw.decode("utf-8")
        status = response.status
        conn.close()
        return status, decoded, response_headers

    def test_health_is_local_readonly_surface(self) -> None:
        status, payload, headers = self.request("GET", "/api/v1/health")
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, dict)
        assert isinstance(payload, dict)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["local_only"])
        self.assertFalse(payload["write_authority"])
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["x-frame-options"], "DENY")

    def test_summary_and_readiness_are_connected_to_service(self) -> None:
        status, summary, _ = self.request(
            "GET", "/api/v1/security/monitoring/summary"
        )
        self.assertEqual(status, 200)
        assert isinstance(summary, dict)
        self.assertEqual(summary["enabled_asset_count"], 2)

        status, readiness, _ = self.request(
            "GET", "/api/v1/security/monitoring/readiness"
        )
        self.assertEqual(status, 200)
        assert isinstance(readiness, dict)
        self.assertTrue(readiness["ready"])
        self.assertFalse(readiness["packet_capture_executed"])
        self.assertFalse(readiness["remediation_executed"])

    def test_readonly_execution_requires_csrf_and_explicit_confirmation(self) -> None:
        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": True},
        )
        self.assertEqual(status, 403)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "CSRF_TOKEN_REQUIRED")
        self.assertEqual(self.service.run_calls, 0)

        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": False},
            headers={"X-Workspace-CSRF": self.csrf},
        )
        self.assertEqual(status, 409)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "USER_CONFIRMATION_REQUIRED")
        self.assertEqual(self.service.run_calls, 0)

        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": True},
            headers={"X-Workspace-CSRF": self.csrf},
        )
        self.assertEqual(status, 200)
        assert isinstance(payload, dict)
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(self.service.run_calls, 1)

    def test_browser_request_cannot_add_path_target_or_command_fields(self) -> None:
        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": True, "target": "192.0.2.10"},
            headers={"X-Workspace-CSRF": self.csrf},
        )
        self.assertEqual(status, 400)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "UNSUPPORTED_REQUEST_FIELDS")
        self.assertEqual(self.service.run_calls, 0)

    def test_host_header_and_bind_address_are_loopback_only(self) -> None:
        self.assertEqual(validate_loopback_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_loopback_host("localhost"), "localhost")
        with self.assertRaisesRegex(ValueError, "SECURITY_CONSOLE_LOOPBACK_ONLY"):
            validate_loopback_host("0.0.0.0")

        status, payload, _ = self.request(
            "GET",
            "/api/v1/health",
            headers={"Host": "example.test"},
        )
        self.assertEqual(status, 421)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "LOOPBACK_HOST_REQUIRED")

    def test_root_serves_self_contained_japanese_console(self) -> None:
        status, payload, headers = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, str)
        assert isinstance(payload, str)
        self.assertIn("WorkSpace Security Console", payload)
        self.assertIn("読み取り専用監視を実行", payload)
        self.assertNotIn("__CSRF_TOKEN__", payload)
        self.assertIn("content-security-policy", headers)


if __name__ == "__main__":
    unittest.main()
