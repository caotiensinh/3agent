from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class _RuntimeFailureService:
    def __init__(self, *, run_reason: str | None = None, initialize_reason: str | None = None) -> None:
        self.run_reason = run_reason
        self.initialize_reason = initialize_reason

    def run_hourly(self, *, execute_readonly: bool = False) -> dict[str, object]:
        if execute_readonly is not True:
            raise AssertionError("run-hourly must preserve explicit read-only execution")
        if self.run_reason is not None:
            raise RuntimeError(self.run_reason)
        return {"status": "ok"}

    def initialize(self) -> dict[str, object]:
        if self.initialize_reason is not None:
            raise RuntimeError(self.initialize_reason)
        return {"status": "initialized"}


class SecurityConsoleRuntimeErrorBoundaryTests(unittest.TestCase):
    csrf = "a" * 64

    def _post(
        self,
        service: _RuntimeFailureService,
        path: str,
        payload: dict[str, object],
    ) -> tuple[int, dict[str, object], str]:
        server = build_server(
            "127.0.0.1",
            0,
            service,  # type: ignore[arg-type]
            csrf_token=self.csrf,
            csp_nonce="b" * 32,
            demo_mode=False,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            body = json.dumps(payload).encode("utf-8")
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
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
            return status, json.loads(raw), raw
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_run_hourly_unexpected_runtime_error_is_internal(self) -> None:
        sensitive = "runner failed at /srv/workspace/private/customer-a/runtime.db"
        status, payload, raw = self._post(
            _RuntimeFailureService(run_reason=sensitive),
            "/api/v1/security/monitoring/run-hourly",
            {"confirm_readonly": True},
        )
        self.assertEqual(status, 500)
        self.assertEqual(payload, {"status": "error", "reason_code": "INTERNAL_ERROR"})
        self.assertNotIn(sensitive, raw)

    def test_initialize_runtime_error_is_internal(self) -> None:
        sensitive = "sqlite failure at /srv/workspace/private/customer-a/runtime.db"
        status, payload, raw = self._post(
            _RuntimeFailureService(initialize_reason=sensitive),
            "/api/v1/security/monitoring/initialize",
            {"confirm_initialize": True},
        )
        self.assertEqual(status, 500)
        self.assertEqual(payload, {"status": "error", "reason_code": "INTERNAL_ERROR"})
        self.assertNotIn(sensitive, raw)

    def test_run_hourly_preserves_fixed_public_block_reasons(self) -> None:
        for reason in (
            "MONITORING_DISABLED",
            "REAL_NETWORK_NOT_ALLOWED_BY_CONFIG",
            "EXPLICIT_READONLY_EXECUTION_FLAG_REQUIRED",
        ):
            with self.subTest(reason=reason):
                status, payload, _ = self._post(
                    _RuntimeFailureService(run_reason=reason),
                    "/api/v1/security/monitoring/run-hourly",
                    {"confirm_readonly": True},
                )
                self.assertEqual(status, 409)
                self.assertEqual(payload, {"status": "blocked", "reason_code": reason})

    def test_run_hourly_preserves_allowlisted_readiness_reasons(self) -> None:
        reason = "MONITORING_READINESS_BLOCKED:CONFIG_NOT_SAVED,SECRET_REF_UNRESOLVED"
        status, payload, _ = self._post(
            _RuntimeFailureService(run_reason=reason),
            "/api/v1/security/monitoring/run-hourly",
            {"confirm_readonly": True},
        )
        self.assertEqual(status, 409)
        self.assertEqual(payload, {"status": "blocked", "reason_code": reason})

    def test_run_hourly_rejects_spoofed_readiness_reason(self) -> None:
        sensitive = "MONITORING_READINESS_BLOCKED:/srv/workspace/private/customer-a/runtime.db"
        status, payload, raw = self._post(
            _RuntimeFailureService(run_reason=sensitive),
            "/api/v1/security/monitoring/run-hourly",
            {"confirm_readonly": True},
        )
        self.assertEqual(status, 500)
        self.assertEqual(payload, {"status": "error", "reason_code": "INTERNAL_ERROR"})
        self.assertNotIn(sensitive, raw)


if __name__ == "__main__":
    unittest.main()
