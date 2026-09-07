from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class SecurityConsoleRunReceiptRedactionTests(unittest.TestCase):
    def test_browser_run_result_exposes_only_operational_aggregates(self) -> None:
        sensitive_receipt: dict[str, object] = {
            "run_id": "run-secret-router-01",
            "slot_key": "hourly:secret-profile:2026-09-07T02",
            "attempt": 2,
            "scheduled_at": "2026-09-07T02:00:00+09:00",
            "started_at": "2026-09-07T02:00:01+09:00",
            "completed_at": "2026-09-07T02:00:09+09:00",
            "status": "partial",
            "inventory_fingerprint": "sha256:" + "a" * 64,
            "policy_fingerprint": "sha256:" + "b" * 64,
            "expected_assets": 3,
            "observed_assets": 2,
            "coverage_pct": 66.6666666667,
            "failure_codes": [
                "DATA_GAP_SECRET_ROUTER_01",
                "COLLECTOR_EXCEPTION_SECRETBACKENDERROR",
            ],
        }

        class ReceiptService:
            def run_hourly(self, *, execute_readonly: bool = False) -> dict[str, object]:
                if execute_readonly is not True:
                    raise AssertionError("run-hourly must preserve explicit read-only execution")
                return dict(sensitive_receipt)

        service = ReceiptService()
        self.assertEqual(service.run_hourly(execute_readonly=True), sensitive_receipt)

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
            body = json.dumps({"confirm_readonly": True}).encode("utf-8")
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            conn.request(
                "POST",
                "/api/v1/security/monitoring/run-hourly",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "X-Workspace-CSRF": csrf,
                },
            )
            response = conn.getresponse()
            raw = response.read().decode("utf-8")
            payload = json.loads(raw)
            status = response.status
            conn.close()

            self.assertEqual(status, 200)
            self.assertEqual(
                payload,
                {
                    "status": "partial",
                    "attempt": 2,
                    "expected_assets": 3,
                    "observed_assets": 2,
                    "coverage_pct": 66.6666666667,
                    "failure_count": 2,
                },
            )
            for sensitive in (
                "run-secret-router-01",
                "secret-profile",
                "2026-09-07T02:00:00+09:00",
                "2026-09-07T02:00:01+09:00",
                "2026-09-07T02:00:09+09:00",
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                "DATA_GAP_SECRET_ROUTER_01",
                "COLLECTOR_EXCEPTION_SECRETBACKENDERROR",
            ):
                self.assertNotIn(sensitive, raw)
            self.assertNotIn("failure_codes", payload)
            self.assertNotIn("run_id", payload)
            self.assertNotIn("slot_key", payload)
            self.assertNotIn("inventory_fingerprint", payload)
            self.assertNotIn("policy_fingerprint", payload)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
