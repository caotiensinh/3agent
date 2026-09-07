from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class SecurityConsoleReadinessRedactionTests(unittest.TestCase):
    def test_browser_readiness_redacts_asset_ids_fingerprints_and_dynamic_messages(self) -> None:
        sensitive_readiness: dict[str, object] = {
            "schema_version": "workspace-security-monitoring/readiness-v1",
            "ready": False,
            "status": "blocked",
            "config_saved": True,
            "policy_fingerprint": "sha256:" + "f" * 64,
            "enabled_asset_count": 2,
            "issues": [
                {
                    "code": "SECRET_REF_UNRESOLVED",
                    "message": "asset-router-secret-01: credential reference is not present in /srv/customer-a/private/secrets.",
                },
                {
                    "code": "VENDOR_BACKEND_SECRET_DETAIL",
                    "message": "backend leaked asset-router-secret-02 and /srv/customer-a/internal.db",
                },
            ],
            "warnings": [
                {
                    "code": "MONITORING_DISABLED",
                    "message": "asset-router-secret-03: monitoring is currently disabled by private profile.",
                },
                {
                    "code": "UNKNOWN_PRIVATE_WARNING",
                    "message": "customer-a-private-warning",
                },
            ],
            "network_test_executed": False,
            "secret_values_read": False,
            "packet_capture_executed": False,
            "remediation_executed": False,
        }

        class ReadinessService:
            def readiness(self) -> dict[str, object]:
                return dict(sensitive_readiness)

        service = ReadinessService()
        self.assertEqual(service.readiness(), sensitive_readiness)
        self.assertIn("asset-router-secret-01", json.dumps(service.readiness()))
        self.assertIn("policy_fingerprint", service.readiness())

        server = build_server(
            "127.0.0.1",
            0,
            service,  # type: ignore[arg-type]
            csrf_token="a" * 64,
            csp_nonce="b" * 32,
            demo_mode=False,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            conn.request("GET", "/api/v1/security/monitoring/readiness")
            response = conn.getresponse()
            raw = response.read().decode("utf-8")
            payload = json.loads(raw)
            status = response.status
            conn.close()

            self.assertEqual(status, 200)
            self.assertEqual(payload["schema_version"], "workspace-security-monitoring/readiness-v1")
            self.assertIs(payload["ready"], False)
            self.assertEqual(payload["status"], "blocked")
            self.assertIs(payload["config_saved"], True)
            self.assertEqual(payload["enabled_asset_count"], 2)
            self.assertEqual(
                payload["issues"],
                [
                    {
                        "code": "SECRET_REF_UNRESOLVED",
                        "message": "Credential reference is not present in the local secret boundary.",
                    },
                    {
                        "code": "READINESS_DETAIL_REDACTED",
                        "message": "Additional readiness issue details are unavailable.",
                    },
                ],
            )
            self.assertEqual(
                payload["warnings"],
                [
                    {
                        "code": "MONITORING_DISABLED",
                        "message": "Monitoring is currently disabled.",
                    },
                    {
                        "code": "READINESS_WARNING_REDACTED",
                        "message": "Additional readiness warning details are unavailable.",
                    },
                ],
            )
            self.assertIs(payload["network_test_executed"], False)
            self.assertIs(payload["secret_values_read"], False)
            self.assertIs(payload["packet_capture_executed"], False)
            self.assertIs(payload["remediation_executed"], False)
            self.assertNotIn("policy_fingerprint", payload)
            for sensitive in (
                "sha256:" + "f" * 64,
                "asset-router-secret-01",
                "asset-router-secret-02",
                "asset-router-secret-03",
                "/srv/customer-a/private/secrets",
                "/srv/customer-a/internal.db",
                "customer-a-private-warning",
                "VENDOR_BACKEND_SECRET_DETAIL",
                "UNKNOWN_PRIVATE_WARNING",
            ):
                self.assertNotIn(sensitive, raw)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
