from __future__ import annotations

import json
import unittest

from scripts.check_self_hosted_runner_readiness import SCHEMA, evaluate_readiness


class SelfHostedRunnerReadinessTests(unittest.TestCase):
    def _evaluate(self, **overrides):
        values = {
            "system_name": "Linux",
            "machine": "x86_64",
            "systemd_available": True,
            "service_count": 1,
            "active_service_count": 1,
            "listener_count": 1,
            "github_reachable": True,
            "api_github_reachable": True,
        }
        values.update(overrides)
        return evaluate_readiness(**values)

    def test_ready_requires_live_listener_and_github_network(self) -> None:
        payload = self._evaluate()
        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(payload["status"], "READY")
        self.assertEqual(payload["runner_listener_count"], 1)

    def test_missing_service_is_distinct_from_inactive_service(self) -> None:
        missing = self._evaluate(service_count=0, active_service_count=0, listener_count=0)
        inactive = self._evaluate(service_count=1, active_service_count=0, listener_count=0)
        self.assertEqual(missing["status"], "RUNNER_SERVICE_MISSING")
        self.assertEqual(inactive["status"], "RUNNER_SERVICE_INACTIVE")

    def test_active_service_without_listener_is_process_failure(self) -> None:
        payload = self._evaluate(listener_count=0)
        self.assertEqual(payload["status"], "RUNNER_PROCESS_MISSING")

    def test_running_listener_with_failed_outbound_network_is_blocked(self) -> None:
        payload = self._evaluate(github_reachable=False)
        self.assertEqual(payload["status"], "NETWORK_UNREACHABLE")

    def test_interactive_runner_can_be_ready_without_systemd_service(self) -> None:
        payload = self._evaluate(
            systemd_available=False,
            service_count=0,
            active_service_count=0,
            listener_count=1,
        )
        self.assertEqual(payload["status"], "READY")

    def test_output_is_sanitized_and_read_only(self) -> None:
        payload = self._evaluate()
        encoded = json.dumps(payload, sort_keys=True).lower()
        for forbidden in ("hostname", "runner_name", "service_name", "process_cmdline", "token", "credential"):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(payload["mutations_performed"])
        self.assertFalse(payload["secrets_read"])
        self.assertFalse(payload["host_identity_included"])
        self.assertTrue(payload["labels_server_side_verification_required"])

    def test_unsupported_host_fails_closed(self) -> None:
        payload = self._evaluate(system_name="Windows", machine="AMD64")
        self.assertEqual(payload["status"], "UNSUPPORTED_HOST")


if __name__ == "__main__":
    unittest.main()
