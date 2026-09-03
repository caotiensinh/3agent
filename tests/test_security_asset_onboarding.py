from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.asset_onboarding import SecurityAssetOnboardingService
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.discovery_candidate_store import DiscoveryCandidateStore
from three_agent.security_monitoring.discovery_candidates import DiscoveryCandidate
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_monitoring.ui_config import safe_default_payload
from three_agent.security_monitoring.ui_config_v2 import SecurityMonitoringUIConfigManagerV2


class SecurityAssetOnboardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "monitoring.sqlite3"
        self.config_path = self.root / "security_monitoring.json"
        payload = safe_default_payload(self.config_path)
        payload["database_path"] = str(self.db)
        payload["secret_directory"] = str(self.root / "secrets")
        self.payload = payload
        self._write_config()

        self.store = MonitoringStore(self.db)
        self.candidates = DiscoveryCandidateStore(self.store)
        self.candidates.initialize()
        self.manager = SecurityMonitoringUIConfigManagerV2(
            self.config_path, path_source="test"
        )
        self.service = SecurityAssetOnboardingService(self.manager)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_config(self) -> None:
        self.config_path.write_text(
            json.dumps(self.payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _candidate(self, *, kind: str = "ip", value: str = "192.0.2.10") -> DiscoveryCandidate:
        candidate = DiscoveryCandidate.build(
            identity_kind=kind,
            identity_value=value,
            first_seen="2026-09-02T00:00:00Z",
            last_seen="2026-09-02T01:00:00Z",
            observation_count=3,
            confidence_basis_points=9000,
            provenance_refs=("source-ref:test",),
            evidence_refs=("evidence-ref:test",),
        )
        self.candidates.put(candidate)
        return candidate

    @staticmethod
    def _asset(host: str = "192.0.2.10") -> dict[str, object]:
        return {
            "asset_id": "router-test",
            "role": "router",
            "management_host": host,
            "collector_capabilities": ["icmp_echo"],
            "allowed_tcp_ports": [],
            "data_class": "confidential",
            "enabled": True,
            "credential_ref": None,
        }

    def _request(self, candidate: DiscoveryCandidate, *, host: str = "192.0.2.10") -> dict[str, object]:
        return {
            "candidate_id": candidate.candidate_id,
            "candidate_fingerprint": candidate.fingerprint,
            "operator_approval_ref": "approval-ref:operator-test-001",
            "asset": self._asset(host),
        }

    def test_candidate_listing_is_read_only_and_does_not_expose_raw_target(self) -> None:
        self._candidate()
        result = self.service.list_candidates(limit=20)
        self.assertEqual(len(result["items"]), 1)
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("192.0.2.10", encoded)
        self.assertNotIn("identity_ref", encoded)
        self.assertEqual(result["items"][0]["trust_state"], "untrusted")
        self.assertEqual(result["items"][0]["authority"], "none")
        self.assertFalse(result["authority"]["database_write"])
        self.assertFalse(result["authority"]["network_execution"])

    def test_prepare_returns_config_draft_without_approved_inventory_db_write(self) -> None:
        candidate = self._candidate()
        result = self.service.prepare(self._request(candidate))
        self.assertEqual(result["status"], "prepared_not_saved")
        self.assertEqual(result["transition"], "append_required")
        self.assertEqual(result["asset"]["management_host"], "192.0.2.10")
        self.assertEqual(result["authority"]["result"], "configuration_draft_only")
        self.assertTrue(result["authority"]["config_is_authoritative"])
        self.assertFalse(result["authority"]["config_saved"])
        self.assertFalse(result["authority"]["database_write"])
        self.assertFalse(result["authority"]["network_execution"])
        with self.store.connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM approved_assets").fetchone()[0]
        self.assertEqual(count, 0)
        persisted = self.candidates.get(candidate.candidate_id)
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.trust_state, "untrusted")
        self.assertEqual(persisted.inventory_status, "not_enrolled")
        self.assertEqual(persisted.authority, "none")

    def test_prepare_requires_exact_candidate_fingerprint(self) -> None:
        candidate = self._candidate()
        request = self._request(candidate)
        request["candidate_fingerprint"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(MonitoringContractError, "fingerprint changed"):
            self.service.prepare(request)

    def test_prepare_requires_exact_management_host_binding(self) -> None:
        candidate = self._candidate()
        with self.assertRaisesRegex(MonitoringContractError, "does not match"):
            self.service.prepare(self._request(candidate, host="192.0.2.11"))

    def test_prepare_requires_typed_operator_approval_reference(self) -> None:
        candidate = self._candidate()
        request = self._request(candidate)
        request["operator_approval_ref"] = "approved-by-admin"
        with self.assertRaisesRegex(MonitoringContractError, "approval-ref"):
            self.service.prepare(request)

    def test_prepare_rejects_raw_secret_fields_instead_of_ignoring_them(self) -> None:
        candidate = self._candidate()
        request = self._request(candidate)
        request["asset"] = dict(request["asset"], password="secret-value")
        with self.assertRaisesRegex(MonitoringContractError, "unknown onboarding asset keys"):
            self.service.prepare(request)

    def test_prepare_does_not_mutate_existing_asset_definition(self) -> None:
        candidate = self._candidate()
        existing = self._asset()
        existing["role"] = "legacy-router"
        self.payload["assets"] = [existing]
        self._write_config()
        with self.assertRaisesRegex(MonitoringContractError, "cannot mutate"):
            self.service.prepare(self._request(candidate))

    def test_prepare_rejects_management_host_owned_by_other_configured_asset(self) -> None:
        candidate = self._candidate()
        existing = self._asset()
        existing["asset_id"] = "other-router"
        self.payload["assets"] = [existing]
        self._write_config()
        with self.assertRaisesRegex(MonitoringContractError, "already owned"):
            self.service.prepare(self._request(candidate))

    def test_prepare_is_idempotent_when_exact_asset_is_already_configured(self) -> None:
        candidate = self._candidate()
        self.payload["assets"] = [self._asset()]
        self._write_config()
        result = self.service.prepare(self._request(candidate))
        self.assertEqual(result["transition"], "already_configured")
        self.assertFalse(result["authority"]["config_saved"])

    def test_mac_candidate_cannot_be_silently_cross_bound_to_management_ip(self) -> None:
        candidate = self._candidate(kind="mac", value="02:00:00:00:00:10")
        with self.assertRaisesRegex(MonitoringContractError, "cross-identity"):
            self.service.prepare(self._request(candidate))

    def test_onboarding_module_has_no_network_or_process_execution_surface(self) -> None:
        import three_agent.security_monitoring.asset_onboarding as module

        source = inspect.getsource(module)
        for forbidden in (
            "subprocess",
            "socket.",
            "os.system",
            "Popen",
            "execute_capture",
            "systemctl",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("PRAGMA query_only=ON", source)
        self.assertIn("mode=ro", source)


if __name__ == "__main__":
    unittest.main()
