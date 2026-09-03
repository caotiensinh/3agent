from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.asset_onboarding import (
    SecurityAssetOnboardingConflict,
    SecurityMonitoringAssetOnboarding,
)
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.ui_config import (
    REAL_NETWORK_CONFIRMATION,
    SecurityMonitoringUIConfigManagerV2,
)


class SecurityAssetOnboardingV011Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "security_monitoring.json"
        self.manager = SecurityMonitoringUIConfigManagerV2(
            self.path,
            path_source="test",
        )
        self.onboarding = SecurityMonitoringAssetOnboarding(self.manager)

    @staticmethod
    def _asset(**updates):
        payload = {
            "asset_id": "switch-01",
            "role": "switch",
            "management_host": "192.168.11.116",
            "collector_capabilities": ["local_net_read"],
            "allowed_tcp_ports": [],
            "data_class": "confidential",
            "enabled": True,
        }
        payload.update(updates)
        return payload

    def _fingerprint(self) -> str:
        return str(self.onboarding.snapshot()["config_fingerprint"])

    def test_create_update_and_disable_exact_asset_without_network_execution(self) -> None:
        created = self.onboarding.upsert(
            self._asset(),
            actor_id="admin-1",
            expected_config_fingerprint=self._fingerprint(),
        )
        self.assertEqual(created.action, "created")
        self.assertEqual(created.asset_id, "switch-01")
        self.assertEqual(created.asset_count, 1)
        self.assertEqual(created.enabled_asset_count, 1)
        self.assertFalse(created.network_executed)

        updated = self.onboarding.upsert(
            self._asset(role="core_switch"),
            actor_id="admin-1",
            expected_config_fingerprint=created.config_fingerprint,
        )
        self.assertEqual(updated.action, "updated")
        self.assertEqual(updated.asset_count, 1)
        self.assertEqual(updated.enabled_asset_count, 1)
        saved = self.manager.get()["config"]["assets"]
        self.assertEqual(saved[0]["role"], "core_switch")
        self.assertEqual(saved[0]["management_host"], "192.168.11.116")

        disabled = self.onboarding.disable(
            "switch-01",
            actor_id="admin-1",
            expected_config_fingerprint=updated.config_fingerprint,
        )
        self.assertEqual(disabled.action, "disabled")
        self.assertEqual(disabled.asset_count, 1)
        self.assertEqual(disabled.enabled_asset_count, 0)
        self.assertFalse(self.manager.get()["config"]["assets"][0]["enabled"])

    def test_raw_secret_fields_and_non_opaque_credentials_fail_closed(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "raw secret fields are forbidden"):
            self.onboarding.upsert(
                self._asset(password="plaintext"),
                actor_id="admin-1",
                expected_config_fingerprint=self._fingerprint(),
            )
        with self.assertRaisesRegex(MonitoringContractError, "secret handle must start"):
            self.onboarding.upsert(
                self._asset(
                    collector_capabilities=["snmpv3_read"],
                    credential_ref="plaintext-community",
                ),
                actor_id="admin-1",
                expected_config_fingerprint=self._fingerprint(),
            )

    def test_snmpv3_requires_opaque_credential_reference(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "requires an opaque credential_ref"):
            self.onboarding.upsert(
                self._asset(collector_capabilities=["snmpv3_read"]),
                actor_id="admin-1",
                expected_config_fingerprint=self._fingerprint(),
            )
        created = self.onboarding.upsert(
            self._asset(
                collector_capabilities=["snmpv3_read"],
                credential_ref="secret-ref:snmp-switch-01",
            ),
            actor_id="admin-1",
            expected_config_fingerprint=self._fingerprint(),
        )
        self.assertEqual(created.action, "created")
        saved = self.manager.get()["config"]["assets"][0]
        self.assertEqual(saved["credential_ref"], "secret-ref:snmp-switch-01")

    def test_target_scope_is_one_exact_host_not_cidr_or_url(self) -> None:
        for host in (
            "192.168.11.0/24",
            "https://192.168.11.116",
            "192.168.11.116;reboot",
        ):
            with self.subTest(host=host):
                with self.assertRaises(MonitoringContractError):
                    self.onboarding.upsert(
                        self._asset(management_host=host),
                        actor_id="admin-1",
                        expected_config_fingerprint=self._fingerprint(),
                    )

    def test_stale_configuration_fingerprint_blocks_lost_update(self) -> None:
        stale = self._fingerprint()
        first = self.onboarding.upsert(
            self._asset(),
            actor_id="admin-1",
            expected_config_fingerprint=stale,
        )
        self.assertNotEqual(stale, first.config_fingerprint)
        with self.assertRaisesRegex(SecurityAssetOnboardingConflict, "SECURITY_ASSET_CONFIG_STALE"):
            self.onboarding.upsert(
                self._asset(role="stale-edit"),
                actor_id="admin-2",
                expected_config_fingerprint=stale,
            )

    def test_real_network_inventory_change_preserves_strong_confirmation_gate(self) -> None:
        created = self.onboarding.upsert(
            self._asset(),
            actor_id="admin-1",
            expected_config_fingerprint=self._fingerprint(),
        )
        config = self.manager.get()["config"]
        config["allow_real_network"] = True
        armed = self.manager.save(
            config,
            actor_id="admin-1",
            confirmation=REAL_NETWORK_CONFIRMATION,
        )
        self.assertTrue(armed["audit_recorded"])
        fingerprint = self._fingerprint()

        with self.assertRaisesRegex(PermissionError, "REAL_NETWORK_CONFIRMATION_REQUIRED"):
            self.onboarding.upsert(
                self._asset(role="distribution_switch"),
                actor_id="admin-1",
                expected_config_fingerprint=fingerprint,
            )

        changed = self.onboarding.upsert(
            self._asset(role="distribution_switch"),
            actor_id="admin-1",
            expected_config_fingerprint=fingerprint,
            confirmation=REAL_NETWORK_CONFIRMATION,
        )
        self.assertEqual(changed.action, "updated")
        self.assertIn("approved_inventory_change", changed.confirmation_reasons)
        self.assertFalse(changed.network_executed)

    def test_snapshot_exposes_authority_boundary_and_never_secret_values(self) -> None:
        snapshot = self.onboarding.snapshot()
        self.assertEqual(snapshot["schema_version"], "workspace-security-monitoring/asset-onboarding-v1")
        self.assertTrue(snapshot["authority"]["approved_inventory_only"])
        self.assertFalse(snapshot["authority"]["raw_secrets_accepted"])
        self.assertFalse(snapshot["authority"]["network_executed"])
        self.assertNotIn("password", repr(snapshot).lower())


if __name__ == "__main__":
    unittest.main()
