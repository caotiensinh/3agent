from __future__ import annotations

import unittest
from pathlib import Path


class SecurityConfigurationInstallerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = Path("scripts/install_chat_gateway.sh").read_text(encoding="utf-8")

    def test_installer_provisions_application_owned_config_path(self) -> None:
        self.assertIn("WORKSPACE_SECURITY_MONITORING_CONFIG=$SECURITY_CONFIG_DEFAULT", self.script)
        self.assertIn('SECURITY_CONFIG_DEFAULT="$CONFIG_DIR/security_monitoring.json"', self.script)
        self.assertIn('SECURITY_DATA_DIR="$HOME/.local/share/3agent/security-monitoring"', self.script)

    def test_bootstrap_config_is_fail_closed(self) -> None:
        self.assertIn('"enabled": false', self.script)
        self.assertIn('"allow_real_network": false', self.script)
        self.assertIn('"network_scope": "approved_inventory_only"', self.script)
        self.assertIn('"read_only": true', self.script)
        self.assertIn('"allow_active_liveness": false', self.script)
        self.assertIn('"packet_analysis_mode": "passive_only"', self.script)
        self.assertIn('"assets": []', self.script)

    def test_existing_custom_monitoring_path_is_preserved(self) -> None:
        self.assertIn("Preserving existing WORKSPACE_SECURITY_MONITORING_CONFIG path.", self.script)
        self.assertIn("A pre-existing custom path is", self.script)
        self.assertNotIn('sed -i "s/^WORKSPACE_SECURITY_MONITORING_CONFIG=', self.script)


if __name__ == "__main__":
    unittest.main()
