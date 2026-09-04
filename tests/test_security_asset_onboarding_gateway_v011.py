from __future__ import annotations

import unittest
from pathlib import Path


class SecurityAssetOnboardingGatewayV011ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.gateway = (root / "src/three_agent/chat_gateway.py").read_text(encoding="utf-8")
        cls.frontend = (root / "src/three_agent/workspace_frontend.py").read_text(encoding="utf-8")

    def test_gateway_routes_are_admin_only_and_exact_asset_scoped(self) -> None:
        self.assertIn('"/api/security/assets/config"', self.gateway)
        self.assertIn('"/api/security/assets/upsert"', self.gateway)
        self.assertIn('"/api/security/assets/disable"', self.gateway)
        self.assertGreaterEqual(self.gateway.count("self._require_admin()"), 2)
        self.assertIn("SecurityMonitoringAssetOnboarding(self.security_config)", self.gateway)
        self.assertNotIn("/api/security/assets/discover", self.gateway)
        self.assertNotIn("/api/security/assets/scan", self.gateway)

    def test_gateway_maps_stale_and_confirmation_failures_without_network_side_effects(self) -> None:
        self.assertIn("HTTPStatus.CONFLICT", self.gateway)
        self.assertIn('"SECURITY_ASSET_CONFIG_STALE"', self.gateway)
        self.assertIn("HTTPStatus.FORBIDDEN", self.gateway)
        self.assertIn('"REAL_NETWORK_CONFIRMATION_REQUIRED"', self.gateway)
        lowered = self.gateway.lower()
        for forbidden in ("subprocess", "socket.", "os.system", "shell=true", "pcap"):
            self.assertNotIn(forbidden, lowered)

    def test_frontend_adds_save_disable_and_stale_reload_controls(self) -> None:
        self.assertIn("Save asset", self.frontend)
        self.assertIn("Disable asset", self.frontend)
        self.assertIn("Remove draft row", self.frontend)
        self.assertIn("expected_config_fingerprint", self.frontend)
        self.assertIn("SECURITY_ASSET_CONFIG_STALE", self.frontend)
        self.assertIn("network execution=false", self.frontend)
        self.assertIn("/api/security/assets/upsert", self.frontend)
        self.assertIn("/api/security/assets/disable", self.frontend)

    def test_frontend_never_collects_raw_secret_fields(self) -> None:
        lowered = self.frontend.lower()
        for field in ("password", "community_string", "auth_key", "priv_key", "api_key"):
            self.assertNotIn(field, lowered)
        self.assertIn("secAssetCredential", self.frontend)
        self.assertIn("credential_ref", self.frontend)


if __name__ == "__main__":
    unittest.main()
