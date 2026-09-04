from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway import SecurityE2EApplication, SecurityE2EHTTPHandler


class SecurityAssetOnboardingGatewayTests(unittest.TestCase):
    def test_application_wires_config_authoritative_onboarding_service(self) -> None:
        source = inspect.getsource(SecurityE2EApplication.__init__)
        self.assertIn("SecurityMonitoringUIConfigManagerV2.from_environment()", source)
        self.assertIn("SecurityAssetOnboardingService(self.security_config)", source)

    def test_candidate_and_prepare_routes_are_admin_only(self) -> None:
        candidates = inspect.getsource(SecurityE2EHTTPHandler._security_onboarding_candidates)
        prepare = inspect.getsource(SecurityE2EHTTPHandler._security_onboarding_prepare)
        self.assertIn("self._require_admin()", candidates)
        self.assertIn("self._require_admin()", prepare)
        self.assertIn("self.app.security_onboarding.list_candidates", candidates)
        self.assertIn("self.app.security_onboarding.prepare", prepare)

    def test_routes_are_explicit_and_do_not_save_configuration_implicitly(self) -> None:
        get_source = inspect.getsource(SecurityE2EHTTPHandler.do_GET)
        post_source = inspect.getsource(SecurityE2EHTTPHandler.do_POST)
        prepare = inspect.getsource(SecurityE2EHTTPHandler._security_onboarding_prepare)
        self.assertIn('"/api/security/onboarding/candidates"', get_source)
        self.assertIn('"/api/security/onboarding/prepare"', post_source)
        self.assertNotIn("security_config.save", prepare)
        self.assertNotIn("refresh_security_monitoring", prepare)
        self.assertNotIn("execute", prepare)

    def test_runtime_contract_explicitly_denies_discovery_self_enrollment(self) -> None:
        source = inspect.getsource(SecurityE2EHTTPHandler._security_runtime)
        self.assertIn('"discovery_self_enrollment": False', source)
        self.assertIn('"asset_onboarding_authority": "configuration_center_only"', source)
        self.assertIn('"autonomous_remediation": False', source)

    def test_onboarding_http_surface_has_no_network_process_or_capture_execution(self) -> None:
        source = "\n".join(
            (
                inspect.getsource(SecurityE2EHTTPHandler._security_onboarding_candidates),
                inspect.getsource(SecurityE2EHTTPHandler._security_onboarding_prepare),
            )
        )
        for forbidden in (
            "subprocess",
            "socket.",
            "systemctl",
            "execute_capture",
            "security_config.save",
            "refresh_security_monitoring",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
