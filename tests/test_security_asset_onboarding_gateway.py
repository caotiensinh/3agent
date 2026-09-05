from __future__ import annotations

import inspect
import unittest
from http import HTTPStatus
from unittest.mock import Mock, PropertyMock, patch

from three_agent.chat_gateway import (
    ApprovedAssetHTTPHandler,
    SecurityE2EApplication,
    SecurityE2EHTTPHandler,
    WORKSPACE_HTML,
)
from three_agent.security_monitoring.asset_onboarding import SecurityAssetOnboardingConflict


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
        handler = object.__new__(SecurityE2EHTTPHandler)

        handler.path = "/api/security/onboarding/candidates"
        with patch.object(
            SecurityE2EHTTPHandler,
            "_security_onboarding_candidates",
        ) as candidates:
            handler.do_GET()
        candidates.assert_called_once()
        parsed = candidates.call_args.args[0]
        self.assertEqual(parsed.path, "/api/security/onboarding/candidates")

        handler.path = "/api/security/onboarding/prepare"
        with patch.object(
            SecurityE2EHTTPHandler,
            "_security_onboarding_prepare",
        ) as prepare_route:
            handler.do_POST()
        prepare_route.assert_called_once()

        prepare = inspect.getsource(SecurityE2EHTTPHandler._security_onboarding_prepare)
        self.assertNotIn("security_config.save", prepare)
        self.assertNotIn("refresh_security_monitoring", prepare)
        self.assertNotIn("execute", prepare)

    def test_runtime_contract_explicitly_denies_discovery_self_enrollment(self) -> None:
        handler = object.__new__(SecurityE2EHTTPHandler)
        with (
            patch.object(SecurityE2EHTTPHandler, "_require_admin", return_value=object()),
            patch.object(SecurityE2EHTTPHandler, "_json") as emit,
        ):
            handler._security_runtime()

        emit.assert_called_once()
        status, payload = emit.call_args.args
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIs(payload["discovery_self_enrollment"], False)
        self.assertEqual(payload["asset_onboarding_authority"], "configuration_center_only")
        self.assertIs(payload["autonomous_remediation"], False)

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

    def test_approved_asset_routes_are_exact_and_admin_fail_closed(self) -> None:
        handler = object.__new__(ApprovedAssetHTTPHandler)

        handler.path = "/api/security/assets/config"
        with patch.object(ApprovedAssetHTTPHandler, "_security_asset_snapshot") as snapshot:
            handler.do_GET()
        snapshot.assert_called_once_with()

        for path, action in (
            ("/api/security/assets/upsert", "upsert"),
            ("/api/security/assets/disable", "disable"),
        ):
            handler.path = path
            with self.subTest(path=path), patch.object(
                ApprovedAssetHTTPHandler,
                "_security_asset_post",
            ) as mutate:
                handler.do_POST()
            mutate.assert_called_once_with(action)

        dispatch_source = "\n".join(
            (
                inspect.getsource(ApprovedAssetHTTPHandler.do_GET),
                inspect.getsource(ApprovedAssetHTTPHandler.do_POST),
            )
        )
        self.assertNotIn("/api/security/assets/discover", dispatch_source)
        self.assertNotIn("/api/security/assets/scan", dispatch_source)

        with (
            patch.object(ApprovedAssetHTTPHandler, "_require_admin", return_value=None),
            patch.object(ApprovedAssetHTTPHandler, "_json") as emit,
        ):
            handler._security_asset_snapshot()
            handler._security_asset_post("upsert")
        emit.assert_not_called()

    def test_approved_asset_rejections_map_codes_without_refresh_side_effects(self) -> None:
        cases = (
            (SecurityAssetOnboardingConflict(), HTTPStatus.CONFLICT, "SECURITY_ASSET_CONFIG_STALE"),
            (PermissionError(), HTTPStatus.FORBIDDEN, "REAL_NETWORK_CONFIRMATION_REQUIRED"),
        )
        for error, expected_status, expected_code in cases:
            with self.subTest(code=expected_code):
                handler = object.__new__(ApprovedAssetHTTPHandler)
                app = Mock()
                app.security_assets.upsert.side_effect = error
                payload = {
                    "asset": {"asset_id": "router-1"},
                    "expected_config_fingerprint": "fingerprint",
                    "confirmation": "",
                }
                with (
                    patch.object(
                        ApprovedAssetHTTPHandler,
                        "app",
                        new_callable=PropertyMock,
                        return_value=app,
                    ),
                    patch.object(
                        ApprovedAssetHTTPHandler,
                        "_require_admin",
                        return_value={"user_id": "admin"},
                    ),
                    patch.object(
                        ApprovedAssetHTTPHandler,
                        "_read_json_large",
                        return_value=payload,
                    ),
                    patch.object(ApprovedAssetHTTPHandler, "_json") as emit,
                ):
                    handler._security_asset_post("upsert")

                emit.assert_called_once()
                status, response = emit.call_args.args
                self.assertEqual(status, expected_status)
                self.assertEqual(response["code"], expected_code)
                app.refresh_security_monitoring.assert_not_called()

    def test_approved_asset_frontend_controls_preserve_opaque_secret_boundary(self) -> None:
        for marker in (
            "Save asset",
            "Disable asset",
            "Remove draft row",
            "expected_config_fingerprint",
            "SECURITY_ASSET_CONFIG_STALE",
            "network execution=false",
            "/api/security/assets/upsert",
            "/api/security/assets/disable",
        ):
            self.assertIn(marker, WORKSPACE_HTML)

        start_token = "function assetEditor(item={})"
        end_token = "function readAssets()"
        self.assertIn(start_token, WORKSPACE_HTML)
        self.assertIn(end_token, WORKSPACE_HTML)
        asset_editor = WORKSPACE_HTML.split(start_token, 1)[1].split(end_token, 1)[0].lower()
        for field in ("password", "community_string", "auth_key", "priv_key", "api_key"):
            self.assertNotIn(field, asset_editor)
        self.assertIn("secassetcredential", asset_editor)
        self.assertIn("credential_ref", asset_editor)


if __name__ == "__main__":
    unittest.main()
