from __future__ import annotations

import ast
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.repair_canonical_chat_security_ui import repair_source
from three_agent import chat_gateway


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "src" / "three_agent" / "chat_gateway.py"
ONBOARDING_MODULE = "security_monitoring.asset_onboarding"
ONBOARDING_SERVICE_NAME = "SecurityAssetOnboardingService"


class SecurityAssetOnboardingRuntimeRegressionTests(unittest.TestCase):
    def test_canonical_gateway_imports_onboarding_service_exactly_once(self) -> None:
        source = CANONICAL.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(CANONICAL))
        imports = [
            alias.name
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.level == 1
            and node.module == ONBOARDING_MODULE
            for alias in node.names
            if alias.name == ONBOARDING_SERVICE_NAME
        ]
        self.assertEqual(imports, [ONBOARDING_SERVICE_NAME])
        self.assertTrue(hasattr(chat_gateway, ONBOARDING_SERVICE_NAME))

    def test_security_application_constructs_onboarding_service_at_runtime(self) -> None:
        config = Mock(name="security_config")
        onboarding = Mock(name="security_onboarding")

        with (
            patch.object(
                chat_gateway.WorkflowDraftApplication,
                "__init__",
                return_value=None,
            ),
            patch.object(
                chat_gateway.SecurityMonitoringUIConfigManagerV2,
                "from_environment",
                return_value=config,
            ),
            patch.object(
                chat_gateway,
                ONBOARDING_SERVICE_NAME,
                return_value=onboarding,
            ) as onboarding_factory,
            patch.object(
                chat_gateway.SecurityE2EApplication,
                "refresh_security_monitoring",
                return_value=None,
            ),
        ):
            application = chat_gateway.SecurityE2EApplication(
                Mock(name="service"),
                Mock(name="auth"),
                Mock(name="artifact_root"),
                Mock(name="external_store"),
                Mock(name="external_settings"),
            )

        onboarding_factory.assert_called_once_with(config)
        self.assertIs(application.security_config, config)
        self.assertIs(application.security_onboarding, onboarding)

    def test_canonical_security_repair_is_idempotent(self) -> None:
        source = CANONICAL.read_text(encoding="utf-8")
        repaired, changed = repair_source(source)
        self.assertFalse(changed)
        self.assertEqual(repaired, source)


if __name__ == "__main__":
    unittest.main()
