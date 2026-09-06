from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from three_agent import security_monitoring_cli
from three_agent.security_monitoring.service import (
    ASSET_INTELLIGENCE_SUMMARY_SCHEMA,
    safe_asset_intelligence_summary,
)


class SecurityAssetIntelligenceTests(unittest.TestCase):
    def test_summary_is_aggregate_only_and_excludes_sensitive_asset_details(self) -> None:
        assets = (
            SimpleNamespace(
                asset_id="router-core-01",
                enabled=True,
                role="core-router",
                management_host="192.0.2.10",
                collector_capabilities=("icmp_echo", "snmpv3_read"),
                allowed_tcp_ports=(),
                data_class="restricted",
                credential_ref=SimpleNamespace(handle="secret-ref:router-core-01"),
            ),
            SimpleNamespace(
                asset_id="app-server-01",
                enabled=True,
                role="app-server",
                management_host="server.internal",
                collector_capabilities=("tcp_connect",),
                allowed_tcp_ports=(443,),
                data_class="confidential",
                credential_ref=None,
            ),
            SimpleNamespace(
                asset_id="staged-01",
                enabled=False,
                role="staged-device",
                management_host="192.0.2.30",
                collector_capabilities=("local_net_read",),
                allowed_tcp_ports=(),
                data_class="internal",
                credential_ref=None,
            ),
        )

        payload = safe_asset_intelligence_summary(SimpleNamespace(assets=assets))

        self.assertEqual(payload["schema_version"], ASSET_INTELLIGENCE_SUMMARY_SCHEMA)
        self.assertEqual(payload["count_scope"], "enabled_assets")
        self.assertEqual(payload["asset_count"], 3)
        self.assertEqual(payload["enabled_asset_count"], 2)
        self.assertEqual(payload["disabled_asset_count"], 1)
        self.assertEqual(payload["unique_role_count"], 2)
        self.assertEqual(
            payload["capability_counts"],
            {"icmp_echo": 1, "snmpv3_read": 1, "tcp_connect": 1},
        )
        self.assertEqual(
            payload["data_class_counts"],
            {"confidential": 1, "restricted": 1},
        )
        self.assertEqual(payload["credential_ref_asset_count"], 1)
        self.assertEqual(payload["explicit_tcp_port_binding_count"], 1)
        self.assertFalse(payload["contains_raw_credentials"])

        authority = payload["authority"]
        assert isinstance(authority, dict)
        self.assertTrue(authority["aggregate_only"])
        self.assertTrue(authority["config_is_authoritative"])
        self.assertFalse(authority["asset_ids_exposed"])
        self.assertFalse(authority["management_hosts_exposed"])
        self.assertFalse(authority["credential_refs_exposed"])
        self.assertFalse(authority["allowed_tcp_ports_exposed"])
        self.assertFalse(authority["database_write"])
        self.assertFalse(authority["network_execution"])
        self.assertFalse(authority["collector_execution"])
        self.assertFalse(authority["packet_capture_execution"])
        self.assertFalse(authority["remediation_execution"])

        serialized = json.dumps(payload, sort_keys=True)
        for sensitive_value in (
            "router-core-01",
            "app-server-01",
            "staged-01",
            "core-router",
            "app-server",
            "staged-device",
            "192.0.2.10",
            "server.internal",
            "192.0.2.30",
            "secret-ref:router-core-01",
            "443",
        ):
            self.assertNotIn(sensitive_value, serialized)
        self.assertNotIn("local_net_read", serialized)
        self.assertNotIn("internal", serialized)

    @patch("three_agent.security_monitoring_cli.SecurityMonitoringService")
    def test_cli_uses_canonical_service_without_execution_authority(self, service_cls) -> None:
        service = service_cls.return_value
        service.asset_intelligence.return_value = {
            "schema_version": ASSET_INTELLIGENCE_SUMMARY_SCHEMA,
            "authority": {"network_execution": False},
        }
        stdout = StringIO()

        with redirect_stdout(stdout):
            rc = security_monitoring_cli.main(
                ["--config", "monitoring.json", "asset-intelligence"]
            )

        self.assertEqual(rc, 0)
        service_cls.assert_called_once_with(Path("monitoring.json"))
        service.asset_intelligence.assert_called_once_with()
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], ASSET_INTELLIGENCE_SUMMARY_SCHEMA)
        self.assertFalse(payload["authority"]["network_execution"])
        service.initialize.assert_not_called()
        service.run_hourly.assert_not_called()


if __name__ == "__main__":
    unittest.main()
