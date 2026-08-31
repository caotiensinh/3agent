from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_monitoring.ui_read_model import (
    MAX_PAGE_OFFSET,
    MAX_PAGE_SIZE,
    SecurityMonitoringUIReadModel,
)


class SecurityMonitoringUIReadModelTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path]:
        db = root / "monitoring.sqlite3"
        store = MonitoringStore(db)
        store.initialize()
        with store.connect() as conn:
            conn.execute(
                """
                INSERT INTO approved_assets(
                    asset_id,role,management_host,collector_capabilities_json,
                    allowed_tcp_ports_json,data_class,enabled,credential_ref,asset_fingerprint
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    "switch-1",
                    "switch",
                    "192.168.11.6",
                    '["snmpv3_read"]',
                    "[]",
                    "confidential",
                    1,
                    "secret-ref:do-not-render",
                    "sha256:" + "1" * 64,
                ),
            )
            conn.execute(
                """
                INSERT INTO hourly_runs(
                    run_id,slot_key,attempt,scheduled_at,started_at,completed_at,status,
                    inventory_fingerprint,policy_fingerprint,expected_assets,observed_assets,
                    coverage_pct,failure_codes_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "run-1",
                    "2026-08-31T00:00+09:00",
                    1,
                    "2026-08-31T00:00:00+09:00",
                    "2026-08-31T00:00:02+09:00",
                    "2026-08-31T00:00:05+09:00",
                    "completed",
                    "sha256:" + "2" * 64,
                    "sha256:" + "3" * 64,
                    1,
                    1,
                    100.0,
                    "[]",
                ),
            )
            conn.execute(
                """
                INSERT INTO observations(
                    run_id,asset_id,collector,observed_at,metric,status,value_json,unit,evidence_ref
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    "run-1",
                    "switch-1",
                    "snmpv3_read",
                    "2026-08-31T00:00:04+09:00",
                    "network.interface.utilization",
                    "ok",
                    json.dumps(
                        {
                            "percent": 12.5,
                            "management_host": "192.168.11.6",
                            "token": "raw-secret-token",
                        }
                    ),
                    "percent",
                    "evidence:obs-1",
                ),
            )
            conn.execute(
                """
                INSERT INTO findings(
                    finding_id,category,severity,status,first_seen,last_seen,asset_refs_json,
                    evidence_refs_json,correlation_key,rule_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "finding-1",
                    "network.interface.error",
                    "high",
                    "open",
                    "2026-08-31T00:00:03+09:00",
                    "2026-08-31T00:00:04+09:00",
                    '["switch-1"]',
                    '["evidence:obs-1"]',
                    "switch-1:private-correlation-key",
                    "rule-interface-error",
                ),
            )
            conn.execute(
                """
                INSERT INTO canonical_events(
                    event_id,source_id,source_type,observed_at,category,severity,
                    message_sha256,parser_version,evidence_ref
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    "evt-1",
                    "suricata-1",
                    "suricata_eve",
                    "2026-08-31T00:00:03+09:00",
                    "suricata.alert",
                    "high",
                    "sha256:" + "4" * 64,
                    "workspace-json-sensor/v1",
                    "event:evt-1",
                ),
            )
            conn.execute(
                """
                INSERT INTO archive_receipts(
                    archive_id,period_kind,period_key,status,bundle_ref,manifest_sha256,attempt,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    "archive-1",
                    "weekly",
                    "2026-W35",
                    "completed",
                    "/mnt/private/archive/report.zip",
                    "sha256:" + "5" * 64,
                    1,
                    "2026-08-31T00:00:05+09:00",
                ),
            )

        config = root / "monitoring.json"
        config.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "allow_real_network": False,
                    "database_path": str(db),
                    "secret_directory": None,
                    "policy": {
                        "profile_id": "ui-test",
                        "network_scope": "approved_inventory_only",
                        "read_only": True,
                        "production_safety_profile": "non_disruptive_v1",
                        "allow_active_liveness": False,
                        "bandwidth_measurement_mode": "counter_only",
                        "packet_analysis_mode": "passive_only",
                        "max_workers": 2,
                        "timeout_seconds": 2.0,
                        "max_retries": 1,
                        "max_catch_up_runs": 1,
                        "allowed_capabilities": ["snmpv3_read"],
                    },
                    "assets": [],
                }
            ),
            encoding="utf-8",
        )
        return config, db

    def test_unconfigured_dashboard_is_explicit_and_never_guesses_a_path(self):
        model = SecurityMonitoringUIReadModel.from_environment({})
        summary = model.summary()
        self.assertEqual(summary["health"], "not_configured")
        self.assertEqual(summary["reason_codes"], ["MONITORING_CONFIG_NOT_SET"])
        self.assertFalse(summary["configured"])
        self.assertEqual(model.assets()["items"], [])

    def test_read_model_is_sqlite_query_only_and_has_no_mutation_surface(self):
        source = inspect.getsource(SecurityMonitoringUIReadModel._connect_ro)
        self.assertIn("?mode=ro", source)
        self.assertIn("PRAGMA query_only=ON", source)
        for forbidden in ("INSERT ", "UPDATE ", "DELETE ", "REPLACE "):
            self.assertNotIn(forbidden, inspect.getsource(SecurityMonitoringUIReadModel))
        for method in ("add_event", "add_finding", "upsert_asset", "put_hourly_receipt"):
            self.assertFalse(hasattr(SecurityMonitoringUIReadModel, method))

    def test_authenticated_views_are_bounded_and_do_not_render_sensitive_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _db = self._fixture(Path(tmp))
            model = SecurityMonitoringUIReadModel.from_environment(
                {"WORKSPACE_SECURITY_MONITORING_CONFIG": str(config)}
            )
            now = datetime(2026, 8, 30, 15, 1, tzinfo=timezone.utc)
            summary = model.summary(now=now)
            self.assertEqual(summary["health"], "attention")
            self.assertEqual(summary["high_critical_count"], 1)
            self.assertEqual(summary["enabled_asset_count"], 1)
            self.assertEqual(summary["latest_hourly"]["coverage_pct"], 100.0)

            network = model.network(limit=10, offset=0)
            self.assertEqual(network["items"][0]["value"], {"percent": 12.5})
            self.assertEqual(model.findings(limit=10)["items"][0]["finding_id"], "finding-1")
            self.assertEqual(model.events(limit=10)["items"][0]["event_id"], "evt-1")
            self.assertEqual(model.assets()["items"][0]["asset_id"], "switch-1")
            self.assertEqual(model.reports(limit=10)["items"][0]["archive_id"], "archive-1")

            rendered = json.dumps(
                {
                    "summary": summary,
                    "network": network,
                    "findings": model.findings(limit=10),
                    "events": model.events(limit=10),
                    "assets": model.assets(),
                    "reports": model.reports(limit=10),
                    "admin": model.admin_status(),
                },
                sort_keys=True,
            )
            for secret in (
                "192.168.11.6",
                "secret-ref:do-not-render",
                "raw-secret-token",
                "private-correlation-key",
                "/mnt/private/archive/report.zip",
            ):
                self.assertNotIn(secret, rendered)
            self.assertNotIn("message_sha256", rendered)
            self.assertNotIn("credential_ref", rendered)
            self.assertNotIn("management_host", rendered)
            self.assertNotIn("bundle_ref", rendered)
            self.assertNotIn("correlation_key", rendered)

    def test_pagination_hard_bounds_fail_closed(self):
        model = SecurityMonitoringUIReadModel.from_environment({})
        with self.assertRaises(MonitoringContractError):
            model.events(limit=MAX_PAGE_SIZE + 1)
        with self.assertRaises(MonitoringContractError):
            model.findings(offset=MAX_PAGE_OFFSET + 1)

    def test_admin_status_is_read_only_and_exposes_policy_not_server_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _db = self._fixture(Path(tmp))
            model = SecurityMonitoringUIReadModel.from_environment(
                {"WORKSPACE_SECURITY_MONITORING_CONFIG": str(config)}
            )
            status = model.admin_status()
            self.assertTrue(status["read_only_ui"])
            self.assertFalse(status["mutations_exposed"])
            self.assertFalse(status["autonomous_remediation"])
            self.assertFalse(status["autonomous_pcap"])
            self.assertEqual(status["policy"]["production_safety_profile"], "non_disruptive_v1")
            rendered = json.dumps(status, sort_keys=True)
            self.assertNotIn(str(config), rendered)
            self.assertNotIn(str(_db), rendered)


if __name__ == "__main__":
    unittest.main()
