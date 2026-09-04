from __future__ import annotations

import inspect
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from three_agent.chat_gateway import SecurityMonitoringHTTPHandler
from three_agent.security_monitoring.soc_read_model import SOC_READ_MODEL_SCHEMA_VERSION
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_monitoring.ui_read_model import (
    SecurityMonitoringUIReadModel,
    _QueryOnlyReportStore,
)


class SecurityMonitoringSOCGatewayTests(unittest.TestCase):
    def _model(self, root: Path) -> SecurityMonitoringUIReadModel:
        db = root / "monitoring.sqlite3"
        store = MonitoringStore(db)
        store.initialize()
        with store.connect() as conn:
            conn.execute(
                """
                INSERT INTO hourly_runs(
                    run_id,slot_key,attempt,scheduled_at,started_at,completed_at,status,
                    inventory_fingerprint,policy_fingerprint,expected_assets,observed_assets,
                    coverage_pct,failure_codes_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "run-soc-1",
                    "2026-08-31T17:00+09:00",
                    1,
                    "2026-08-31T17:00:00+09:00",
                    "2026-08-31T17:00:02+09:00",
                    "2026-08-31T17:00:05+09:00",
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
                INSERT INTO findings(
                    finding_id,category,severity,status,first_seen,last_seen,asset_refs_json,
                    evidence_refs_json,correlation_key,rule_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "finding-soc-1",
                    "network.interface.error",
                    "high",
                    "open",
                    "2026-08-31T16:59:00+09:00",
                    "2026-08-31T17:01:00+09:00",
                    '["switch-sensitive-1"]',
                    '["evidence:soc-1"]',
                    "switch-sensitive-1:private-correlation",
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
                    "evt-soc-1",
                    "suricata-1",
                    "suricata_eve",
                    "2026-08-31T17:00:30+09:00",
                    "suricata.alert",
                    "high",
                    "sha256:" + "4" * 64,
                    "workspace-json-sensor/v1",
                    "event:soc-1",
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
                        "profile_id": "soc-ui-test",
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
        return SecurityMonitoringUIReadModel.from_environment(
            {"WORKSPACE_SECURITY_MONITORING_CONFIG": str(config)}
        )

    def test_soc_projection_reuses_canonical_contract_and_drops_sensitive_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = self._model(Path(tmp)).soc(
                cutoff_at="2026-08-31T17:30:00+09:00"
            )

        self.assertEqual(payload["schema_version"], SOC_READ_MODEL_SCHEMA_VERSION)
        self.assertEqual(payload["report_id"], "report-20260831-1730")
        self.assertEqual(payload["risk_summary"]["today_open_high_critical"], 1)
        self.assertEqual(payload["findings"][0]["finding_id"], "finding-soc-1")
        self.assertEqual(payload["findings"][0]["evidence_refs"], ["evidence:soc-1"])
        rendered = json.dumps(payload, sort_keys=True)
        for forbidden in (
            "asset_refs",
            "switch-sensitive-1",
            "private-correlation",
            "management_host",
            "credential_ref",
            '"label"',
            '"authority"',
            '"remediation"',
        ):
            self.assertNotIn(forbidden, rendered)

    def test_soc_report_adapter_is_query_only(self):
        source = inspect.getsource(_QueryOnlyReportStore)
        self.assertIn("_connect_ro", source)
        for forbidden in ("INSERT ", "UPDATE ", "DELETE ", "REPLACE ", "MonitoringStore("):
            self.assertNotIn(forbidden, source)

        with tempfile.TemporaryDirectory() as tmp:
            model = self._model(Path(tmp))
            with _QueryOnlyReportStore(model._connect_ro).connect() as conn:
                self.assertEqual(conn.execute("PRAGMA query_only").fetchone()[0], 1)
                with self.assertRaises(sqlite3.OperationalError):
                    conn.execute("CREATE TABLE should_never_exist(id INTEGER)")

    def test_unconfigured_soc_fails_as_data_unavailable(self):
        model = SecurityMonitoringUIReadModel.from_environment({})
        with self.assertRaises(sqlite3.DatabaseError):
            model.soc(cutoff_at="2026-08-31T17:30:00+09:00")

    def test_soc_route_is_authenticated_and_uses_query_only_read_model(self):
        routes = inspect.getsource(SecurityMonitoringHTTPHandler.do_GET)
        helper = inspect.getsource(SecurityMonitoringHTTPHandler._security_get)
        self.assertIn('"/api/security/soc": "soc"', routes)
        self.assertIn('view == "soc"', helper)
        self.assertIn("model.soc()", helper)
        self.assertIn("self._authorized_local()", helper)
        for forbidden in ("build_deterministic_report(", "MonitoringStore(", "execute_capture"):
            self.assertNotIn(forbidden, helper)


if __name__ == "__main__":
    unittest.main()
