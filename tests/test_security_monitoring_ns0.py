import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import (
    AssetInventoryRecord,
    MonitoringContractError,
    SecretReference,
)
from three_agent.security_monitoring.parsers import (
    QuarantinedRecord,
    parse_json_sensor_event,
    parse_syslog_line,
)
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine
from three_agent.security_monitoring.storage import MonitoringStore

FIXTURES = Path(__file__).parent / "fixtures" / "security_monitoring"


class MonitoringContractsTests(unittest.TestCase):
    def test_inventory_fixture_validates_without_real_network_access(self):
        payload = json.loads((FIXTURES / "inventory.json").read_text(encoding="utf-8"))
        assets = []
        for item in payload:
            credential = SecretReference(item["credential_ref"]) if item.get("credential_ref") else None
            assets.append(
                AssetInventoryRecord(
                    asset_id=item["asset_id"],
                    role=item["role"],
                    management_host=item["management_host"],
                    collector_capabilities=tuple(item["collector_capabilities"]),
                    allowed_tcp_ports=tuple(item["allowed_tcp_ports"]),
                    data_class=item["data_class"],
                    enabled=item["enabled"],
                    credential_ref=credential,
                ).validate()
            )
        self.assertEqual([a.asset_id for a in assets], ["router-rnd-01", "switch-rnd-01"])
        self.assertNotEqual(assets[0].fingerprint, assets[1].fingerprint)

    def test_management_target_rejects_url_and_shell_like_content(self):
        for value in (
            "https://192.0.2.1",
            "192.0.2.1;reboot",
            "192.0.2.1 && id",
            "192.0.2.1/path",
        ):
            with self.subTest(value=value), self.assertRaises(MonitoringContractError):
                AssetInventoryRecord(
                    asset_id="router-1",
                    role="router",
                    management_host=value,
                    collector_capabilities=("icmp_echo",),
                ).validate()

    def test_snmp_requires_opaque_reference_not_raw_secret(self):
        with self.assertRaises(MonitoringContractError):
            SecretReference("super-secret-password").validate()
        with self.assertRaises(MonitoringContractError):
            AssetInventoryRecord(
                asset_id="switch-1",
                role="switch",
                management_host="192.0.2.2",
                collector_capabilities=("snmpv3_read",),
            ).validate()
        asset = AssetInventoryRecord(
            asset_id="switch-1",
            role="switch",
            management_host="192.0.2.2",
            collector_capabilities=("snmpv3_read",),
            credential_ref=SecretReference("secret-ref:snmpv3-switch-1"),
        ).validate()
        self.assertTrue(asset.credential_ref.handle.startswith("secret-ref:"))


class MonitoringPolicyTests(unittest.TestCase):
    def setUp(self):
        self.asset = AssetInventoryRecord(
            asset_id="router-1",
            role="router",
            management_host="192.0.2.1",
            collector_capabilities=("icmp_echo", "tcp_connect"),
            allowed_tcp_ports=(443,),
        ).validate()
        self.engine = MonitoringPolicyEngine(
            MonitoringPolicy(max_workers=2, max_retries=1, allow_active_liveness=True)
        )

    def test_exact_approved_host_and_port_are_required(self):
        allowed = self.engine.require(
            self.asset,
            capability="tcp_connect",
            effect="network_read",
            target_host="192.0.2.1",
            target_port=443,
        )
        self.assertTrue(allowed.allowed)
        for host, port in (("192.0.2.99", 443), ("192.0.2.1", 22)):
            with self.subTest(host=host, port=port), self.assertRaises(PermissionError):
                self.engine.require(
                    self.asset,
                    capability="tcp_connect",
                    effect="network_read",
                    target_host=host,
                    target_port=port,
                )

    def test_network_write_effect_is_impossible(self):
        decision = self.engine.authorize(
            self.asset,
            capability="tcp_connect",
            effect="network_write",
            target_host="192.0.2.1",
            target_port=443,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "EFFECT_NOT_READ_ONLY")

    def test_audit_metadata_hashes_target(self):
        decision = self.engine.require(
            self.asset,
            capability="icmp_echo",
            effect="network_read",
            target_host="192.0.2.1",
        )
        metadata = json.dumps(decision.metadata(), sort_keys=True)
        self.assertNotIn("192.0.2.1", metadata)
        self.assertIn("target_sha256", metadata)

    def test_policy_bounds_retries_workers_and_scope(self):
        for kwargs in (
            {"max_workers": 5},
            {"max_retries": 2},
            {"max_catch_up_runs": 2},
            {"network_scope": "whole_lan"},
            {"read_only": False},
            {"production_safety_profile": "unsafe"},
            {"bandwidth_measurement_mode": "speedtest"},
            {"packet_analysis_mode": "inject"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(MonitoringContractError):
                MonitoringPolicy(**kwargs).validate()


class MonitoringParserTests(unittest.TestCase):
    def test_syslog_fixture_parses_and_quarantines_malformed_line(self):
        lines = (FIXTURES / "syslog.txt").read_text(encoding="utf-8").splitlines()
        records = [parse_syslog_line(source_id="syslog-lab", line=line) for line in lines]
        self.assertEqual(records[0].category, "syslog.link")
        self.assertEqual(records[1].severity, "high")
        self.assertIsInstance(records[2], QuarantinedRecord)
        self.assertEqual(records[2].reason_code, "SYSLOG_PARSE_FAILED")

    def test_suricata_fixture_extracts_metadata_not_raw_message(self):
        lines = (FIXTURES / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()
        event = parse_json_sensor_event(
            source_id="suricata-lab", source_type="suricata_eve", raw_line=lines[0]
        )
        self.assertEqual(event.category, "suricata.alert")
        self.assertEqual(event.severity, "high")
        self.assertTrue(event.message_sha256.startswith("sha256:"))
        self.assertFalse(hasattr(event, "raw_message"))

    def test_zeek_fixture_is_metadata_only(self):
        line = (FIXTURES / "zeek_conn.jsonl").read_text(encoding="utf-8").splitlines()[0]
        event = parse_json_sensor_event(source_id="zeek-lab", source_type="zeek_json", raw_line=line)
        self.assertEqual(event.category, "zeek.conn")
        self.assertEqual(event.severity, "info")


class MonitoringStorageTests(unittest.TestCase):
    def test_schema_and_inventory_are_separate_from_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MonitoringStore(Path(tmp) / "monitoring.sqlite3")
            store.initialize()
            self.assertEqual(store.schema_version(), 1)
            asset = AssetInventoryRecord(
                asset_id="router-store-1",
                role="router",
                management_host="192.0.2.10",
                collector_capabilities=("icmp_echo",),
            ).validate()
            store.upsert_asset(asset)
            loaded = store.get_asset(asset.asset_id)
            self.assertEqual(loaded.management_host, "192.0.2.10")
            self.assertEqual(store.count("approved_assets"), 1)
            self.assertEqual(store.count("observations"), 0)

    def test_quarantine_metadata_does_not_store_raw_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MonitoringStore(Path(tmp) / "monitoring.sqlite3")
            store.initialize()
            record = parse_syslog_line(source_id="syslog-lab", line="RAW_PRIVATE_PAYLOAD malformed")
            self.assertIsInstance(record, QuarantinedRecord)
            store.add_quarantine(record)
            self.assertEqual(store.count("quarantine"), 1)
            with store.connect() as conn:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(quarantine)").fetchall()}
            self.assertNotIn("raw_payload", columns)


if __name__ == "__main__":
    unittest.main()
