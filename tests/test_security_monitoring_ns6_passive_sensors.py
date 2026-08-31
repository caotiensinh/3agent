import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path

import three_agent.security_monitoring.passive_sensors as passive_sensors
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.passive_sensors import PassiveJsonlSensorAdapter, PassiveSensorConfig


FIXTURES = Path(__file__).parent / "fixtures" / "security_monitoring"


class PassiveSensorAdapterTests(unittest.TestCase):
    def test_zeek_and_suricata_existing_jsonl_are_read_without_sensor_installation(self):
        zeek = PassiveJsonlSensorAdapter(
            PassiveSensorConfig(
                source_id="zeek-synthetic",
                source_type="zeek_json",
                path=(FIXTURES / "zeek_conn.jsonl").resolve(),
                enabled=True,
                expected_interval_seconds=120,
            )
        ).read_batch(evaluated_at="2026-08-30T12:13:00+00:00")
        self.assertEqual(zeek.health.state, "healthy")
        self.assertEqual(zeek.health.events_emitted, 2)
        self.assertTrue(all(event.source_type == "zeek_json" for event in zeek.events))

        suricata = PassiveJsonlSensorAdapter(
            PassiveSensorConfig(
                source_id="suricata-synthetic",
                source_type="suricata_eve",
                path=(FIXTURES / "suricata_eve.jsonl").resolve(),
                enabled=True,
                expected_interval_seconds=120,
            )
        ).read_batch(evaluated_at="2026-08-30T12:12:00+00:00")
        self.assertEqual(suricata.health.state, "healthy")
        self.assertEqual(suricata.events[0].severity, "high")
        self.assertEqual(suricata.events[0].category, "suricata.alert")

    def test_normalized_flow_requires_existing_telemetry_and_never_opens_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flows.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-30T12:12:00+00:00",
                        "flow_type": "netflow",
                        "src_ip": "192.0.2.10",
                        "dst_ip": "192.0.2.20",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            batch = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="existing-flow-export",
                    source_type="flow_json",
                    path=path.resolve(),
                    enabled=True,
                    expected_interval_seconds=120,
                    existing_telemetry_only=True,
                )
            ).read_batch(evaluated_at="2026-08-30T12:13:00+00:00")
            self.assertEqual(batch.health.state, "healthy")
            self.assertEqual(batch.events[0].category, "flow.netflow")
            self.assertNotIn("192.0.2.10", repr(batch.events[0]))

            with self.assertRaisesRegex(MonitoringContractError, "EXISTING_TELEMETRY"):
                PassiveSensorConfig(
                    source_id="listener-not-allowed",
                    source_type="flow_json",
                    path=path.resolve(),
                    enabled=True,
                    existing_telemetry_only=False,
                ).validate()

        source = inspect.getsource(passive_sensors)
        self.assertNotIn("import socket", source)
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("Popen(", source)
        self.assertNotIn("tcpdump", source.casefold())

    def test_sensor_drop_and_stale_health_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "eve.jsonl"
            rows = [
                {
                    "timestamp": "2026-08-30T12:10:00+00:00",
                    "event_type": "stats",
                    "stats": {"capture": {"kernel_drops": 7}},
                },
                {
                    "timestamp": "2026-08-30T12:11:00+00:00",
                    "event_type": "flow",
                },
            ]
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            degraded = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="suricata-drop",
                    source_type="suricata_eve",
                    path=path.resolve(),
                    enabled=True,
                    expected_interval_seconds=120,
                )
            ).read_batch(evaluated_at="2026-08-30T12:12:00+00:00")
            self.assertEqual(degraded.health.state, "degraded")
            self.assertEqual(degraded.health.dropped_records, 7)
            self.assertIn("SENSOR_DROPS_REPORTED", degraded.health.reason_codes)

            stale = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="suricata-stale",
                    source_type="suricata_eve",
                    path=path.resolve(),
                    enabled=True,
                    expected_interval_seconds=60,
                )
            ).read_batch(evaluated_at="2026-08-30T12:20:00+00:00")
            self.assertEqual(stale.health.state, "data_gap")
            self.assertIn("SOURCE_STALE", stale.health.reason_codes)

    def test_disabled_missing_bounded_tail_and_symlink_are_fail_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.jsonl"
            disabled = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="disabled-zeek",
                    source_type="zeek_json",
                    path=missing.resolve(),
                    enabled=False,
                )
            ).read_batch(evaluated_at="2026-08-30T12:13:00+00:00")
            self.assertEqual(disabled.health.state, "disabled")
            self.assertEqual(disabled.health.bytes_read, 0)

            gap = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="missing-zeek",
                    source_type="zeek_json",
                    path=missing.resolve(),
                    enabled=True,
                )
            ).read_batch(evaluated_at="2026-08-30T12:13:00+00:00")
            self.assertEqual(gap.health.state, "data_gap")
            self.assertEqual(gap.health.reason_codes, ("SENSOR_INPUT_MISSING",))

            large = root / "large-flow.jsonl"
            rows = []
            for index in range(100):
                rows.append(
                    json.dumps(
                        {
                            "timestamp": f"2026-08-30T12:12:{index % 60:02d}+00:00",
                            "flow_type": "ipfix",
                            "padding": "x" * 96,
                        }
                    )
                )
            large.write_text("\n".join(rows) + "\n", encoding="utf-8")
            bounded = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="bounded-flow",
                    source_type="flow_json",
                    path=large.resolve(),
                    enabled=True,
                    expected_interval_seconds=120,
                    max_read_bytes=4096,
                    max_records=5,
                )
            ).read_batch(evaluated_at="2026-08-30T12:14:00+00:00")
            self.assertLessEqual(bounded.health.bytes_read, 4096)
            self.assertLessEqual(bounded.health.records_examined, 5)
            self.assertTrue(bounded.health.tail_truncated)
            self.assertIn("BOUNDED_TAIL_WINDOW", bounded.health.reason_codes)

            target = root / "target.jsonl"
            target.write_text(rows[-1] + "\n", encoding="utf-8")
            link = root / "link.jsonl"
            try:
                os.symlink(target, link)
            except OSError:
                self.skipTest("symlink creation unavailable on this platform")
            with self.assertRaisesRegex(MonitoringContractError, "SYMLINK"):
                PassiveJsonlSensorAdapter(
                    PassiveSensorConfig(
                        source_id="linked-flow",
                        source_type="flow_json",
                        path=link.absolute(),
                        enabled=True,
                    )
                ).read_batch(evaluated_at="2026-08-30T12:13:00+00:00")

    def test_invalid_or_oversized_records_are_quarantined_without_raw_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flows.jsonl"
            secret_marker = "DO-NOT-STORE-RAW-PAYLOAD"
            path.write_text(secret_marker + "\n", encoding="utf-8")
            batch = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="bad-flow",
                    source_type="flow_json",
                    path=path.resolve(),
                    enabled=True,
                )
            ).read_batch(evaluated_at="2026-08-30T12:13:00+00:00")
            self.assertEqual(batch.health.state, "data_gap")
            self.assertEqual(batch.health.quarantined_records, 1)
            self.assertNotIn(secret_marker, repr(batch))
            self.assertRegex(batch.quarantined[0].payload_sha256, r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
