import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.log_pipeline import EvidencePartitionWriter
from three_agent.security_monitoring.passive_ingest import PassiveSensorIngestor
from three_agent.security_monitoring.passive_sensors import PassiveJsonlSensorAdapter, PassiveSensorConfig
from three_agent.security_monitoring.storage import MonitoringStore


FIXTURES = Path(__file__).parent / "fixtures" / "security_monitoring"


class PassiveSensorIngestTests(unittest.TestCase):
    def test_passive_batch_persists_through_existing_sqlite_and_partition_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = MonitoringStore(root / "monitoring.db")
            writer = EvidencePartitionWriter(root / "evidence", max_records=100, max_uncompressed_bytes=1024 * 1024)
            adapter = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="zeek-existing",
                    source_type="zeek_json",
                    path=(FIXTURES / "zeek_conn.jsonl").resolve(),
                    enabled=True,
                    expected_interval_seconds=120,
                )
            )
            receipt = PassiveSensorIngestor(store=store, partition_writer=writer).ingest(
                adapter=adapter,
                evaluated_at="2026-08-30T12:13:00+00:00",
                partition_id="zeek-existing-20260830T1213Z",
            )
            self.assertEqual(receipt.status, "completed")
            self.assertEqual(receipt.events_accepted, 2)
            self.assertEqual(receipt.records_quarantined, 0)
            self.assertIsNotNone(receipt.partition)
            self.assertEqual(store.count("canonical_events"), 2)
            self.assertEqual(store.count("quarantine"), 0)
            self.assertTrue((root / "evidence" / "zeek-existing-20260830T1213Z.jsonl.gz").is_file())

    def test_missing_sensor_becomes_data_gap_without_creating_partition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = MonitoringStore(root / "monitoring.db")
            writer = EvidencePartitionWriter(root / "evidence")
            adapter = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="missing-sensor",
                    source_type="suricata_eve",
                    path=(root / "missing.jsonl").resolve(),
                    enabled=True,
                )
            )
            receipt = PassiveSensorIngestor(store=store, partition_writer=writer).ingest(
                adapter=adapter,
                evaluated_at="2026-08-30T12:13:00+00:00",
                partition_id="missing-20260830T1213Z",
            )
            self.assertEqual(receipt.status, "data_gap")
            self.assertIsNone(receipt.partition)
            self.assertEqual(store.count("canonical_events"), 0)
            self.assertEqual(store.count("quarantine"), 0)


if __name__ == "__main__":
    unittest.main()
