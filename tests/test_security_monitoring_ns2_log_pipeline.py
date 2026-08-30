import gzip
import os
import tempfile
import time
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.log_pipeline import (
    BoundedLogSpool,
    BoundedRetentionWorker,
    DeterministicEventRuleEngine,
    EventRule,
    EvidencePartitionWriter,
    SpoolFull,
    deterministic_template,
    evaluate_source_freshness,
)

SHA = "sha256:" + "a" * 64


def event(event_id="evt-1", *, severity="high", category="suricata.alert", source_type="suricata_eve"):
    return CanonicalEvent(
        event_id=event_id,
        source_id="sensor-1",
        source_type=source_type,
        observed_at="2026-08-30T12:00:00+00:00",
        category=category,
        severity=severity,
        message_sha256=SHA,
        parser_version="parser-v1",
        evidence_ref="event:abc",
    ).validate()


class LogPipelineTests(unittest.TestCase):
    def test_spool_rotates_and_applies_backpressure_without_deleting_unprocessed_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "spool"
            spool = BoundedLogSpool(root, max_total_bytes=4096, max_file_bytes=1024)
            for _ in range(8):
                spool.append(source_id="syslog-1", raw_line="x" * 200)
            self.assertGreaterEqual(len(spool.ready_files()), 1)
            before = sum(p.stat().st_size for p in root.iterdir())
            with self.assertRaises(SpoolFull):
                while True:
                    spool.append(source_id="syslog-1", raw_line="y" * 250)
            after = sum(p.stat().st_size for p in root.iterdir())
            self.assertGreaterEqual(after, before)

    def test_spool_rejects_oversized_single_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = BoundedLogSpool(Path(tmp) / "spool", max_total_bytes=512 * 1024, max_file_bytes=300 * 1024)
            with self.assertRaises(MonitoringContractError):
                spool.append(source_id="syslog-1", raw_line="z" * (257 * 1024))

    def test_atomic_gzip_partition_has_manifest_digest_and_normalized_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            writer = EvidencePartitionWriter(root, max_records=4, max_uncompressed_bytes=8192)
            receipt = writer.write_events(partition_id="events-20260830-12", events=[event("evt-1"), event("evt-2")])
            final = root / "events-20260830-12.jsonl.gz"
            self.assertTrue(final.exists())
            self.assertEqual(receipt.record_count, 2)
            self.assertTrue(receipt.sha256.startswith("sha256:"))
            with gzip.open(final, "rt", encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn('"event_id":"evt-1"', text)
            self.assertFalse(any(p.suffix == ".tmp" for p in root.iterdir()))

    def test_partition_hard_bounds_fail_closed_and_leave_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            writer = EvidencePartitionWriter(root, max_records=1, max_uncompressed_bytes=4096)
            with self.assertRaises(MonitoringContractError):
                writer.write_events(partition_id="bounded", events=[event("evt-1"), event("evt-2")])
            self.assertFalse((root / "bounded.jsonl.gz").exists())

    def test_template_normalization_is_deterministic_and_cheap(self):
        first = deterministic_template("port 443 from 192.168.1.10 mac aa:bb:cc:dd:ee:ff id 0xAABBCC")
        second = deterministic_template("port 8443 from 10.0.0.7 mac 11:22:33:44:55:66 id 0x123456")
        self.assertEqual(first, second)
        self.assertEqual(first, "port <N> from <IP> mac <MAC> id <HEX>")

    def test_rule_engine_is_exact_and_severity_bounded(self):
        engine = DeterministicEventRuleEngine(
            [
                EventRule("rule-alert-high", source_type="suricata_eve", category="suricata.alert", min_severity="high"),
                EventRule("rule-any-critical", min_severity="critical"),
            ]
        )
        self.assertEqual(engine.match(event()), ("rule-alert-high",))
        self.assertEqual(engine.match(event(severity="critical")), ("rule-alert-high", "rule-any-critical"))
        self.assertEqual(engine.match(event(severity="medium")), ())

    def test_source_freshness_turns_missing_or_stale_input_into_data_gap_semantics(self):
        missing = evaluate_source_freshness(
            source_id="syslog-1", expected_interval_seconds=60, last_seen_at=None, evaluated_at="2026-08-30T12:00:00+00:00"
        )
        self.assertFalse(missing.fresh)
        self.assertEqual(missing.reason_code, "SOURCE_NEVER_SEEN")
        stale = evaluate_source_freshness(
            source_id="syslog-1", expected_interval_seconds=60,
            last_seen_at="2026-08-30T11:57:00+00:00", evaluated_at="2026-08-30T12:00:00+00:00"
        )
        self.assertFalse(stale.fresh)
        self.assertEqual(stale.reason_code, "SOURCE_STALE")

    def test_retention_is_bounded_and_never_follows_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_time = time.time() - 10000
            for index in range(3):
                path = root / f"p{index}.jsonl.gz"
                path.write_bytes(b"x")
                os.utime(path, (old_time, old_time))
            target = root / "outside.txt"
            target.write_text("KEEP", encoding="utf-8")
            (root / "link.jsonl.gz").symlink_to(target)
            result = BoundedRetentionWorker(root, max_deletes_per_run=2).delete_older_than(cutoff_epoch=time.time() - 100)
            self.assertEqual(len(result.deleted), 2)
            self.assertEqual(result.remaining_candidates, 1)
            self.assertEqual(target.read_text(encoding="utf-8"), "KEEP")


if __name__ == "__main__":
    unittest.main()
