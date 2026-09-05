import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.security_monitoring.pcap_evidence import (
    BoundedPCAPEvidenceReader,
    MAX_ORIGINAL_PACKET_BYTES,
    PCAPEvidenceDenied,
    PCAPEvidenceError,
    PCAPResource,
    PCAPResourceRegistry,
)


def _classic_pcap(payload: bytes = b"A") -> bytes:
    data = bytearray(b"\xd4\xc3\xb2\xa1")
    data.extend(struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
    data.extend(struct.pack("<IIII", 1_700_000_000, 123_456, len(payload), len(payload)))
    data.extend(payload)
    return bytes(data)


def _registry(root: Path) -> PCAPResourceRegistry:
    return PCAPResourceRegistry(
        root,
        (
            PCAPResource(
                resource_ref="evidence/hardening-001",
                relative_path="capture.pcap",
            ),
        ),
    )


class SecurityPCAPHardeningTests(unittest.TestCase):
    def test_same_size_in_place_change_detected_by_post_read_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(_classic_pcap(b"PRIVATE"))
            reader = BoundedPCAPEvidenceReader(_registry(root))
            real_fstat = os.fstat
            calls = 0

            def changing_fstat(fd):
                nonlocal calls
                current = real_fstat(fd)
                calls += 1
                if calls == 1:
                    return current
                return SimpleNamespace(
                    st_dev=current.st_dev,
                    st_ino=current.st_ino,
                    st_size=current.st_size,
                    st_mtime_ns=current.st_mtime_ns + 1,
                    st_ctime_ns=current.st_ctime_ns,
                )

            with patch("three_agent.security_monitoring.pcap_evidence.os.fstat", side_effect=changing_fstat):
                with self.assertRaisesRegex(PCAPEvidenceDenied, "PCAP_RESOURCE_CHANGED_DURING_READ"):
                    reader.read_capture("evidence/hardening-001")
            self.assertEqual(calls, 2)

    def test_opened_fd_must_still_be_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(_classic_pcap())
            reader = BoundedPCAPEvidenceReader(_registry(root))
            real_fstat = os.fstat

            def non_regular_fstat(fd):
                current = real_fstat(fd)
                return SimpleNamespace(
                    st_mode=stat.S_IFDIR,
                    st_dev=current.st_dev,
                    st_ino=current.st_ino,
                    st_size=current.st_size,
                    st_mtime_ns=current.st_mtime_ns,
                    st_ctime_ns=current.st_ctime_ns,
                )

            with patch("three_agent.security_monitoring.pcap_evidence.os.fstat", side_effect=non_regular_fstat):
                with self.assertRaisesRegex(PCAPEvidenceDenied, "PCAP_RESOURCE_NOT_REGULAR_FILE"):
                    reader.read_metadata("evidence/hardening-001")

    def test_metadata_mode_enforces_original_packet_length_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = bytearray(_classic_pcap(b"A"))
            # Classic PCAP packet header starts at offset 24; original_len is its fourth u32.
            struct.pack_into("<I", capture, 24 + 12, MAX_ORIGINAL_PACKET_BYTES + 1)
            root.joinpath("capture.pcap").write_bytes(capture)
            reader = BoundedPCAPEvidenceReader(_registry(root))

            with self.assertRaisesRegex(PCAPEvidenceError, "PCAP_ORIGINAL_LENGTH_BOUND_EXCEEDED"):
                reader.read_metadata("evidence/hardening-001")

    def test_hardened_reader_preserves_metadata_only_output_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(_classic_pcap(b"SENSITIVE-PAYLOAD"))
            evidence = BoundedPCAPEvidenceReader(_registry(root)).read_metadata("evidence/hardening-001")

            self.assertEqual(evidence.mode, "metadata")
            self.assertEqual(evidence.packet_count, 1)
            self.assertEqual(evidence.packets, ())
            self.assertNotIn("SENSITIVE-PAYLOAD", evidence.to_json())


if __name__ == "__main__":
    unittest.main()
