import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from three_agent.benchmark_readiness import (
    READINESS_SCHEMA,
    BenchmarkReadinessError,
    BenchmarkReadinessProbe,
    load_readiness_receipt,
    validate_readiness_receipt,
)


SOURCE = "a" * 40
MODEL = "qwen3:30b"


class FakeRunner:
    def __init__(self, mapping=None, missing=None):
        self.mapping = dict(mapping or {})
        self.missing = set(missing or ())

    def __call__(self, argv, cwd):
        del cwd
        key = tuple(argv)
        if key in self.missing:
            raise FileNotFoundError(key[0])
        if key not in self.mapping:
            raise AssertionError(f"unexpected command: {key}")
        return self.mapping[key]


def command_map(*, head=SOURCE, status="", gpu_rows=None, ollama_version="ollama version is 0.11.4"):
    if gpu_rows is None:
        gpu_rows = (
            "NVIDIA GeForce RTX 5090, 590.44, 32607\n"
            "NVIDIA GeForce RTX 5090, 590.44, 32607\n"
        )
    return {
        ("git", "rev-parse", "HEAD"): head + "\n",
        ("git", "status", "--porcelain", "--untracked-files=no"): status,
        (
            "nvidia-smi",
            "--query-gpu=name,driver_version,memory.total",
            "--format=csv,noheader,nounits",
        ): gpu_rows,
        ("ollama", "--version"): ollama_version + "\n",
        ("ollama", "show", MODEL): "PRIVATE_MODEL_METADATA_MUST_NOT_BE_RECORDED\n",
    }


def fixed_clock():
    return datetime(2026, 8, 29, 7, 0, 0, tzinfo=timezone.utc)


class BenchmarkReadinessProbeTests(unittest.TestCase):
    def test_ready_receipt_is_metadata_only_and_fingerprinted(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = BenchmarkReadinessProbe(
                Path(tmp),
                runner=FakeRunner(command_map()),
                clock=fixed_clock,
            ).collect(source_ref=SOURCE, model=MODEL)

        self.assertEqual(receipt["schema_version"], READINESS_SCHEMA)
        self.assertTrue(receipt["ready"])
        self.assertEqual(receipt["failures"], [])
        self.assertEqual(receipt["environment"]["gpu_count"], 2)
        self.assertEqual(receipt["environment"]["matching_rtx5090_count"], 2)
        self.assertEqual(
            {gpu["driver_version"] for gpu in receipt["environment"]["gpus"]},
            {"590.44"},
        )
        self.assertEqual(receipt["environment"]["model"], MODEL)
        self.assertTrue(receipt["environment"]["model_preinstalled"])
        self.assertTrue(receipt["environment_sha256"].startswith("sha256:"))
        self.assertTrue(receipt["receipt_sha256"].startswith("sha256:"))
        encoded = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("PRIVATE_MODEL_METADATA", encoded)
        self.assertNotIn("hostname", encoded.lower().replace("hostname_recorded", ""))
        self.assertTrue(all(value is False for value in receipt["privacy"].values()))
        validate_readiness_receipt(receipt, expected_source_ref=SOURCE)

    def test_environment_fingerprint_ignores_capture_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = BenchmarkReadinessProbe(
                root,
                runner=FakeRunner(command_map()),
                clock=lambda: datetime(2026, 8, 29, 7, 0, tzinfo=timezone.utc),
            ).collect(source_ref=SOURCE, model=MODEL)
            second = BenchmarkReadinessProbe(
                root,
                runner=FakeRunner(command_map()),
                clock=lambda: datetime(2026, 8, 29, 8, 0, tzinfo=timezone.utc),
            ).collect(source_ref=SOURCE, model=MODEL)
        self.assertEqual(first["environment_sha256"], second["environment_sha256"])
        self.assertNotEqual(first["receipt_sha256"], second["receipt_sha256"])

    def test_one_rtx5090_fails_closed(self):
        mapping = command_map(gpu_rows="NVIDIA GeForce RTX 5090, 590.44, 32607\n")
        with tempfile.TemporaryDirectory() as tmp:
            receipt = BenchmarkReadinessProbe(
                Path(tmp), runner=FakeRunner(mapping), clock=fixed_clock
            ).collect(source_ref=SOURCE, model=MODEL)
        self.assertFalse(receipt["ready"])
        self.assertIn("DUAL_RTX5090_REQUIRED", receipt["failures"])
        self.assertFalse(receipt["checks"]["dual_rtx5090_available"])
        with self.assertRaisesRegex(BenchmarkReadinessError, "not ready"):
            validate_readiness_receipt(receipt)
        validate_readiness_receipt(receipt, require_ready=False)

    def test_mixed_matching_gpu_driver_versions_fail_closed(self):
        mapping = command_map(
            gpu_rows=(
                "NVIDIA GeForce RTX 5090, 590.44, 32607\n"
                "NVIDIA GeForce RTX 5090, 595.84, 32607\n"
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            receipt = BenchmarkReadinessProbe(
                Path(tmp), runner=FakeRunner(mapping), clock=fixed_clock
            ).collect(source_ref=SOURCE, model=MODEL)
        self.assertFalse(receipt["ready"])
        self.assertIn("GPU_DRIVER_VERSION_MISMATCH", receipt["failures"])
        self.assertFalse(receipt["checks"]["uniform_matching_gpu_driver"])

    def test_source_mismatch_and_dirty_checkout_are_explicit(self):
        mapping = command_map(head="b" * 40, status=" M src/three_agent/x.py\n")
        with tempfile.TemporaryDirectory() as tmp:
            receipt = BenchmarkReadinessProbe(
                Path(tmp), runner=FakeRunner(mapping), clock=fixed_clock
            ).collect(source_ref=SOURCE, model=MODEL)
        self.assertFalse(receipt["ready"])
        self.assertIn("SOURCE_REF_MISMATCH", receipt["failures"])
        self.assertIn("TRACKED_WORKTREE_DIRTY", receipt["failures"])

    def test_missing_model_does_not_leak_command_error_text(self):
        mapping = command_map()
        missing = {("ollama", "show", MODEL)}
        with tempfile.TemporaryDirectory() as tmp:
            receipt = BenchmarkReadinessProbe(
                Path(tmp),
                runner=FakeRunner(mapping, missing=missing),
                clock=fixed_clock,
            ).collect(source_ref=SOURCE, model=MODEL)
        self.assertFalse(receipt["ready"])
        self.assertIn("OLLAMA_MODEL_NOT_AVAILABLE", receipt["failures"])
        self.assertFalse(receipt["environment"]["model_preinstalled"])
        self.assertNotIn("FileNotFoundError", json.dumps(receipt))

    def test_tampered_environment_or_receipt_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = BenchmarkReadinessProbe(
                Path(tmp), runner=FakeRunner(command_map()), clock=fixed_clock
            ).collect(source_ref=SOURCE, model=MODEL)
        tampered = json.loads(json.dumps(receipt))
        tampered["environment"]["gpus"][0]["memory_total_mib"] += 1
        with self.assertRaisesRegex(BenchmarkReadinessError, "environment fingerprint"):
            validate_readiness_receipt(tampered)

        tampered = json.loads(json.dumps(receipt))
        tampered["captured_at_utc"] = "2026-08-29T09:00:00Z"
        with self.assertRaisesRegex(BenchmarkReadinessError, "receipt fingerprint"):
            validate_readiness_receipt(tampered)

    def test_receipt_round_trip_load_binds_exact_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            receipt = BenchmarkReadinessProbe(
                root, runner=FakeRunner(command_map()), clock=fixed_clock
            ).collect(source_ref=SOURCE, model=MODEL)
            path = root / "environment.json"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            loaded = load_readiness_receipt(path, expected_source_ref=SOURCE)
            self.assertEqual(loaded["receipt_sha256"], receipt["receipt_sha256"])
            with self.assertRaisesRegex(BenchmarkReadinessError, "does not match"):
                load_readiness_receipt(path, expected_source_ref="b" * 40)


if __name__ == "__main__":
    unittest.main()
