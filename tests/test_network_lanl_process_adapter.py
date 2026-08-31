from __future__ import annotations

import ast
import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.network_lanl_process_adapter as process_module
from three_agent.network_corpus_adapter import (
    AdapterInputContract,
    NetworkAdapterIntegrityError,
)
from three_agent.network_lanl_adapter import (
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
)
from three_agent.network_lanl_process_adapter import (
    LANL_PROCESS_ADAPTER_VERSION,
    LANLProcessAdapter,
)


def _row(
    *,
    time: str = "1",
    user_domain: str = "U748@DOM1",
    computer: str = "C17693",
    process_name: str = "P16",
    start_end: str = "Start",
) -> list[str]:
    return [time, user_domain, computer, process_name, start_end]


def _write_rows(path: Path, rows: list[list[str]]) -> bytes:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerows(rows)
    return path.read_bytes()


def _contract(
    payload: bytes,
    *,
    dataset_id: str = "lanl-comprehensive",
    variant: str = "events",
    adapter_version: str = LANL_PROCESS_ADAPTER_VERSION,
) -> AdapterInputContract:
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return AdapterInputContract.from_dict(
        {
            "dataset_id": dataset_id,
            "variant": variant,
            "source_object_ref": "lanl/process/shard-0001.txt",
            "source_sha256": digest,
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": max(1, len(payload) + 1024),
            "acquisition_plan_fingerprint": "sha256:" + ("a" * 64),
            "registry_fingerprint": "sha256:" + ("b" * 64),
            "policy_fingerprint": "sha256:" + ("c" * 64),
            "provenance_ref": "prov://fixture/lanl-process-v3-02c",
            "adapter_version": adapter_version,
        }
    )


class LANLProcessSchemaTests(unittest.TestCase):
    def test_start_event_emits_observation_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row()])
            adapter = LANLProcessAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]

            self.assertEqual(evidence.timestamp, "lanl:T+1s")
            self.assertEqual(evidence.source_domain, "host_process")
            self.assertEqual(evidence.event_family, "process")
            self.assertEqual(evidence.event_type, "lanl_process_lifecycle")
            self.assertEqual(evidence.asset_refs, ("lanl:computer:C17693",))
            self.assertEqual(evidence.account_refs, ("lanl:user:U748@DOM1",))
            self.assertEqual(evidence.network_refs, ())
            self.assertEqual(evidence.observation_fields["process_name"], "P16")
            self.assertEqual(evidence.observation_fields["start_end"], "Start")
            visible = repr(evidence.as_dict()).casefold()
            self.assertNotIn("redteam", visible)
            self.assertNotIn("attack_label", visible)
            self.assertNotIn("ground_truth", visible)

    def test_end_event_is_preserved_as_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row(time="2", start_end="End")])
            adapter = LANLProcessAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]
            self.assertEqual(evidence.timestamp, "lanl:T+2s")
            self.assertEqual(evidence.observation_fields["start_end"], "End")

    def test_unknown_optional_fields_remain_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(
                source,
                [_row(user_domain="?", process_name="?", start_end="?")],
            )
            adapter = LANLProcessAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]
            fields = evidence.observation_fields
            self.assertIsNone(fields["user_domain"])
            self.assertIsNone(fields["process_name"])
            self.assertIsNone(fields["start_end"])
            self.assertEqual(evidence.account_refs, ())
            self.assertEqual(evidence.asset_refs, ("lanl:computer:C17693",))

    def test_wrong_field_count_fails_closed_during_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row()[:-1]])
            with self.assertRaises(LANLAdapterSchemaError):
                LANLProcessAdapter().inspect(
                    source, authorized_root=root, contract=_contract(payload)
                )

    def test_wrong_dataset_variant_or_adapter_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row()])
            for kwargs in (
                {"dataset_id": "cse-cic-ids2018"},
                {"variant": "process"},
                {"adapter_version": "lanl-comprehensive-process/9.9"},
            ):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(LANLAdapterSchemaError):
                        LANLProcessAdapter().inspect(
                            source,
                            authorized_root=root,
                            contract=_contract(payload, **kwargs),
                        )


class LANLProcessParsingTests(unittest.TestCase):
    def _run_once(self, source: Path, root: Path, payload: bytes):
        adapter = LANLProcessAdapter()
        inspection = adapter.inspect(
            source, authorized_root=root, contract=_contract(payload)
        )
        return list(adapter.iterate(source, inspection=inspection)), adapter.counters()

    def test_replay_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(
                source,
                [
                    _row(),
                    _row(
                        time="2",
                        user_domain="U100@DOM1",
                        computer="C200",
                        process_name="P42",
                        start_end="End",
                    ),
                ],
            )
            first, first_counts = self._run_once(source, root, payload)
            second, second_counts = self._run_once(source, root, payload)
            self.assertEqual(
                [item.as_dict() for item in first],
                [item.as_dict() for item in second],
            )
            self.assertEqual(first_counts, second_counts)

    def test_invalid_time_record_is_rejected_not_synthesized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row(time="0")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)
            self.assertEqual(
                counts.first_error_code,
                "PROCESS_REQUIRED_FIELD_INVALID",
            )

    def test_unknown_required_computer_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row(computer="?")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)

    def test_invalid_lifecycle_value_is_rejected_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row(start_end="Spawn")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)
            self.assertEqual(counts.first_error_code, "PROCESS_LIFECYCLE_INVALID")

    def test_visible_record_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row(), _row(time="2")])
            adapter = LANLProcessAdapter(max_visible_records=1)
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterResourceError):
                list(adapter.iterate(source, inspection=inspection))


class LANLProcessIntegrityTests(unittest.TestCase):
    def test_same_size_tamper_after_inspection_fails_digest_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row(process_name="P16")])
            adapter = LANLProcessAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            tampered = payload.replace(b"P16", b"P17")
            self.assertEqual(len(tampered), len(payload))
            source.write_bytes(tampered)
            with self.assertRaises(NetworkAdapterIntegrityError):
                list(adapter.iterate(source, inspection=inspection))

    def test_iterate_requires_successful_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proc.txt"
            payload = _write_rows(source, [_row()])
            inspection = LANLProcessAdapter().inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterSchemaError):
                list(LANLProcessAdapter().iterate(source, inspection=inspection))


class LANLProcessAuthorityTests(unittest.TestCase):
    def test_adapter_ast_has_no_network_model_subprocess_or_whole_file_read_authority(self):
        text = inspect.getsource(process_module)
        tree = ast.parse(text)
        forbidden_roots = {
            "requests",
            "urllib",
            "socket",
            "subprocess",
            "openai",
            "ollama",
        }
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "read"
                and not node.args
                and not node.keywords
            ):
                self.fail("unbounded whole-file read() authority found")
        self.assertTrue(forbidden_roots.isdisjoint(imported_roots))
        self.assertIn("csv.reader", text)


if __name__ == "__main__":
    unittest.main()
