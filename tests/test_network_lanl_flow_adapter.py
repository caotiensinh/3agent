from __future__ import annotations

import ast
import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.network_lanl_flow_adapter as flow_module
from three_agent.network_corpus_adapter import (
    AdapterInputContract,
    NetworkAdapterIntegrityError,
)
from three_agent.network_lanl_adapter import (
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
)
from three_agent.network_lanl_family import LANLSourceFamilySchemaError
from three_agent.network_lanl_flow_adapter import (
    LANL_FLOW_ADAPTER_VERSION,
    LANLFlowAdapter,
    lanl_nonnegative_integer,
)


def _row(
    *,
    time: str = "1",
    duration: str = "0",
    source_computer: str = "C17693",
    source_port: str = "N123",
    destination_computer: str = "C200",
    destination_port: str = "443",
    protocol: str = "6",
    packet_count: str = "10",
    byte_count: str = "2048",
) -> list[str]:
    return [
        time,
        duration,
        source_computer,
        source_port,
        destination_computer,
        destination_port,
        protocol,
        packet_count,
        byte_count,
    ]


def _write_rows(path: Path, rows: list[list[str]]) -> bytes:
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, lineterminator="\n").writerows(rows)
    return path.read_bytes()


def _contract(
    payload: bytes,
    *,
    source_object_ref: str = "lanl/flow/shard-0001.txt",
    dataset_id: str = "lanl-comprehensive",
    variant: str = "events",
    adapter_version: str = LANL_FLOW_ADAPTER_VERSION,
) -> AdapterInputContract:
    return AdapterInputContract.from_dict(
        {
            "dataset_id": dataset_id,
            "variant": variant,
            "source_object_ref": source_object_ref,
            "source_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": len(payload) + 1024,
            "acquisition_plan_fingerprint": "sha256:" + ("a" * 64),
            "registry_fingerprint": "sha256:" + ("b" * 64),
            "policy_fingerprint": "sha256:" + ("c" * 64),
            "provenance_ref": "prov://fixture/lanl-flow-v3-02c",
            "adapter_version": adapter_version,
        }
    )


class LANLFlowSchemaTests(unittest.TestCase):
    def test_valid_well_known_and_anonymized_ports_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "flow.txt"
            payload = _write_rows(source, [_row()])
            adapter = LANLFlowAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]

            self.assertEqual(evidence.timestamp, "lanl:T+1s")
            self.assertEqual(evidence.source_domain, "network_flow")
            self.assertEqual(evidence.event_family, "network_flow")
            self.assertEqual(evidence.event_type, "lanl_router_flow")
            self.assertEqual(
                evidence.asset_refs,
                ("lanl:computer:C17693", "lanl:computer:C200"),
            )
            self.assertEqual(
                evidence.network_refs,
                ("lanl:port:N123", "lanl:port:443", "lanl:protocol:6"),
            )
            self.assertEqual(evidence.observation_fields["source_port"], "N123")
            self.assertEqual(evidence.observation_fields["destination_port"], "443")
            self.assertEqual(evidence.observation_fields["packet_count"], 10)
            self.assertEqual(evidence.observation_fields["byte_count"], 2048)

    def test_unknown_optional_port_and_protocol_remain_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "flow.txt"
            payload = _write_rows(
                source,
                [_row(source_port="?", destination_port="?", protocol="?")],
            )
            adapter = LANLFlowAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]
            self.assertIsNone(evidence.observation_fields["source_port"])
            self.assertIsNone(evidence.observation_fields["destination_port"])
            self.assertIsNone(evidence.observation_fields["protocol"])
            self.assertEqual(evidence.network_refs, ())

    def test_wrong_field_count_fails_schema_on_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "flow.txt"
            payload = _write_rows(source, [_row()[:-1]])
            with self.assertRaises(LANLAdapterSchemaError):
                LANLFlowAdapter().inspect(
                    source, authorized_root=root, contract=_contract(payload)
                )

    def test_auth_namespace_is_rejected_even_with_nine_field_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.txt"
            payload = _write_rows(
                source,
                [[
                    "1",
                    "U1@DOM1",
                    "U2@DOM1",
                    "C1",
                    "C2",
                    "Kerberos",
                    "Network",
                    "LogOn",
                    "Success",
                ]],
            )
            with self.assertRaises(LANLSourceFamilySchemaError):
                LANLFlowAdapter().inspect(
                    source,
                    authorized_root=root,
                    contract=_contract(
                        payload,
                        source_object_ref="lanl/auth/shard-0001.txt",
                    ),
                )


class LANLFlowNumericTests(unittest.TestCase):
    def test_nonnegative_integer_parser_does_not_silently_coerce(self):
        self.assertEqual(lanl_nonnegative_integer("0", "duration_seconds"), 0)
        self.assertEqual(lanl_nonnegative_integer("42", "packet_count"), 42)
        for raw in ("?", "", "-1", "1.5", "NaN", "Infinity", "abc"):
            with self.subTest(raw=raw):
                with self.assertRaises(LANLAdapterSchemaError):
                    lanl_nonnegative_integer(raw, "packet_count")

    def test_negative_duration_packets_and_bytes_are_rejected(self):
        bad_rows = (
            _row(duration="-1"),
            _row(packet_count="-1"),
            _row(byte_count="-1"),
        )
        for row in bad_rows:
            with self.subTest(row=row):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    source = root / "flow.txt"
                    payload = _write_rows(source, [row])
                    adapter = LANLFlowAdapter()
                    inspection = adapter.inspect(
                        source, authorized_root=root, contract=_contract(payload)
                    )
                    outputs = list(adapter.iterate(source, inspection=inspection))
                    self.assertEqual(outputs, [])
                    self.assertEqual(adapter.counters().records_rejected, 1)
                    self.assertEqual(
                        adapter.counters().first_error_code,
                        "FLOW_REQUIRED_FIELD_INVALID",
                    )

    def test_unknown_required_computer_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "flow.txt"
            payload = _write_rows(source, [_row(source_computer="?")])
            adapter = LANLFlowAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            self.assertEqual(list(adapter.iterate(source, inspection=inspection)), [])
            self.assertEqual(adapter.counters().records_rejected, 1)


class LANLFlowDeterminismIntegrityTests(unittest.TestCase):
    def _run_once(self, source: Path, root: Path, payload: bytes):
        adapter = LANLFlowAdapter()
        inspection = adapter.inspect(
            source, authorized_root=root, contract=_contract(payload)
        )
        return list(adapter.iterate(source, inspection=inspection))

    def test_replay_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "flow.txt"
            payload = _write_rows(source, [_row(), _row(time="2", byte_count="4096")])
            first = self._run_once(source, root, payload)
            second = self._run_once(source, root, payload)
            self.assertEqual(
                [item.as_dict() for item in first],
                [item.as_dict() for item in second],
            )

    def test_visible_record_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "flow.txt"
            payload = _write_rows(source, [_row(), _row(time="2")])
            adapter = LANLFlowAdapter(max_visible_records=1)
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterResourceError):
                list(adapter.iterate(source, inspection=inspection))

    def test_same_size_tamper_after_inspection_fails_digest_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "flow.txt"
            payload = _write_rows(source, [_row(byte_count="2048")])
            adapter = LANLFlowAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            tampered = payload.replace(b"2048", b"2049")
            self.assertEqual(len(tampered), len(payload))
            source.write_bytes(tampered)
            with self.assertRaises(NetworkAdapterIntegrityError):
                list(adapter.iterate(source, inspection=inspection))


class LANLFlowAuthorityTests(unittest.TestCase):
    def test_adapter_ast_has_no_network_model_subprocess_or_whole_file_read_authority(self):
        text = inspect.getsource(flow_module)
        tree = ast.parse(text)
        forbidden_roots = {
            "requests",
            "urllib",
            "socket",
            "subprocess",
            "openai",
            "ollama",
            "pandas",
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
