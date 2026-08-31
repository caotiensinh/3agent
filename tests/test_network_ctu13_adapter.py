from __future__ import annotations

import ast
import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.network_ctu13_adapter as ctu_module
from three_agent.network_corpus_adapter import AdapterInputContract, NetworkAdapterIntegrityError
from three_agent.network_ctu13_adapter import (
    CTU13_ADAPTER_VERSION,
    CTU13_COLUMNS,
    CTU13AdapterResourceError,
    CTU13AdapterSchemaError,
    CTU13BidirectionalFlowAdapter,
)


def _row(
    *,
    label: str = "flow=Background-Established-cmpgw-CVUT",
    timestamp: str = "2011/08/10 09:46:53.047277",
    src: str = "147.32.84.170",
    dst: str = "212.24.150.110",
    sport: str = "45833",
    dport: str = "80",
) -> list[str]:
    values = {
        "StartTime": timestamp,
        "Dur": "1.026539",
        "Proto": "tcp",
        "SrcAddr": src,
        "Sport": sport,
        "Dir": "   ->",
        "DstAddr": dst,
        "Dport": dport,
        "State": "S_RA",
        "sTos": "0",
        "dTos": "0",
        "TotPkts": "4",
        "TotBytes": "252",
        "SrcBytes": "132",
        "Label": label,
    }
    return [values[column] for column in CTU13_COLUMNS]


def _write(path: Path, rows: list[list[str]], header: tuple[str, ...] = CTU13_COLUMNS) -> bytes:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)
    return path.read_bytes()


def _contract(payload: bytes, *, dataset_id: str = "ctu-13", variant: str = "bidirectional-netflow",
              adapter_version: str = CTU13_ADAPTER_VERSION) -> AdapterInputContract:
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return AdapterInputContract.from_dict(
        {
            "dataset_id": dataset_id,
            "variant": variant,
            "source_object_ref": "ctu13/scenario-42.binetflow",
            "source_sha256": digest,
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": len(payload) + 1024,
            "acquisition_plan_fingerprint": "sha256:" + "a" * 64,
            "registry_fingerprint": "sha256:" + "b" * 64,
            "policy_fingerprint": "sha256:" + "c" * 64,
            "provenance_ref": "prov://fixture/ctu13-v002",
            "adapter_version": adapter_version,
        }
    )


class CTU13SchemaTests(unittest.TestCase):
    def test_reviewed_schema_is_exact(self):
        self.assertEqual(len(CTU13_COLUMNS), 15)
        self.assertEqual(CTU13_COLUMNS[0], "StartTime")
        self.assertEqual(CTU13_COLUMNS[-1], "Label")

    def test_schema_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "drift.binetflow"
            header = list(CTU13_COLUMNS)
            header[3] = "SourceAddress"
            payload = _write(source, [_row()], tuple(header))
            with self.assertRaises(CTU13AdapterSchemaError):
                CTU13BidirectionalFlowAdapter().inspect(
                    source, authorized_root=root, contract=_contract(payload)
                )

    def test_wrong_dataset_variant_or_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.binetflow"
            payload = _write(source, [_row()])
            cases = (
                {"dataset_id": "cse-cic-ids2018"},
                {"variant": "pcap"},
                {"adapter_version": "ctu-13-bidirectional-netflow/9.9"},
            )
            for kwargs in cases:
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(CTU13AdapterSchemaError):
                        CTU13BidirectionalFlowAdapter().inspect(
                            source, authorized_root=root, contract=_contract(payload, **kwargs)
                        )


class CTU13TruthBoundaryTests(unittest.TestCase):
    def test_label_is_scorer_only_and_flow_is_canonicalized(self):
        label = "flow=From-Botnet-V42-TCP-Attempt"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.binetflow"
            payload = _write(source, [_row(label=label)])
            adapter = CTU13BidirectionalFlowAdapter()
            inspection = adapter.inspect(source, authorized_root=root, contract=_contract(payload))
            item = list(adapter.iterate(source, inspection=inspection))[0]

            visible = item.evidence.as_dict()
            self.assertNotIn("Label", item.evidence.observation_fields)
            self.assertNotIn("label", {key.casefold() for key in item.evidence.observation_fields})
            self.assertNotIn(label, repr(visible))
            self.assertEqual(item.evidence.observation_fields["source_address"], "147.32.84.170")
            self.assertEqual(item.evidence.observation_fields["destination_port"], "80")
            self.assertEqual(item.truth.truth_fields["flow_label"], label)
            self.assertTrue(item.truth.truth_fields["is_botnet"])
            self.assertEqual(item.truth.evidence_refs, (item.evidence.evidence_id,))

    def test_background_and_normal_truth_are_not_inferred_into_evidence(self):
        labels = ("flow=Background-Established", "flow=From-Normal-V42-TCP")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.binetflow"
            payload = _write(source, [_row(label=labels[0]), _row(label=labels[1])])
            adapter = CTU13BidirectionalFlowAdapter()
            inspection = adapter.inspect(source, authorized_root=root, contract=_contract(payload))
            outputs = list(adapter.iterate(source, inspection=inspection))
            self.assertTrue(outputs[0].truth.truth_fields["is_background"])
            self.assertTrue(outputs[1].truth.truth_fields["is_normal"])
            self.assertTrue(all("flow=" not in repr(item.evidence.as_dict()) for item in outputs))


class CTU13ParsingIntegrityAndResourceTests(unittest.TestCase):
    def _run(self, source: Path, root: Path, payload: bytes):
        adapter = CTU13BidirectionalFlowAdapter()
        inspection = adapter.inspect(source, authorized_root=root, contract=_contract(payload))
        return list(adapter.iterate(source, inspection=inspection)), adapter.counters()

    def test_replay_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.binetflow"
            payload = _write(source, [_row(), _row(label="flow=From-Botnet-V42-TCP-Attempt")])
            first, first_counts = self._run(source, root, payload)
            second, second_counts = self._run(source, root, payload)
            self.assertEqual([item.evidence.as_dict() for item in first], [item.evidence.as_dict() for item in second])
            self.assertEqual([item.truth.as_dict() for item in first], [item.truth.as_dict() for item in second])
            self.assertEqual(first_counts, second_counts)

    def test_invalid_numeric_or_byte_invariant_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "bad.binetflow"
            row = _row()
            row[CTU13_COLUMNS.index("TotBytes")] = "100"
            row[CTU13_COLUMNS.index("SrcBytes")] = "101"
            payload = _write(source, [row])
            outputs, counts = self._run(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)
            self.assertEqual(counts.first_error_code, "ROW_BYTE_INVARIANT_INVALID")

    def test_invalid_timestamp_and_blank_label_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "bad.binetflow"
            payload = _write(source, [_row(timestamp="not-a-time"), _row(label="")])
            outputs, counts = self._run(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 2)
            self.assertEqual(counts.records_malformed, 2)

    def test_visible_record_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "two.binetflow"
            payload = _write(source, [_row(), _row(label="flow=Normal")])
            adapter = CTU13BidirectionalFlowAdapter(max_visible_records=1)
            inspection = adapter.inspect(source, authorized_root=root, contract=_contract(payload))
            with self.assertRaises(CTU13AdapterResourceError):
                list(adapter.iterate(source, inspection=inspection))

    def test_same_size_tamper_after_inspection_fails_digest_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.binetflow"
            payload = _write(source, [_row(label="flow=Normal")])
            adapter = CTU13BidirectionalFlowAdapter()
            inspection = adapter.inspect(source, authorized_root=root, contract=_contract(payload))
            tampered = payload.replace(b"flow=Normal", b"flow=Botnet")
            self.assertEqual(len(tampered), len(payload))
            source.write_bytes(tampered)
            with self.assertRaises(NetworkAdapterIntegrityError):
                list(adapter.iterate(source, inspection=inspection))


class CTU13AuthorityTests(unittest.TestCase):
    def test_adapter_has_no_network_model_subprocess_or_malware_execution_authority(self):
        text = inspect.getsource(ctu_module)
        tree = ast.parse(text)
        banned_roots = {"requests", "urllib", "socket", "subprocess", "openai", "ollama", "ctypes"}
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertFalse(imported & banned_roots)
        self.assertNotIn("exec(", text)
        self.assertNotIn("eval(", text)

    def test_adapter_contains_no_unbounded_whole_file_read(self):
        text = inspect.getsource(ctu_module)
        tree = ast.parse(text)
        unbounded = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "read":
                if not node.args and not node.keywords:
                    unbounded.append(node.lineno)
        self.assertEqual(unbounded, [])
        self.assertIn("csv.reader", text)


if __name__ == "__main__":
    unittest.main()
