from __future__ import annotations

import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.network_cic_adapter as cic_module
from three_agent.network_cic_adapter import (
    CIC_ADAPTER_VERSION,
    CIC_COLUMNS,
    CICAdapterResourceError,
    CICAdapterSchemaError,
    CSECICIDS2018Adapter,
)
from three_agent.network_corpus_adapter import (
    AdapterInputContract,
    NetworkAdapterIntegrityError,
)


def _row(*, label: str = "Benign", timestamp: str = "14/02/2018 08:31:00") -> list[str]:
    values = {column: "1" for column in CIC_COLUMNS}
    values["Dst Port"] = "443"
    values["Protocol"] = "6"
    values["Timestamp"] = timestamp
    values["Flow Duration"] = "141385"
    values["Tot Fwd Pkts"] = "9"
    values["Tot Bwd Pkts"] = "7"
    values["Fwd Pkt Len Mean"] = "61.444444"
    values["Flow Byts/s"] = "30597.30523"
    values["Label"] = label
    return [values[column] for column in CIC_COLUMNS]


def _write_csv(path: Path, rows: list[list[str]], header: tuple[str, ...] = CIC_COLUMNS) -> bytes:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)
    return path.read_bytes()


def _contract(payload: bytes, *, dataset_id: str = "cse-cic-ids2018",
              variant: str = "processed-ml",
              adapter_version: str = CIC_ADAPTER_VERSION) -> AdapterInputContract:
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return AdapterInputContract.from_dict(
        {
            "dataset_id": dataset_id,
            "variant": variant,
            "source_object_ref": "cic/fixture.csv",
            "source_sha256": digest,
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": max(1, len(payload) + 1024),
            "acquisition_plan_fingerprint": "sha256:" + ("a" * 64),
            "registry_fingerprint": "sha256:" + ("b" * 64),
            "policy_fingerprint": "sha256:" + ("c" * 64),
            "provenance_ref": "prov://fixture/cic-v3-02b",
            "adapter_version": adapter_version,
        }
    )


class CICSchemaContractTests(unittest.TestCase):
    def test_reviewed_processed_ml_schema_has_exactly_80_columns(self):
        self.assertEqual(len(CIC_COLUMNS), 80)
        self.assertEqual(CIC_COLUMNS[:4], ("Dst Port", "Protocol", "Timestamp", "Flow Duration"))
        self.assertEqual(CIC_COLUMNS[-1], "Label")
        self.assertNotIn("Src IP", CIC_COLUMNS)
        self.assertNotIn("Dst IP", CIC_COLUMNS)

    def test_schema_drift_fails_closed_during_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "drift.csv"
            header = list(CIC_COLUMNS)
            header[0] = "Destination Port"
            payload = _write_csv(source, [_row()], tuple(header))
            adapter = CSECICIDS2018Adapter()
            with self.assertRaises(CICAdapterSchemaError):
                adapter.inspect(
                    source,
                    authorized_root=root,
                    contract=_contract(payload),
                )

    def test_wrong_dataset_variant_or_adapter_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.csv"
            payload = _write_csv(source, [_row()])
            for kwargs in (
                {"dataset_id": "lanl-comprehensive"},
                {"variant": "raw-pcap"},
                {"adapter_version": "cse-cic-ids2018-processed-ml/9.9"},
            ):
                with self.subTest(kwargs=kwargs):
                    adapter = CSECICIDS2018Adapter()
                    with self.assertRaises(CICAdapterSchemaError):
                        adapter.inspect(
                            source,
                            authorized_root=root,
                            contract=_contract(payload, **kwargs),
                        )


class CICTruthBoundaryTests(unittest.TestCase):
    def test_benign_label_is_scorer_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.csv"
            payload = _write_csv(source, [_row(label="Benign")])
            adapter = CSECICIDS2018Adapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            outputs = list(adapter.iterate(source, inspection=inspection))
            self.assertEqual(len(outputs), 1)
            item = outputs[0]
            self.assertNotIn("Label", item.evidence.observation_fields)
            self.assertNotIn("label", {k.casefold() for k in item.evidence.observation_fields})
            self.assertEqual(item.truth.truth_fields["attack_class"], "Benign")
            self.assertTrue(item.truth.truth_fields["is_benign"])
            self.assertEqual(item.truth.evidence_refs, (item.evidence.evidence_id,))

    def test_attack_label_never_enters_visible_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "attack.csv"
            payload = _write_csv(source, [_row(label="Bot")])
            adapter = CSECICIDS2018Adapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            item = list(adapter.iterate(source, inspection=inspection))[0]
            visible_text = repr(item.evidence.as_dict())
            self.assertNotIn("'Bot'", visible_text)
            self.assertEqual(item.truth.truth_fields["attack_class"], "Bot")
            self.assertFalse(item.truth.truth_fields["is_benign"])

    def test_adapter_does_not_fabricate_missing_ip_or_asset_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.csv"
            payload = _write_csv(source, [_row()])
            adapter = CSECICIDS2018Adapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0].evidence
            self.assertEqual(evidence.asset_refs, ())
            self.assertEqual(evidence.account_refs, ())
            self.assertEqual(
                evidence.network_refs,
                ("dst_port=443", "protocol=6"),
            )


class CICDeterminismAndParsingTests(unittest.TestCase):
    def _run_once(self, source: Path, root: Path, payload: bytes):
        adapter = CSECICIDS2018Adapter()
        inspection = adapter.inspect(
            source, authorized_root=root, contract=_contract(payload)
        )
        outputs = list(adapter.iterate(source, inspection=inspection))
        return outputs, adapter.counters()

    def test_replay_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.csv"
            payload = _write_csv(source, [_row(label="Benign"), _row(label="Bot")])
            first, first_counts = self._run_once(source, root, payload)
            second, second_counts = self._run_once(source, root, payload)
            self.assertEqual(
                [x.evidence.as_dict() for x in first],
                [x.evidence.as_dict() for x in second],
            )
            self.assertEqual(
                [x.truth.as_dict() for x in first],
                [x.truth.as_dict() for x in second],
            )
            self.assertEqual(first_counts, second_counts)

    def test_invalid_required_numeric_field_is_rejected_not_zeroed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "bad-number.csv"
            row = _row()
            row[CIC_COLUMNS.index("Flow Duration")] = "not-a-number"
            payload = _write_csv(source, [row])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)
            self.assertEqual(counts.records_malformed, 1)
            self.assertEqual(counts.first_error_code, "ROW_REQUIRED_FIELD_INVALID")

    def test_non_finite_numeric_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "nonfinite.csv"
            row = _row()
            row[CIC_COLUMNS.index("Flow Byts/s")] = "Infinity"
            payload = _write_csv(source, [row])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)

    def test_invalid_timestamp_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "bad-time.csv"
            payload = _write_csv(source, [_row(timestamp="not-a-time")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)

    def test_blank_label_is_rejected_instead_of_inferred(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "blank-label.csv"
            payload = _write_csv(source, [_row(label="")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)
            self.assertEqual(counts.first_error_code, "LABEL_MISSING")

    def test_row_column_count_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "short-row.csv"
            payload = _write_csv(source, [_row()[:-1]])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_malformed, 1)
            self.assertEqual(counts.first_error_code, "ROW_COLUMN_COUNT")

    def test_visible_record_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "two.csv"
            payload = _write_csv(source, [_row(), _row(label="Bot")])
            adapter = CSECICIDS2018Adapter(max_visible_records=1)
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(CICAdapterResourceError):
                list(adapter.iterate(source, inspection=inspection))


class CICIntegrityBoundaryTests(unittest.TestCase):
    def test_same_size_tamper_after_inspection_fails_digest_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.csv"
            payload = _write_csv(source, [_row(label="Benign")])
            adapter = CSECICIDS2018Adapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            tampered = payload.replace(b"Benign", b"Attack")
            self.assertEqual(len(tampered), len(payload))
            source.write_bytes(tampered)
            with self.assertRaises(NetworkAdapterIntegrityError):
                list(adapter.iterate(source, inspection=inspection))

    def test_iterate_requires_successful_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.csv"
            payload = _write_csv(source, [_row()])
            inspection = CSECICIDS2018Adapter().inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            fresh = CSECICIDS2018Adapter()
            with self.assertRaises(CICAdapterSchemaError):
                list(fresh.iterate(source, inspection=inspection))


class CICAuthorityTests(unittest.TestCase):
    def test_adapter_source_contains_no_network_model_subprocess_or_whole_file_read(self):
        text = inspect.getsource(cic_module)
        lowered = text.casefold()
        self.assertNotIn("import requests", text)
        self.assertNotIn("import urllib", text)
        self.assertNotIn("import socket", text)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("ollama", lowered)
        self.assertNotIn("openai", lowered)
        self.assertNotIn(".read()", text)
        self.assertIn("csv.reader", text)


if __name__ == "__main__":
    unittest.main()
