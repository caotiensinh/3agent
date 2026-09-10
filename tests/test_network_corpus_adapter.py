from __future__ import annotations

import hashlib
import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path

import three_agent.network_corpus_adapter as adapter_module
from three_agent.network_corpus_adapter import (
    AdapterInputContract,
    AdapterReceipt,
    EvidenceRecord,
    NetworkAdapterError,
    NetworkAdapterIntegrityError,
    NetworkAdapterSecurityError,
    TruthRecord,
    canonical_sha256,
    inspect_staged_source,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "evaluation/fixtures/network_adapter_v1/canonical_records.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def evidence_from_fixture() -> EvidenceRecord:
    data = load_fixture()
    row = data["evidence"]
    return EvidenceRecord.build(
        dataset_id=row["dataset_id"],
        source_domain=row["source_domain"],
        source_object_ref=data["source_object_ref"],
        source_sha256=data["source_sha256"],
        adapter_version=data["adapter_version"],
        record_ordinal=row["record_ordinal"],
        timestamp=row["timestamp"],
        asset_refs=row["asset_refs"],
        account_refs=row["account_refs"],
        network_refs=row["network_refs"],
        event_family=row["event_family"],
        event_type=row["event_type"],
        observation_fields=row["observation_fields"],
        provenance_ref=data["provenance_ref"],
    )


class CanonicalRecordTests(unittest.TestCase):
    def test_fixture_builds_separate_visible_evidence_and_scorer_truth(self):
        data = load_fixture()
        evidence = evidence_from_fixture()
        truth = TruthRecord.build(
            evidence_refs=[evidence.evidence_id],
            truth_class=data["truth"]["truth_class"],
            truth_fields=data["truth"]["truth_fields"],
            source_object_ref=data["source_object_ref"],
            source_sha256=data["source_sha256"],
            adapter_version=data["adapter_version"],
            provenance_ref=data["provenance_ref"],
        )
        visible = evidence.as_dict()
        self.assertNotIn("truth_class", visible)
        self.assertNotIn("label", visible["observation_fields"])
        self.assertEqual(truth.truth_fields["label"], "BENIGN")
        self.assertEqual(truth.evidence_refs, (evidence.evidence_id,))

    def test_evidence_id_is_deterministic_and_adapter_version_bound(self):
        first = evidence_from_fixture()
        second = evidence_from_fixture()
        self.assertEqual(first.as_dict(), second.as_dict())

        data = load_fixture()
        row = data["evidence"]
        changed = EvidenceRecord.build(
            dataset_id=row["dataset_id"],
            source_domain=row["source_domain"],
            source_object_ref=data["source_object_ref"],
            source_sha256=data["source_sha256"],
            adapter_version="network-adapter-base/0.2",
            record_ordinal=row["record_ordinal"],
            timestamp=row["timestamp"],
            asset_refs=row["asset_refs"],
            account_refs=row["account_refs"],
            network_refs=row["network_refs"],
            event_family=row["event_family"],
            event_type=row["event_type"],
            observation_fields=row["observation_fields"],
            provenance_ref=data["provenance_ref"],
        )
        self.assertNotEqual(first.evidence_id, changed.evidence_id)

    def test_visible_truth_fields_fail_closed_recursively(self):
        data = load_fixture()
        row = data["evidence"]
        with self.assertRaises(NetworkAdapterSecurityError):
            EvidenceRecord.build(
                dataset_id=row["dataset_id"],
                source_domain=row["source_domain"],
                source_object_ref=data["source_object_ref"],
                source_sha256=data["source_sha256"],
                adapter_version=data["adapter_version"],
                record_ordinal=0,
                timestamp=row["timestamp"],
                event_family="flow",
                event_type="connection",
                observation_fields={
                    "protocol": "TCP",
                    "nested": {"attack_label": "Bot"},
                },
                provenance_ref=data["provenance_ref"],
            )

    def test_timestamp_and_interval_are_mutually_exclusive(self):
        data = load_fixture()
        with self.assertRaises(NetworkAdapterError):
            EvidenceRecord.build(
                dataset_id="cse-cic-ids2018",
                source_domain="network_flow",
                source_object_ref=data["source_object_ref"],
                source_sha256=data["source_sha256"],
                adapter_version=data["adapter_version"],
                record_ordinal=0,
                timestamp="2018-02-14T10:00:00Z",
                interval_start="2018-02-14T09:59:59Z",
                interval_end="2018-02-14T10:00:01Z",
                event_family="flow",
                event_type="connection",
                observation_fields={"protocol": "TCP"},
                provenance_ref=data["provenance_ref"],
            )

    def test_logical_source_reference_is_host_independent(self):
        data = load_fixture()
        base = evidence_from_fixture()
        for unsafe in (
            "/var/cache/workspace/cic.csv",
            r"C:\workspace\cic.csv",
            "../cic.csv",
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(NetworkAdapterError):
                    EvidenceRecord.build(
                        dataset_id=base.dataset_id,
                        source_domain=base.source_domain,
                        source_object_ref=unsafe,
                        source_sha256=data["source_sha256"],
                        adapter_version=data["adapter_version"],
                        record_ordinal=0,
                        timestamp=base.timestamp,
                        event_family=base.event_family,
                        event_type=base.event_type,
                        observation_fields={"protocol": "TCP"},
                        provenance_ref=data["provenance_ref"],
                    )

    def test_record_rejects_noncanonical_or_oversized_values(self):
        data = load_fixture()
        row = data["evidence"]
        with self.assertRaises(NetworkAdapterError):
            EvidenceRecord.build(
                dataset_id=row["dataset_id"],
                source_domain=row["source_domain"],
                source_object_ref=data["source_object_ref"],
                source_sha256=data["source_sha256"],
                adapter_version=data["adapter_version"],
                record_ordinal=0,
                timestamp=row["timestamp"],
                event_family="flow",
                event_type="connection",
                observation_fields={"ratio": float("nan")},
                provenance_ref=data["provenance_ref"],
            )
        with self.assertRaises(NetworkAdapterError):
            EvidenceRecord.build(
                dataset_id=row["dataset_id"],
                source_domain=row["source_domain"],
                source_object_ref=data["source_object_ref"],
                source_sha256=data["source_sha256"],
                adapter_version=data["adapter_version"],
                record_ordinal=0,
                timestamp=row["timestamp"],
                event_family="flow",
                event_type="connection",
                observation_fields={"bulk": "x" * (1024 * 1024)},
                provenance_ref=data["provenance_ref"],
            )


class AdapterInspectionTests(unittest.TestCase):
    def _contract(self, payload: bytes, *, source_ref: str = "cic/shard.csv"):
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        return AdapterInputContract.from_dict(
            {
                "dataset_id": "cse-cic-ids2018",
                "variant": "processed-ml",
                "source_object_ref": source_ref,
                "source_sha256": digest,
                "actual_source_size_bytes": len(payload),
                "max_plan_bytes": max(1, len(payload) + 1),
                "acquisition_plan_fingerprint": "sha256:" + ("b" * 64),
                "registry_fingerprint": "sha256:" + ("c" * 64),
                "policy_fingerprint": "sha256:" + ("d" * 64),
                "provenance_ref": "prov://fixture/cic-source",
                "adapter_version": "network-adapter-base/0.1",
            }
        )

    def test_inspection_streams_digest_and_is_physical_path_independent(self):
        payload = (b"header\n" + b"record\n" * 10)
        contract = self._contract(payload)
        fingerprints = []
        for suffix in ("one", "two"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                nested = root / suffix
                nested.mkdir()
                source = nested / "shard.csv"
                source.write_bytes(payload)
                inspection = inspect_staged_source(
                    source,
                    authorized_root=root,
                    contract=contract,
                )
                fingerprints.append(inspection.inspection_fingerprint)
        self.assertEqual(fingerprints[0], fingerprints[1])

    def test_digest_mismatch_fails_integrity(self):
        payload = b"trusted bytes"
        contract = self._contract(payload)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "shard.csv"
            source.write_bytes(b"tampered")
            with self.assertRaises(NetworkAdapterIntegrityError):
                inspect_staged_source(
                    source,
                    authorized_root=root,
                    contract=contract,
                )

    @unittest.skipIf(
        os.name == "nt",
        "symlink creation is not reliably permitted on hosted Windows runners",
    )
    def test_symlink_source_fails_security(self):
        payload = b"data"
        contract = self._contract(payload)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.csv"
            real.write_bytes(payload)
            link = root / "link.csv"
            link.symlink_to(real)
            with self.assertRaises(NetworkAdapterSecurityError):
                inspect_staged_source(
                    link,
                    authorized_root=root,
                    contract=contract,
                )

    def test_source_outside_authorized_root_fails_security(self):
        payload = b"data"
        contract = self._contract(payload)
        with tempfile.TemporaryDirectory() as tmp_root:
            with tempfile.TemporaryDirectory() as tmp_outside:
                root = Path(tmp_root)
                source = Path(tmp_outside) / "outside.csv"
                source.write_bytes(payload)
                with self.assertRaises(NetworkAdapterSecurityError):
                    inspect_staged_source(
                        source,
                        authorized_root=root,
                        contract=contract,
                    )

    def test_input_contract_rejects_plan_oversize(self):
        with self.assertRaises(NetworkAdapterIntegrityError):
            AdapterInputContract.from_dict(
                {
                    "dataset_id": "cse-cic-ids2018",
                    "variant": "processed-ml",
                    "source_object_ref": "cic/shard.csv",
                    "source_sha256": "sha256:" + ("a" * 64),
                    "actual_source_size_bytes": 11,
                    "max_plan_bytes": 10,
                    "acquisition_plan_fingerprint": "sha256:" + ("b" * 64),
                    "registry_fingerprint": "sha256:" + ("c" * 64),
                    "policy_fingerprint": "sha256:" + ("d" * 64),
                    "provenance_ref": "prov://fixture/cic-source",
                    "adapter_version": "network-adapter-base/0.1",
                }
            )


class AdapterReceiptTests(unittest.TestCase):
    def test_pass_receipt_requires_all_zero_tolerance_gates(self):
        common = dict(
            exact_head_sha="1" * 40,
            adapter_id="base-fixture",
            adapter_version="network-adapter-base/0.1",
            adapter_spec_sha256="sha256:" + ("a" * 64),
            fixture_or_source_manifest_sha256="sha256:" + ("b" * 64),
            source_sha256="sha256:" + ("c" * 64),
            registry_fingerprint="sha256:" + ("d" * 64),
            policy_fingerprint="sha256:" + ("e" * 64),
            records_seen=2,
            records_emitted=2,
            records_rejected=0,
            truth_records_emitted=1,
            resource_measurements={"model_calls": 0, "internet_calls": 0},
        )
        receipt = AdapterReceipt.build(
            **common,
            determinism_identical=True,
            zero_tolerance_gates={
                "hidden_label_leakage": True,
                "source_digest_match": True,
            },
            verdict="PASS",
            failed_gate_ids=[],
        )
        self.assertEqual(receipt.verdict, "PASS")
        with self.assertRaises(NetworkAdapterError):
            AdapterReceipt.build(
                **common,
                determinism_identical=True,
                zero_tolerance_gates={
                    "hidden_label_leakage": False,
                    "source_digest_match": True,
                },
                verdict="PASS",
                failed_gate_ids=["hidden_label_leakage"],
            )

    def test_failed_gate_ids_must_exactly_match_gate_map(self):
        with self.assertRaises(NetworkAdapterError):
            AdapterReceipt.build(
                exact_head_sha="1" * 40,
                adapter_id="base-fixture",
                adapter_version="network-adapter-base/0.1",
                adapter_spec_sha256="sha256:" + ("a" * 64),
                fixture_or_source_manifest_sha256="sha256:" + ("b" * 64),
                source_sha256="sha256:" + ("c" * 64),
                registry_fingerprint="sha256:" + ("d" * 64),
                policy_fingerprint="sha256:" + ("e" * 64),
                records_seen=1,
                records_emitted=0,
                records_rejected=1,
                truth_records_emitted=0,
                determinism_identical=True,
                zero_tolerance_gates={"schema_valid": False},
                resource_measurements={},
                verdict="FAIL_SCHEMA",
                failed_gate_ids=[],
            )

    def test_canonical_hash_is_order_independent(self):
        self.assertEqual(
            canonical_sha256({"a": 1, "b": 2}),
            canonical_sha256({"b": 2, "a": 1}),
        )


class StreamingContractTests(unittest.TestCase):
    def test_adapter_base_contains_no_network_model_or_whole_file_read_authority(self):
        text = inspect.getsource(adapter_module)
        self.assertNotIn("import requests", text)
        self.assertNotIn("import urllib", text)
        self.assertNotIn("import socket", text)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("ollama", text.casefold())
        self.assertNotIn("handle.read()", text)
        self.assertIn("handle.read(HASH_CHUNK_BYTES)", text)


if __name__ == "__main__":
    unittest.main()
