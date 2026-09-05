from __future__ import annotations

import ast
import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.network_lanl_dns_adapter as dns_module
from three_agent.network_corpus_adapter import (
    AdapterInputContract,
    NetworkAdapterIntegrityError,
)
from three_agent.network_lanl_adapter import (
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
)
from three_agent.network_lanl_dns_adapter import (
    LANL_DNS_ADAPTER_VERSION,
    LANLDNSAdapter,
)


def _row(
    *,
    time: str = "1",
    source_computer: str = "C17693",
    computer_resolved: str = "C200",
) -> list[str]:
    return [time, source_computer, computer_resolved]


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
    adapter_version: str = LANL_DNS_ADAPTER_VERSION,
) -> AdapterInputContract:
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return AdapterInputContract.from_dict(
        {
            "dataset_id": dataset_id,
            "variant": variant,
            "source_object_ref": "lanl/dns/shard-0001.txt",
            "source_sha256": digest,
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": max(1, len(payload) + 1024),
            "acquisition_plan_fingerprint": "sha256:" + ("a" * 64),
            "registry_fingerprint": "sha256:" + ("b" * 64),
            "policy_fingerprint": "sha256:" + ("c" * 64),
            "provenance_ref": "prov://fixture/lanl-dns-v3-02c",
            "adapter_version": adapter_version,
        }
    )


class LANLDNSSchemaTests(unittest.TestCase):
    def test_valid_dns_row_emits_deidentified_observation_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row()])
            adapter = LANLDNSAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]

            self.assertEqual(evidence.timestamp, "lanl:T+1s")
            self.assertEqual(evidence.source_domain, "dns")
            self.assertEqual(evidence.event_family, "dns")
            self.assertEqual(evidence.event_type, "lanl_dns_lookup")
            self.assertEqual(
                evidence.asset_refs,
                ("lanl:computer:C17693", "lanl:computer:C200"),
            )
            self.assertEqual(evidence.account_refs, ())
            self.assertEqual(evidence.network_refs, ())
            self.assertEqual(
                evidence.observation_fields["computer_resolved"], "C200"
            )
            visible = repr(evidence.as_dict()).casefold()
            self.assertNotIn("redteam", visible)
            self.assertNotIn("attack_label", visible)
            self.assertNotIn("ground_truth", visible)

    def test_unknown_resolved_computer_remains_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row(computer_resolved="?")])
            adapter = LANLDNSAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]
            self.assertIsNone(evidence.observation_fields["computer_resolved"])
            self.assertEqual(evidence.asset_refs, ("lanl:computer:C17693",))

    def test_wrong_field_count_fails_closed_during_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row()[:-1]])
            with self.assertRaises(LANLAdapterSchemaError):
                LANLDNSAdapter().inspect(
                    source, authorized_root=root, contract=_contract(payload)
                )

    def test_wrong_dataset_variant_or_adapter_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row()])
            for kwargs in (
                {"dataset_id": "cse-cic-ids2018"},
                {"variant": "dns"},
                {"adapter_version": "lanl-comprehensive-dns/9.9"},
            ):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(LANLAdapterSchemaError):
                        LANLDNSAdapter().inspect(
                            source,
                            authorized_root=root,
                            contract=_contract(payload, **kwargs),
                        )


class LANLDNSParsingTests(unittest.TestCase):
    def _run_once(self, source: Path, root: Path, payload: bytes):
        adapter = LANLDNSAdapter()
        inspection = adapter.inspect(
            source, authorized_root=root, contract=_contract(payload)
        )
        return list(adapter.iterate(source, inspection=inspection)), adapter.counters()

    def test_replay_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(
                source,
                [
                    _row(),
                    _row(time="2", source_computer="C300", computer_resolved="C400"),
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
            source = root / "dns.txt"
            payload = _write_rows(source, [_row(time="0")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)
            self.assertEqual(counts.first_error_code, "DNS_REQUIRED_FIELD_INVALID")

    def test_unknown_required_source_computer_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row(source_computer="?")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)

    def test_visible_record_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row(), _row(time="2")])
            adapter = LANLDNSAdapter(max_visible_records=1)
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterResourceError):
                list(adapter.iterate(source, inspection=inspection))


class LANLDNSIntegrityTests(unittest.TestCase):
    def test_same_size_tamper_after_inspection_fails_digest_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row(computer_resolved="C200")])
            adapter = LANLDNSAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            tampered = payload.replace(b"C200", b"C201")
            self.assertEqual(len(tampered), len(payload))
            source.write_bytes(tampered)
            with self.assertRaises(NetworkAdapterIntegrityError):
                list(adapter.iterate(source, inspection=inspection))

    def test_iterate_requires_successful_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dns.txt"
            payload = _write_rows(source, [_row()])
            inspection = LANLDNSAdapter().inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterSchemaError):
                list(LANLDNSAdapter().iterate(source, inspection=inspection))


class LANLDNSAuthorityTests(unittest.TestCase):
    def test_adapter_ast_has_no_network_model_subprocess_or_whole_file_read_authority(self):
        text = inspect.getsource(dns_module)
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
