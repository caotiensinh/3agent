from __future__ import annotations

import csv
import hashlib
import tempfile
import unittest
from pathlib import Path

from three_agent.network_corpus_adapter import AdapterInputContract
from three_agent.network_lanl_adapter import (
    LANL_AUTH_ADAPTER_VERSION,
    LANLAuthAdapter,
)
from three_agent.network_lanl_dns_adapter import (
    LANL_DNS_ADAPTER_VERSION,
    LANLDNSAdapter,
)
from three_agent.network_lanl_family import LANLSourceFamilySchemaError
from three_agent.network_lanl_process_adapter import (
    LANL_PROCESS_ADAPTER_VERSION,
    LANLProcessAdapter,
)


def _write_row(path: Path, row: list[str]) -> bytes:
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, lineterminator="\n").writerow(row)
    return path.read_bytes()


def _contract(
    payload: bytes,
    *,
    source_object_ref: str,
    adapter_version: str,
) -> AdapterInputContract:
    return AdapterInputContract.from_dict(
        {
            "dataset_id": "lanl-comprehensive",
            "variant": "events",
            "source_object_ref": source_object_ref,
            "source_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": len(payload) + 1024,
            "acquisition_plan_fingerprint": "sha256:" + ("a" * 64),
            "registry_fingerprint": "sha256:" + ("b" * 64),
            "policy_fingerprint": "sha256:" + ("c" * 64),
            "provenance_ref": "prov://fixture/lanl-family-binding-v1",
            "adapter_version": adapter_version,
        }
    )


class LANLSourceFamilyBindingTests(unittest.TestCase):
    def test_correct_manifest_namespaces_are_accepted(self):
        cases = (
            (
                LANLAuthAdapter(),
                LANL_AUTH_ADAPTER_VERSION,
                "lanl/auth/shard-0001.txt",
                [
                    "1",
                    "U1@DOM1",
                    "U2@DOM1",
                    "C1",
                    "C2",
                    "Kerberos",
                    "Network",
                    "LogOn",
                    "Success",
                ],
            ),
            (
                LANLProcessAdapter(),
                LANL_PROCESS_ADAPTER_VERSION,
                "lanl/process/shard-0001.txt",
                ["1", "U1@DOM1", "C1", "P1", "Start"],
            ),
            (
                LANLDNSAdapter(),
                LANL_DNS_ADAPTER_VERSION,
                "lanl/dns/shard-0001.txt",
                ["1", "C1", "C2"],
            ),
        )

        for adapter, version, logical_ref, row in cases:
            with self.subTest(logical_ref=logical_ref):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    source = root / "source.txt"
                    payload = _write_row(source, row)
                    inspection = adapter.inspect(
                        source,
                        authorized_root=root,
                        contract=_contract(
                            payload,
                            source_object_ref=logical_ref,
                            adapter_version=version,
                        ),
                    )
                    self.assertEqual(inspection.source_object_ref, logical_ref)

    def test_cross_family_manifest_namespaces_fail_before_parsing(self):
        cases = (
            (
                LANLAuthAdapter(),
                LANL_AUTH_ADAPTER_VERSION,
                "lanl/flow/shard-0001.txt",
            ),
            (
                LANLProcessAdapter(),
                LANL_PROCESS_ADAPTER_VERSION,
                "lanl/dns/shard-0001.txt",
            ),
            (
                LANLDNSAdapter(),
                LANL_DNS_ADAPTER_VERSION,
                "lanl/process/shard-0001.txt",
            ),
        )
        valid_nine_field_payload = [
            "1",
            "U1@DOM1",
            "U2@DOM1",
            "C1",
            "C2",
            "Kerberos",
            "Network",
            "LogOn",
            "Success",
        ]

        for adapter, version, wrong_ref in cases:
            with self.subTest(wrong_ref=wrong_ref):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    source = root / "source.txt"
                    payload = _write_row(source, valid_nine_field_payload)
                    with self.assertRaises(LANLSourceFamilySchemaError):
                        adapter.inspect(
                            source,
                            authorized_root=root,
                            contract=_contract(
                                payload,
                                source_object_ref=wrong_ref,
                                adapter_version=version,
                            ),
                        )

    def test_auth_adapter_rejects_flow_namespace_even_when_both_have_nine_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.txt"
            payload = _write_row(
                source,
                ["1", "0", "C1", "N123", "C2", "443", "6", "10", "2048"],
            )
            with self.assertRaises(LANLSourceFamilySchemaError):
                LANLAuthAdapter().inspect(
                    source,
                    authorized_root=root,
                    contract=_contract(
                        payload,
                        source_object_ref="lanl/flow/shard-0001.txt",
                        adapter_version=LANL_AUTH_ADAPTER_VERSION,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
