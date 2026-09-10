from __future__ import annotations

import ast
import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.network_lanl_adapter as lanl_module
from three_agent.network_corpus_adapter import (
    AdapterInputContract,
    NetworkAdapterIntegrityError,
)
from three_agent.network_lanl_adapter import (
    LANL_AUTH_ADAPTER_VERSION,
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
    LANLAuthAdapter,
    lanl_entity_ref,
    lanl_logical_timestamp,
    lanl_time_offset,
)


def _row(
    *,
    time: str = "1",
    source_user: str = "C625$@DOM1",
    destination_user: str = "U147@DOM1",
    source_computer: str = "C625",
    destination_computer: str = "C625",
    authentication_type: str = "Negotiate",
    logon_type: str = "Batch",
    orientation: str = "LogOn",
    outcome: str = "Success",
) -> list[str]:
    return [
        time,
        source_user,
        destination_user,
        source_computer,
        destination_computer,
        authentication_type,
        logon_type,
        orientation,
        outcome,
    ]


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
    adapter_version: str = LANL_AUTH_ADAPTER_VERSION,
) -> AdapterInputContract:
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return AdapterInputContract.from_dict(
        {
            "dataset_id": dataset_id,
            "variant": variant,
            "source_object_ref": "lanl/auth/shard-0001.txt",
            "source_sha256": digest,
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": max(1, len(payload) + 1024),
            "acquisition_plan_fingerprint": "sha256:" + ("a" * 64),
            "registry_fingerprint": "sha256:" + ("b" * 64),
            "policy_fingerprint": "sha256:" + ("c" * 64),
            "provenance_ref": "prov://fixture/lanl-auth-v3-02c",
            "adapter_version": adapter_version,
        }
    )


class LANLSharedContractTests(unittest.TestCase):
    def test_logical_time_preserves_internal_offset_without_inventing_utc(self):
        self.assertEqual(lanl_time_offset("151648"), 151648)
        self.assertEqual(lanl_logical_timestamp(151648), "lanl:T+151648s")
        self.assertNotIn("Z", lanl_logical_timestamp(151648))
        self.assertNotIn("201", lanl_logical_timestamp(151648))

    def test_invalid_logical_time_fails_closed(self):
        for raw in ("", "?", "0", "-1", "1.5", "not-time"):
            with self.subTest(raw=raw):
                with self.assertRaises(LANLAdapterSchemaError):
                    lanl_time_offset(raw)

    def test_entity_reference_is_stable_and_unknown_is_not_fabricated(self):
        self.assertEqual(
            lanl_entity_ref("computer", "C17693"),
            "lanl:computer:C17693",
        )
        self.assertEqual(
            lanl_entity_ref("user", "U748@DOM1"),
            "lanl:user:U748@DOM1",
        )
        self.assertIsNone(lanl_entity_ref("user", None))
        self.assertIsNone(lanl_entity_ref("computer", "?"))


class LANLAuthSchemaTests(unittest.TestCase):
    def test_valid_auth_row_emits_observation_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(source, [_row()])
            adapter = LANLAuthAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]

            self.assertEqual(evidence.timestamp, "lanl:T+1s")
            self.assertEqual(evidence.source_domain, "authentication")
            self.assertEqual(evidence.event_type, "lanl_authentication")
            self.assertEqual(
                evidence.observation_fields["success_failure"], "Success"
            )
            self.assertEqual(
                evidence.asset_refs,
                ("lanl:computer:C625",),
            )
            self.assertEqual(
                evidence.account_refs,
                ("lanl:user:C625$@DOM1", "lanl:user:U147@DOM1"),
            )
            visible = repr(evidence.as_dict()).casefold()
            self.assertNotIn("redteam", visible)
            self.assertNotIn("known_compromise", visible)
            self.assertNotIn("attack_label", visible)

    def test_question_mark_optional_fields_remain_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(
                source,
                [
                    _row(
                        source_user="?",
                        destination_user="U147@DOM1",
                        authentication_type="?",
                        logon_type="?",
                        orientation="?",
                        outcome="?",
                    )
                ],
            )
            adapter = LANLAuthAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            evidence = list(adapter.iterate(source, inspection=inspection))[0]
            fields = evidence.observation_fields
            self.assertIsNone(fields["source_user_domain"])
            self.assertIsNone(fields["authentication_type"])
            self.assertIsNone(fields["logon_type"])
            self.assertIsNone(fields["authentication_orientation"])
            self.assertIsNone(fields["success_failure"])
            self.assertEqual(evidence.account_refs, ("lanl:user:U147@DOM1",))

    def test_wrong_field_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(source, [_row()[:-1]])
            adapter = LANLAuthAdapter()
            with self.assertRaises(LANLAdapterSchemaError):
                adapter.inspect(
                    source, authorized_root=root, contract=_contract(payload)
                )

    def test_wrong_dataset_variant_or_adapter_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(source, [_row()])
            for kwargs in (
                {"dataset_id": "cse-cic-ids2018"},
                {"variant": "auth"},
                {"adapter_version": "lanl-comprehensive-auth/9.9"},
            ):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(LANLAdapterSchemaError):
                        LANLAuthAdapter().inspect(
                            source,
                            authorized_root=root,
                            contract=_contract(payload, **kwargs),
                        )


class LANLAuthParsingTests(unittest.TestCase):
    def _run_once(self, source: Path, root: Path, payload: bytes):
        adapter = LANLAuthAdapter()
        inspection = adapter.inspect(
            source, authorized_root=root, contract=_contract(payload)
        )
        return list(adapter.iterate(source, inspection=inspection)), adapter.counters()

    def test_replay_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(
                source,
                [_row(), _row(time="2", source_computer="C653", destination_computer="C653")],
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
            source = root / "auth.txt"
            payload = _write_rows(source, [_row(time="0")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)
            self.assertEqual(counts.first_error_code, "AUTH_REQUIRED_FIELD_INVALID")

    def test_unknown_required_computer_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(source, [_row(source_computer="?")])
            outputs, counts = self._run_once(source, root, payload)
            self.assertEqual(outputs, [])
            self.assertEqual(counts.records_rejected, 1)

    def test_visible_record_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(source, [_row(), _row(time="2")])
            adapter = LANLAuthAdapter(max_visible_records=1)
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterResourceError):
                list(adapter.iterate(source, inspection=inspection))


class LANLAuthIntegrityTests(unittest.TestCase):
    def test_same_size_tamper_after_inspection_fails_digest_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(source, [_row(destination_user="U147@DOM1")])
            adapter = LANLAuthAdapter()
            inspection = adapter.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            tampered = payload.replace(b"U147@DOM1", b"U148@DOM1")
            self.assertEqual(len(tampered), len(payload))
            source.write_bytes(tampered)
            with self.assertRaises(NetworkAdapterIntegrityError):
                list(adapter.iterate(source, inspection=inspection))

    def test_iterate_requires_successful_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "auth.txt"
            payload = _write_rows(source, [_row()])
            inspection = LANLAuthAdapter().inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterSchemaError):
                list(LANLAuthAdapter().iterate(source, inspection=inspection))


class LANLAuthAuthorityTests(unittest.TestCase):
    def test_adapter_ast_has_no_network_model_subprocess_or_whole_file_read_authority(self):
        text = inspect.getsource(lanl_module)
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
