from __future__ import annotations

import ast
import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.network_lanl_redteam_matcher as redteam_module
from three_agent.network_corpus_adapter import (
    AdapterInputContract,
    EvidenceRecord,
    NetworkAdapterIntegrityError,
    TruthRecord,
)
from three_agent.network_lanl_adapter import (
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
)
from three_agent.network_lanl_family import LANLSourceFamilySchemaError
from three_agent.network_lanl_redteam_matcher import (
    LANL_REDTEAM_MATCHER_VERSION,
    LANLRedTeamTruthMatcher,
)

SOURCE_SHA = "sha256:" + ("d" * 64)


def _write_rows(path: Path, rows: list[list[str]]) -> bytes:
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, lineterminator="\n").writerows(rows)
    return path.read_bytes()


def _contract(
    payload: bytes,
    *,
    source_object_ref: str = "lanl/redteam/shard-0001.txt",
    adapter_version: str = LANL_REDTEAM_MATCHER_VERSION,
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
            "provenance_ref": "prov://fixture/lanl-redteam-v3-02c",
            "adapter_version": adapter_version,
        }
    )


def _auth_evidence(
    *,
    ordinal: int = 0,
    time: int = 10,
    source_user: str | None = "U1@DOM1",
    destination_user: str | None = "U2@DOM1",
    source_computer: str = "C1",
    destination_computer: str = "C2",
) -> EvidenceRecord:
    return EvidenceRecord.build(
        dataset_id="lanl-comprehensive",
        source_domain="authentication",
        source_object_ref="lanl/auth/shard-0001.txt",
        source_sha256=SOURCE_SHA,
        adapter_version="lanl-comprehensive-auth/0.1",
        record_ordinal=ordinal,
        timestamp=f"lanl:T+{time}s",
        asset_refs=[
            f"lanl:computer:{source_computer}",
            f"lanl:computer:{destination_computer}",
        ],
        account_refs=[
            value
            for value in (
                None if source_user is None else f"lanl:user:{source_user}",
                None if destination_user is None else f"lanl:user:{destination_user}",
            )
            if value is not None
        ],
        network_refs=[],
        event_family="authentication",
        event_type="lanl_authentication",
        observation_fields={
            "time_offset_seconds": time,
            "source_user_domain": source_user,
            "destination_user_domain": destination_user,
            "source_computer": source_computer,
            "destination_computer": destination_computer,
            "authentication_type": "Kerberos",
            "logon_type": "Network",
            "authentication_orientation": "LogOn",
            "success_failure": "Success",
        },
        provenance_ref="prov://fixture/lanl-auth-window",
    )


class LANLRedTeamMatchTests(unittest.TestCase):
    def _inspect(self, root: Path, source: Path, payload: bytes):
        matcher = LANLRedTeamTruthMatcher()
        inspection = matcher.inspect(
            source, authorized_root=root, contract=_contract(payload)
        )
        return matcher, inspection

    def test_exact_single_source_user_match_emits_scorer_only_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U1@DOM1", "C1", "C2"]])
            matcher, inspection = self._inspect(root, source, payload)
            auth = _auth_evidence()
            outputs = list(
                matcher.match(source, inspection=inspection, auth_evidence=[auth])
            )

            self.assertEqual(len(outputs), 1)
            truth = outputs[0]
            self.assertIsInstance(truth, TruthRecord)
            self.assertEqual(truth.evidence_refs, (auth.evidence_id,))
            self.assertEqual(truth.truth_class, "lanl_redteam_auth_compromise")
            self.assertEqual(
                truth.truth_fields,
                {"known_compromise": True, "time_offset_seconds": 10},
            )
            serialized = repr(truth.as_dict())
            self.assertNotIn("U1@DOM1", serialized)
            self.assertNotIn("C1", serialized)
            self.assertNotIn("C2", serialized)
            self.assertEqual(matcher.counters().truth_records_emitted, 1)

    def test_exact_destination_user_match_does_not_assume_user_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U2@DOM1", "C1", "C2"]])
            matcher, inspection = self._inspect(root, source, payload)
            outputs = list(
                matcher.match(
                    source,
                    inspection=inspection,
                    auth_evidence=[_auth_evidence()],
                )
            )
            self.assertEqual(len(outputs), 1)

    def test_zero_match_is_unmatched_and_emits_no_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["11", "U1@DOM1", "C1", "C2"]])
            matcher, inspection = self._inspect(root, source, payload)
            outputs = list(
                matcher.match(
                    source,
                    inspection=inspection,
                    auth_evidence=[_auth_evidence(time=10)],
                )
            )
            self.assertEqual(outputs, [])
            self.assertEqual(matcher.counters().unmatched_truth, 1)
            self.assertEqual(matcher.counters().ambiguous_truth, 0)

    def test_multiple_matches_are_ambiguous_and_never_auto_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U1@DOM1", "C1", "C2"]])
            matcher, inspection = self._inspect(root, source, payload)
            outputs = list(
                matcher.match(
                    source,
                    inspection=inspection,
                    auth_evidence=[
                        _auth_evidence(ordinal=0),
                        _auth_evidence(ordinal=1),
                    ],
                )
            )
            self.assertEqual(outputs, [])
            self.assertEqual(matcher.counters().ambiguous_truth, 1)
            self.assertEqual(matcher.counters().truth_records_emitted, 0)

    def test_replay_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U1@DOM1", "C1", "C2"]])
            auth = [_auth_evidence()]

            first_matcher, first_inspection = self._inspect(root, source, payload)
            first = list(
                first_matcher.match(
                    source,
                    inspection=first_inspection,
                    auth_evidence=auth,
                )
            )
            second_matcher, second_inspection = self._inspect(root, source, payload)
            second = list(
                second_matcher.match(
                    source,
                    inspection=second_inspection,
                    auth_evidence=auth,
                )
            )
            self.assertEqual(
                [item.as_dict() for item in first],
                [item.as_dict() for item in second],
            )


class LANLRedTeamBoundaryTests(unittest.TestCase):
    def test_wrong_manifest_namespace_fails_before_truth_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U1@DOM1", "C1", "C2"]])
            with self.assertRaises(LANLSourceFamilySchemaError):
                LANLRedTeamTruthMatcher().inspect(
                    source,
                    authorized_root=root,
                    contract=_contract(
                        payload,
                        source_object_ref="lanl/auth/shard-0001.txt",
                    ),
                )

    def test_matcher_rejects_non_authentication_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U1@DOM1", "C1", "C2"]])
            matcher = LANLRedTeamTruthMatcher()
            inspection = matcher.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            dns_evidence = EvidenceRecord.build(
                dataset_id="lanl-comprehensive",
                source_domain="dns",
                source_object_ref="lanl/dns/shard-0001.txt",
                source_sha256=SOURCE_SHA,
                adapter_version="lanl-comprehensive-dns/0.1",
                record_ordinal=0,
                timestamp="lanl:T+10s",
                asset_refs=["lanl:computer:C1"],
                account_refs=[],
                network_refs=[],
                event_family="dns",
                event_type="lanl_dns_lookup",
                observation_fields={
                    "time_offset_seconds": 10,
                    "source_computer": "C1",
                    "computer_resolved": "C2",
                },
                provenance_ref="prov://fixture/dns",
            )
            with self.assertRaises(LANLAdapterSchemaError):
                list(
                    matcher.match(
                        source,
                        inspection=inspection,
                        auth_evidence=[dns_evidence],
                    )
                )

    def test_auth_window_resource_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U1@DOM1", "C1", "C2"]])
            matcher = LANLRedTeamTruthMatcher(max_auth_evidence=1)
            inspection = matcher.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            with self.assertRaises(LANLAdapterResourceError):
                list(
                    matcher.match(
                        source,
                        inspection=inspection,
                        auth_evidence=[
                            _auth_evidence(ordinal=0),
                            _auth_evidence(ordinal=1),
                        ],
                    )
                )

    def test_same_size_redteam_tamper_after_inspection_fails_digest_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redteam.txt"
            payload = _write_rows(source, [["10", "U1@DOM1", "C1", "C2"]])
            matcher = LANLRedTeamTruthMatcher()
            inspection = matcher.inspect(
                source, authorized_root=root, contract=_contract(payload)
            )
            tampered = payload.replace(b"U1@DOM1", b"U3@DOM1")
            self.assertEqual(len(tampered), len(payload))
            source.write_bytes(tampered)
            with self.assertRaises(NetworkAdapterIntegrityError):
                list(
                    matcher.match(
                        source,
                        inspection=inspection,
                        auth_evidence=[_auth_evidence()],
                    )
                )

    def test_invalid_or_unknown_required_redteam_fields_emit_no_truth(self):
        bad_rows = (
            ["0", "U1@DOM1", "C1", "C2"],
            ["10", "?", "C1", "C2"],
            ["10", "U1@DOM1", "?", "C2"],
            ["10", "U1@DOM1", "C1", "?"],
        )
        for row in bad_rows:
            with self.subTest(row=row):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    source = root / "redteam.txt"
                    payload = _write_rows(source, [row])
                    matcher = LANLRedTeamTruthMatcher()
                    inspection = matcher.inspect(
                        source, authorized_root=root, contract=_contract(payload)
                    )
                    outputs = list(
                        matcher.match(
                            source,
                            inspection=inspection,
                            auth_evidence=[_auth_evidence()],
                        )
                    )
                    self.assertEqual(outputs, [])
                    self.assertEqual(matcher.counters().records_rejected, 1)


class LANLRedTeamAuthorityTests(unittest.TestCase):
    def test_matcher_ast_has_no_network_model_subprocess_or_whole_file_read_authority(self):
        text = inspect.getsource(redteam_module)
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
        self.assertNotIn("EvidenceRecord.build", text)


if __name__ == "__main__":
    unittest.main()
