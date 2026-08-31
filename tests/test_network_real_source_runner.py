from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from three_agent.network_cic_adapter import (
    CIC_ADAPTER_ID,
    CIC_ADAPTER_VERSION,
    CIC_COLUMNS,
)
from three_agent.network_lanl_adapter import (
    LANL_AUTH_ADAPTER_ID,
    LANL_AUTH_ADAPTER_VERSION,
)
from three_agent.network_lanl_dns_adapter import (
    LANL_DNS_ADAPTER_ID,
    LANL_DNS_ADAPTER_VERSION,
)
from three_agent.network_lanl_flow_adapter import (
    LANL_FLOW_ADAPTER_ID,
    LANL_FLOW_ADAPTER_VERSION,
)
from three_agent.network_lanl_process_adapter import (
    LANL_PROCESS_ADAPTER_ID,
    LANL_PROCESS_ADAPTER_VERSION,
)
from three_agent.network_lanl_redteam_matcher import (
    LANL_REDTEAM_MATCHER_ID,
    LANL_REDTEAM_MATCHER_VERSION,
)
from three_agent.network_real_source_acceptance_contract import (
    FAIL_INTEGRITY,
    FAIL_SCHEMA,
    FAIL_SECURITY,
    MANIFEST_SCHEMA,
    NOT_ENOUGH_REAL_SOURCE_EVIDENCE,
    PASS,
    canonical_sha256,
)
from three_agent.network_real_source_runner import (
    OfflineRealSourceRunner,
    RealSourceRunnerError,
)

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_PROFILE_PATH = ROOT / "evaluation" / "network_real_source_acceptance_v1.json"
RUNNER_PROFILE_PATH = ROOT / "evaluation" / "network_real_source_runner_v1.json"
RUNNER_BINDING_PATH = ROOT / "evaluation" / "network_real_source_runner_binding_v1.json"
POLICY_FINGERPRINT = "sha256:" + "a" * 64
ACQUISITION_RECEIPT = "sha256:" + "d" * 64
SPEC_FINGERPRINT = "sha256:" + "e" * 64
EXACT_HEAD = "1" * 40


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def registry() -> dict:
    return {
        "schema_version": "workspace-network-dataset-registry/v1",
        "datasets": [
            {
                "id": "cse-cic-ids2018",
                "status": "enterprise_approved",
                "license": {
                    "commercial_use": True,
                    "source": "https://www.unb.ca/cic/datasets/ids-2018.html",
                },
                "acquisition": {
                    "mode": "bounded-manual-fixture",
                    "allowlisted_hosts": ["www.unb.ca"],
                },
                "variants": {"processed-ml": {}},
            },
            {
                "id": "lanl-comprehensive",
                "status": "enterprise_approved",
                "license": {
                    "commercial_use": True,
                    "source": "https://csr.lanl.gov/data/cyber1/",
                },
                "acquisition": {
                    "mode": "bounded-manual-fixture",
                    "allowlisted_hosts": ["csr.lanl.gov"],
                },
                "variants": {"events": {}},
            },
        ],
    }


def source_manifest(
    *,
    source_id: str,
    dataset_id: str,
    variant: str,
    source_family: str | None,
    publisher_reference: str,
    logical_ref: str,
    path: Path,
    adapter_id: str,
    adapter_version: str,
) -> dict:
    digest = sha256_file(path)
    size = path.stat().st_size
    return {
        "source_id": source_id,
        "dataset_id": dataset_id,
        "variant": variant,
        "source_family": source_family,
        "real_source": True,
        "publisher_reference": publisher_reference,
        "acquisition_mode": "bounded-manual-fixture",
        "acquisition_receipt_fingerprint": ACQUISITION_RECEIPT,
        "parent_source_object_ref": logical_ref,
        "parent_source_sha256": digest,
        "parent_source_size_bytes": size,
        "bounded_source_object_ref": logical_ref,
        "bounded_source_sha256": digest,
        "bounded_source_size_bytes": size,
        "derivation": None,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "provenance_ref": f"provenance/{source_id}.json",
    }


def manifest_for(sources: list[dict], lanes: list[str], reg: dict) -> dict:
    return {
        "schema_version": MANIFEST_SCHEMA,
        "acceptance_id": "v3-02e-runner-fixture",
        "spec_version": "WORKSPACE_NETWORK_V3_02E_RUNNER_SPEC_V1",
        "created_by_role": "RUNNER_HARNESS",
        "registry_fingerprint": canonical_sha256(reg),
        "policy_fingerprint": POLICY_FINGERPRINT,
        "sources": sources,
        "expected_lanes": lanes,
        "bots_direct_adapter_authorized": False,
    }


def write_cic(path: Path, *, records: int = 1000, include_attack: bool = True) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CIC_COLUMNS)
        for index in range(records):
            values = {column: "1" for column in CIC_COLUMNS}
            values["Timestamp"] = "01/03/2018 12:00:00"
            values["Dst Port"] = "443"
            values["Protocol"] = "6"
            values["Label"] = "Bot" if include_attack and index == records - 1 else "Benign"
            writer.writerow([values[column] for column in CIC_COLUMNS])


def write_rows(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows(rows)


class RunnerFixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.sources = self.base / "sources"
        self.scratch = self.base / "scratch"
        self.outside = self.base / "outside"
        self.sources.mkdir()
        self.scratch.mkdir()
        self.outside.mkdir()
        self.registry = registry()
        self.acceptance_profile = load_json(ACCEPTANCE_PROFILE_PATH)
        self.runner_profile = load_json(RUNNER_PROFILE_PATH)
        self.runner_binding = load_json(RUNNER_BINDING_PATH)
        self.runner = OfflineRealSourceRunner(
            profile=self.runner_profile,
            binding=self.runner_binding,
        )

    def close(self) -> None:
        self.temp.cleanup()

    def run(self, manifest: dict, source_paths: dict[str, str | Path]):
        return self.runner.run(
            manifest=manifest,
            acceptance_profile=self.acceptance_profile,
            registry=self.registry,
            policy_fingerprint=POLICY_FINGERPRINT,
            source_paths=source_paths,
            authorized_root=self.sources,
            scratch_root=self.scratch,
            exact_head_sha=EXACT_HEAD,
            spec_fingerprint=SPEC_FINGERPRINT,
        )

    def cic_manifest(self, *, include_attack: bool = True, records: int = 1000):
        path = self.sources / "cic.csv"
        write_cic(path, records=records, include_attack=include_attack)
        source = source_manifest(
            source_id="cic",
            dataset_id="cse-cic-ids2018",
            variant="processed-ml",
            source_family=None,
            publisher_reference="https://www.unb.ca/cic/datasets/ids-2018.html",
            logical_ref="cic/processed-ml/cic.csv",
            path=path,
            adapter_id=CIC_ADAPTER_ID,
            adapter_version=CIC_ADAPTER_VERSION,
        )
        return manifest_for([source], ["cic_processed_ml"], self.registry), {"cic": "cic.csv"}, path

    def lanl_manifest(self, *, redteam_mode: str = "exact"):
        auth = self.sources / "auth.csv"
        process = self.sources / "process.csv"
        dns = self.sources / "dns.csv"
        flow = self.sources / "flow.csv"
        redteam = self.sources / "redteam.csv"

        auth_rows: list[list[str]] = []
        if redteam_mode == "ambiguous":
            auth_rows.extend(
                [
                    ["1", "U1", "?", "C1", "D1", "Kerberos", "Network", "LogOn", "Success"],
                    ["1", "U1", "?", "C1", "D1", "Kerberos", "Network", "LogOn", "Success"],
                ]
            )
            start = 3
        else:
            auth_rows.append(
                ["1", "U1", "?", "C1", "D1", "Kerberos", "Network", "LogOn", "Success"]
            )
            start = 2
        while len(auth_rows) < 100:
            i = start + len(auth_rows)
            auth_rows.append(
                [str(i), f"U{i}", "?", f"C{i}", f"D{i}", "Kerberos", "Network", "LogOn", "Success"]
            )
        write_rows(auth, auth_rows)
        write_rows(
            process,
            [[str(i), f"U{i}", f"C{i}", f"proc{i}", "Start"] for i in range(1, 101)],
        )
        write_rows(
            dns,
            [[str(i), f"C{i}", f"R{i}"] for i in range(1, 101)],
        )
        write_rows(
            flow,
            [[str(i), "1", f"C{i}", "1000", f"D{i}", "443", "TCP", "1", "100"] for i in range(1, 101)],
        )
        if redteam_mode == "zero":
            redteam_row = ["1", "NO_MATCH", "C1", "D1"]
        else:
            redteam_row = ["1", "U1", "C1", "D1"]
        write_rows(redteam, [redteam_row])

        specs = [
            ("auth", "auth", auth, "lanl/auth/auth.csv", LANL_AUTH_ADAPTER_ID, LANL_AUTH_ADAPTER_VERSION, "lanl_authentication"),
            ("process", "process", process, "lanl/process/process.csv", LANL_PROCESS_ADAPTER_ID, LANL_PROCESS_ADAPTER_VERSION, "lanl_process"),
            ("dns", "dns", dns, "lanl/dns/dns.csv", LANL_DNS_ADAPTER_ID, LANL_DNS_ADAPTER_VERSION, "lanl_dns"),
            ("flow", "flow", flow, "lanl/flow/flow.csv", LANL_FLOW_ADAPTER_ID, LANL_FLOW_ADAPTER_VERSION, "lanl_flow"),
            ("redteam", "redteam", redteam, "lanl/redteam/redteam.csv", LANL_REDTEAM_MATCHER_ID, LANL_REDTEAM_MATCHER_VERSION, "lanl_redteam_truth"),
        ]
        sources: list[dict] = []
        paths: dict[str, str] = {}
        lanes: list[str] = []
        for source_id, family, path, logical, adapter_id, version, lane in specs:
            sources.append(
                source_manifest(
                    source_id=source_id,
                    dataset_id="lanl-comprehensive",
                    variant="events",
                    source_family=family,
                    publisher_reference="https://csr.lanl.gov/data/cyber1/",
                    logical_ref=logical,
                    path=path,
                    adapter_id=adapter_id,
                    adapter_version=version,
                )
            )
            paths[source_id] = path.name
            lanes.append(lane)
        return manifest_for(sources, lanes, self.registry), paths, {
            "auth": auth,
            "process": process,
            "dns": dns,
            "flow": flow,
            "redteam": redteam,
        }


class OfflineRealSourceRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = RunnerFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_cic_production_runner_passes_synthetic_filesystem_harness(self) -> None:
        manifest, paths, source = self.fx.cic_manifest()
        result = self.fx.run(manifest, paths)
        self.assertEqual(result.decision.verdict, PASS)
        self.assertEqual(result.lane_executions[0].records_emitted, 1000)
        self.assertEqual(set(result.lane_executions[0].truth_classes), {"Benign", "Bot"})
        self.assertTrue(source.exists(), "operator-owned source must never be deleted")
        self.assertEqual(list(self.fx.scratch.iterdir()), [])
        receipt_text = json.dumps(result.receipts, sort_keys=True)
        self.assertNotIn(str(source.resolve()), receipt_text)
        self.assertNotIn("Bot", receipt_text)

    def test_runner_fingerprint_is_stable_across_repeated_runs(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        first = self.fx.run(manifest, paths)
        second = self.fx.run(manifest, paths)
        self.assertEqual(first.runner_fingerprint, second.runner_fingerprint)
        self.assertEqual(
            first.lane_executions[0].evidence_fingerprint,
            second.lane_executions[0].evidence_fingerprint,
        )

    def test_cic_benign_only_is_not_enough_real_source_evidence(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest(include_attack=False)
        result = self.fx.run(manifest, paths)
        self.assertEqual(result.decision.verdict, NOT_ENOUGH_REAL_SOURCE_EVIDENCE)
        self.assertIn("CIC_MISSING_NON_BENIGN_TRUTH", result.decision.failed_gate_ids)

    def test_digest_mismatch_fails_integrity_and_preserves_source(self) -> None:
        manifest, paths, source = self.fx.cic_manifest()
        manifest["sources"][0]["bounded_source_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_INTEGRITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_SOURCE_DIGEST_MISMATCH")
        self.assertTrue(source.exists())
        self.assertEqual(list(self.fx.scratch.iterdir()), [])

    def test_size_mismatch_fails_integrity(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        manifest["sources"][0]["bounded_source_size_bytes"] += 1
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_INTEGRITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_SOURCE_SIZE_MISMATCH")

    def test_outside_root_mapping_fails_security(self) -> None:
        manifest, _, _ = self.fx.cic_manifest()
        outside = self.fx.outside / "outside.csv"
        write_cic(outside)
        manifest["sources"][0]["bounded_source_sha256"] = sha256_file(outside)
        manifest["sources"][0]["bounded_source_size_bytes"] = outside.stat().st_size
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, {"cic": "../outside/outside.csv"})
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_SOURCE_ESCAPE")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_symlink_source_fails_security(self) -> None:
        manifest, _, source = self.fx.cic_manifest()
        link = self.fx.sources / "cic-link.csv"
        try:
            os.symlink(source, link)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, {"cic": "cic-link.csv"})
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_SOURCE_SYMLINK")

    def test_unmanifested_extra_file_is_not_discovered(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        (self.fx.sources / "unmanifested.bin").write_bytes(b"not a corpus")
        result = self.fx.run(manifest, paths)
        self.assertEqual(result.decision.verdict, PASS)

    def test_extra_source_mapping_key_fails_security(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        paths["unmanifested"] = "unmanifested.bin"
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_SOURCE_MAPPING_INVALID")

    def test_nonempty_unrelated_scratch_is_rejected(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        (self.fx.scratch / "unrelated.txt").write_text("keep", encoding="utf-8")
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_SCRATCH_ROOT_INVALID")
        self.assertTrue((self.fx.scratch / "unrelated.txt").exists())

    def test_cleanup_failure_invalidates_pass(self) -> None:
        manifest, paths, source = self.fx.cic_manifest()
        with mock.patch(
            "three_agent.network_real_source_runner.shutil.rmtree",
            side_effect=OSError("fixture cleanup failure"),
        ):
            with self.assertRaises(RealSourceRunnerError) as caught:
                self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_CLEANUP_FAILED")
        self.assertTrue(source.exists())

    def test_invalid_manifest_fails_before_any_source_open(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        manifest["registry_fingerprint"] = "sha256:" + "0" * 64
        with mock.patch("pathlib.Path.open", side_effect=AssertionError("source open forbidden")):
            with self.assertRaises(RealSourceRunnerError) as caught:
                self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.gate_id, "RUNNER_MANIFEST_INVALID")

    def test_unknown_adapter_id_is_security_failure(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        manifest["sources"][0]["adapter_id"] = "evil.dynamic.Adapter"
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RUNNER_ADAPTER_NOT_AUTHORIZED")

    def test_adapter_version_mismatch_is_schema_failure(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        manifest["sources"][0]["adapter_version"] = "cse-cic-ids2018-processed-ml/999"
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_SCHEMA)
        self.assertEqual(caught.exception.gate_id, "RUNNER_ADAPTER_VERSION_MISMATCH")

    def test_bots_direct_request_is_security_failure(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        source = manifest["sources"][0]
        source["dataset_id"] = "splunk-bots-v2"
        source["adapter_id"] = "splunk-bots-v2-direct"
        with self.assertRaises(RealSourceRunnerError) as caught:
            self.fx.run(manifest, paths)
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "BOTS_DIRECT_ADAPTER_ATTEMPT")

    def test_lanl_full_multifamily_and_exact_redteam_match_passes(self) -> None:
        manifest, paths, source_files = self.fx.lanl_manifest(redteam_mode="exact")
        result = self.fx.run(manifest, paths)
        self.assertEqual(result.decision.verdict, PASS)
        lanes = {item.lane_id: item for item in result.lane_executions}
        for lane_id in (
            "lanl_authentication",
            "lanl_process",
            "lanl_dns",
            "lanl_flow",
        ):
            self.assertEqual(lanes[lane_id].records_emitted, 100)
        self.assertEqual(lanes["lanl_redteam_truth"].redteam_exact_matches, 1)
        self.assertEqual(lanes["lanl_redteam_truth"].redteam_ambiguous, 0)
        for path in source_files.values():
            self.assertTrue(path.exists())
        self.assertEqual(list(self.fx.scratch.iterdir()), [])

    def test_lanl_redteam_zero_match_does_not_invent_truth(self) -> None:
        manifest, paths, _ = self.fx.lanl_manifest(redteam_mode="zero")
        result = self.fx.run(manifest, paths)
        lanes = {item.lane_id: item for item in result.lane_executions}
        redteam = lanes["lanl_redteam_truth"]
        self.assertEqual(redteam.truth_records_emitted, 0)
        self.assertEqual(redteam.redteam_unmatched, 1)
        self.assertEqual(result.decision.verdict, NOT_ENOUGH_REAL_SOURCE_EVIDENCE)

    def test_lanl_redteam_ambiguous_match_does_not_invent_truth(self) -> None:
        manifest, paths, _ = self.fx.lanl_manifest(redteam_mode="ambiguous")
        result = self.fx.run(manifest, paths)
        lanes = {item.lane_id: item for item in result.lane_executions}
        redteam = lanes["lanl_redteam_truth"]
        self.assertEqual(redteam.truth_records_emitted, 0)
        self.assertEqual(redteam.redteam_ambiguous, 1)
        self.assertEqual(result.decision.verdict, NOT_ENOUGH_REAL_SOURCE_EVIDENCE)

    def test_runner_has_no_network_model_or_subprocess_authority(self) -> None:
        manifest, paths, _ = self.fx.cic_manifest()
        with mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden")), mock.patch(
            "subprocess.Popen", side_effect=AssertionError("subprocess forbidden")
        ), mock.patch("urllib.request.urlopen", side_effect=AssertionError("HTTP forbidden")):
            result = self.fx.run(manifest, paths)
        self.assertEqual(result.decision.verdict, PASS)
        for observation in result.observations:
            self.assertEqual(observation.network_calls, 0)
            self.assertEqual(observation.model_calls, 0)
            self.assertEqual(observation.subprocess_calls, 0)


if __name__ == "__main__":
    unittest.main()
