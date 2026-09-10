from __future__ import annotations

import ast
import copy
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import three_agent.network_cic_real_source_evidence as cic
from three_agent.network_real_source_acceptance_contract import (
    FAIL_INTEGRITY,
    FAIL_PROVENANCE,
    FAIL_RESOURCE,
    FAIL_SCHEMA,
    FAIL_SECURITY,
    NOT_ENOUGH_REAL_SOURCE_EVIDENCE,
    PASS,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "evaluation" / "network_v3_02e_cic_real_source_ci_v1.json"
REGISTRY_PATH = ROOT / "config" / "network-datasets.registry.json"
POLICY_PATH = ROOT / "config" / "network-data-policy.json"
SPEC_PATH = ROOT / "docs" / "WORKSPACE_NETWORK_V3_02E_CIC_REAL_SOURCE_CI_SPEC_V1.md"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "cic-real-source-evidence.yml"
EXACT_HEAD = "1" * 40


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class CICEvidenceFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source_root = self.base / "source"
        self.scratch_root = self.base / "scratch"
        self.output_dir = self.base / "evidence"
        self.outside = self.base / "outside"
        for path in (self.source_root, self.scratch_root, self.output_dir, self.outside):
            path.mkdir()
        self.parent = self.source_root / "parent.csv"
        self.bounded = self.source_root / "bounded.csv"
        self.write_parent()
        self.profile = load_json(PROFILE_PATH)
        self.registry = load_json(REGISTRY_PATH)
        self.policy = load_json(POLICY_PATH)

    def close(self) -> None:
        self.temp.cleanup()

    def write_parent(self, records: int = 5) -> None:
        lines = ["a,b,c\r\n"]
        for index in range(records):
            lines.append(f"{index},x{index},y{index}\r\n")
        self.parent.write_bytes("".join(lines).encode("utf-8"))

    def prepare(self, *, profile: dict | None = None) -> cic.PreparedCICEvidence:
        return cic.prepare_cic_evidence(
            parent_source_path=self.parent,
            bounded_source_path=self.bounded,
            exact_head_sha=EXACT_HEAD,
            s3_etag='"fixture-etag"',
            s3_last_modified="2018-03-02T00:00:00Z",
            profile=profile or self.profile,
            registry=self.registry,
            policy=self.policy,
            spec_path=SPEC_PATH,
        )


def fake_result(verdict: str) -> SimpleNamespace:
    failed = () if verdict == PASS else ("CIC_MISSING_NON_BENIGN_TRUTH",)
    classes = ("Benign", "Infilteration") if verdict == PASS else ("Benign",)
    lane = SimpleNamespace(
        lane_id=cic.EXPECTED_LANE,
        records_seen=1200,
        records_emitted=1200,
        records_rejected=0,
        truth_records_emitted=1200,
        truth_classes=classes,
        evidence_fingerprint="sha256:" + "a" * 64,
        truth_fingerprint="sha256:" + "b" * 64,
    )
    return SimpleNamespace(
        decision=SimpleNamespace(verdict=verdict, failed_gate_ids=failed),
        lane_executions=(lane,),
        runner_fingerprint="sha256:" + "c" * 64,
        manifest_fingerprint="sha256:" + "d" * 64,
        exact_head_sha=EXACT_HEAD,
        peak_rss_delta_bytes=4096,
        cleanup_pass=True,
        receipts=(
            {
                "schema_version": "workspace-network-real-source-acceptance-receipt/v1",
                "verdict": verdict,
                "evidence_fingerprint": "sha256:" + "a" * 64,
            },
        ),
    )


class CICRealSourceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CICEvidenceFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_valid_parent_builds_deterministic_bounded_manifest(self) -> None:
        first = self.fx.prepare()
        first_bytes = self.fx.bounded.read_bytes()
        second = self.fx.prepare()
        self.assertEqual(first.bounded_source_sha256, second.bounded_source_sha256)
        self.assertEqual(first_bytes, self.fx.bounded.read_bytes())
        self.assertEqual(first.bounded_data_record_count, 5)
        source = first.manifest["sources"][0]
        self.assertEqual(source["parent_source_sha256"], first.parent_source_sha256)
        self.assertEqual(source["bounded_source_sha256"], first.bounded_source_sha256)
        self.assertEqual(source["derivation"]["method"], cic.DERIVATION_METHOD)
        self.assertEqual(
            source["derivation"]["selection_rule"], cic.DERIVATION_SELECTION_RULE
        )
        self.assertEqual(
            source["derivation"]["record_boundary_rule"],
            cic.DERIVATION_RECORD_BOUNDARY_RULE,
        )
        receipt = first.acquisition_receipt
        self.assertEqual(receipt["bounded_data_record_count"], 5)
        self.assertNotIn("raw_record", json.dumps(receipt))

    def test_wrong_bucket_object_or_source_authority_fails_security(self) -> None:
        mutations = (
            ("bucket", "mirror-bucket"),
            ("object_key", "other.csv"),
            ("credentials_allowed", True),
            ("mirrors_allowed", True),
            ("signed_urls_allowed", True),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                profile = copy.deepcopy(self.fx.profile)
                profile["source"][field] = value
                with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
                    self.fx.prepare(profile=profile)
                self.assertEqual(caught.exception.verdict, FAIL_SECURITY)

    def test_derivation_rule_drift_fails_provenance(self) -> None:
        profile = copy.deepcopy(self.fx.profile)
        profile["bounded_derivation"]["selection_rule"] = "random_records"
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            self.fx.prepare(profile=profile)
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "BOUNDED_DERIVATION_INVALID")

    def test_label_aware_random_or_shuffle_selection_fails_security(self) -> None:
        for field in (
            "label_aware_selection_allowed",
            "random_selection_allowed",
            "shuffle_allowed",
            "wall_clock_selection_allowed",
        ):
            with self.subTest(field=field):
                profile = copy.deepcopy(self.fx.profile)
                profile["bounded_derivation"][field] = True
                with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
                    self.fx.prepare(profile=profile)
                self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
                self.assertEqual(
                    caught.exception.gate_id, "LABEL_AWARE_SELECTION_ATTEMPT"
                )

    def test_adapter_binding_drift_fails_schema(self) -> None:
        for field in ("adapter_id", "adapter_version", "expected_lane"):
            with self.subTest(field=field):
                profile = copy.deepcopy(self.fx.profile)
                profile["production_binding"][field] = "drifted"
                with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
                    self.fx.prepare(profile=profile)
                self.assertEqual(caught.exception.verdict, FAIL_SCHEMA)
                self.assertEqual(caught.exception.gate_id, "ADAPTER_BINDING_DRIFT")

    def test_parent_size_gate_is_fail_resource(self) -> None:
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            cic._validate_regular_source(
                self.fx.parent, 1, size_gate="SOURCE_TOO_LARGE"
            )
        self.assertEqual(caught.exception.verdict, FAIL_RESOURCE)
        self.assertEqual(caught.exception.gate_id, "SOURCE_TOO_LARGE")

    def test_bounded_record_budget_cannot_be_increased(self) -> None:
        profile = copy.deepcopy(self.fx.profile)
        profile["bounded_derivation"]["maximum_data_records"] = 250001
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            self.fx.prepare(profile=profile)
        self.assertEqual(caught.exception.verdict, FAIL_RESOURCE)
        self.assertEqual(caught.exception.gate_id, "BOUNDED_RECORD_LIMIT_EXCEEDED")

    def test_missing_s3_metadata_fails_provenance(self) -> None:
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            cic.prepare_cic_evidence(
                parent_source_path=self.fx.parent,
                bounded_source_path=self.fx.bounded,
                exact_head_sha=EXACT_HEAD,
                s3_etag="",
                s3_last_modified="2018-03-02T00:00:00Z",
                profile=self.fx.profile,
                registry=self.fx.registry,
                policy=self.fx.policy,
                spec_path=SPEC_PATH,
            )
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "CIC_S3_METADATA_INVALID")

    def test_parent_tamper_after_binding_fails_integrity(self) -> None:
        prepared = self.fx.prepare()
        self.fx.parent.write_bytes(self.fx.parent.read_bytes() + b"tamper\n")
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            cic.verify_prepared_source(prepared)
        self.assertEqual(caught.exception.verdict, FAIL_INTEGRITY)
        self.assertEqual(
            caught.exception.gate_id, "SOURCE_DIGEST_OR_SIZE_BINDING_FAILED"
        )

    def test_bounded_tamper_after_derivation_fails_integrity(self) -> None:
        prepared = self.fx.prepare()
        self.fx.bounded.write_bytes(self.fx.bounded.read_bytes() + b"tamper\n")
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            cic.verify_prepared_source(prepared)
        self.assertEqual(caught.exception.verdict, FAIL_INTEGRITY)

    def test_forbidden_raw_content_key_cannot_be_written(self) -> None:
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            cic._safe_write_json(
                self.fx.output_dir,
                "evidence-summary.json",
                {"raw_payload": "forbidden"},
            )
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RAW_SOURCE_IN_DURABLE_ARTIFACT")

    def test_output_and_source_roots_must_be_disjoint(self) -> None:
        prepared = self.fx.prepare()
        nested_output = self.fx.source_root / "evidence"
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            cic.execute_cic_evidence(
                prepared=prepared,
                exact_head_sha=EXACT_HEAD,
                source_root=self.fx.source_root,
                scratch_root=self.fx.scratch_root,
                output_dir=nested_output,
                acceptance_profile={},
                runner_profile={},
                runner_binding={},
                registry=self.fx.registry,
            )
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "RAW_SOURCE_IN_DURABLE_ARTIFACT")

    def test_source_path_escape_is_rejected_before_runner(self) -> None:
        outside_parent = self.fx.outside / "parent.csv"
        outside_parent.write_bytes(self.fx.parent.read_bytes())
        outside_bounded = self.fx.outside / "bounded.csv"
        prepared = cic.prepare_cic_evidence(
            parent_source_path=outside_parent,
            bounded_source_path=outside_bounded,
            exact_head_sha=EXACT_HEAD,
            s3_etag='"fixture-etag"',
            s3_last_modified="2018-03-02T00:00:00Z",
            profile=self.fx.profile,
            registry=self.fx.registry,
            policy=self.fx.policy,
            spec_path=SPEC_PATH,
        )
        with self.assertRaises(cic.CICRealSourceEvidenceError) as caught:
            cic.execute_cic_evidence(
                prepared=prepared,
                exact_head_sha=EXACT_HEAD,
                source_root=self.fx.source_root,
                scratch_root=self.fx.scratch_root,
                output_dir=self.fx.output_dir,
                acceptance_profile={},
                runner_profile={},
                runner_binding={},
                registry=self.fx.registry,
            )
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "SOURCE_PATH_ESCAPE")

    def test_executor_has_no_network_model_or_subprocess_client_authority(self) -> None:
        tree = ast.parse(inspect.getsource(cic))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        forbidden = {
            "requests",
            "boto3",
            "botocore",
            "socket",
            "http.client",
            "urllib.request",
            "subprocess",
            "openai",
            "ollama",
        }
        self.assertFalse(imported & forbidden, imported & forbidden)
        self.assertIn("urllib.parse", imported)

    def test_runner_pass_writes_only_allowlisted_metadata_artifacts(self) -> None:
        prepared = self.fx.prepare()
        runner = SimpleNamespace(run=mock.Mock(return_value=fake_result(PASS)))
        with mock.patch.object(cic, "OfflineRealSourceRunner", return_value=runner):
            verdict = cic.execute_cic_evidence(
                prepared=prepared,
                exact_head_sha=EXACT_HEAD,
                source_root=self.fx.source_root,
                scratch_root=self.fx.scratch_root,
                output_dir=self.fx.output_dir,
                acceptance_profile={},
                runner_profile={},
                runner_binding={},
                registry=self.fx.registry,
            )
        self.assertEqual(verdict, PASS)
        self.assertEqual(
            {path.name for path in self.fx.output_dir.iterdir()},
            set(cic.ALLOWED_OUTPUT_FILENAMES),
        )
        durable_text = "\n".join(
            path.read_text(encoding="utf-8") for path in self.fx.output_dir.iterdir()
        )
        self.assertNotIn("raw_payload", durable_text)
        self.assertNotIn("a,b,c", durable_text)
        runner.run.assert_called_once()
        source_paths = runner.run.call_args.kwargs["source_paths"]
        self.assertEqual(
            source_paths, {cic.EXPECTED_SOURCE_ID: self.fx.bounded.name}
        )

    def test_runner_insufficient_coverage_remains_not_enough_evidence(self) -> None:
        prepared = self.fx.prepare()
        runner = SimpleNamespace(
            run=mock.Mock(return_value=fake_result(NOT_ENOUGH_REAL_SOURCE_EVIDENCE))
        )
        with mock.patch.object(cic, "OfflineRealSourceRunner", return_value=runner):
            verdict = cic.execute_cic_evidence(
                prepared=prepared,
                exact_head_sha=EXACT_HEAD,
                source_root=self.fx.source_root,
                scratch_root=self.fx.scratch_root,
                output_dir=self.fx.output_dir,
                acceptance_profile={},
                runner_profile={},
                runner_binding={},
                registry=self.fx.registry,
            )
        self.assertEqual(verdict, NOT_ENOUGH_REAL_SOURCE_EVIDENCE)
        summary = load_json(self.fx.output_dir / "evidence-summary.json")
        self.assertEqual(summary["verdict"], NOT_ENOUGH_REAL_SOURCE_EVIDENCE)


class CICRealSourceWorkflowContractTests(unittest.TestCase):
    def workflow_text(self) -> str:
        self.assertTrue(WORKFLOW_PATH.is_file(), "real-source workflow is required")
        return WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_workflow_uses_only_exact_unsigned_official_s3_object(self) -> None:
        text = self.workflow_text()
        self.assertIn("name: cic-real-source-evidence", text)
        self.assertIn("aws s3api head-object", text)
        self.assertIn("aws s3 cp", text)
        self.assertIn("--no-sign-request", text)
        self.assertIn("cse-cic-ids2018", text)
        self.assertIn(cic.EXPECTED_OBJECT_KEY, text)
        self.assertNotIn("aws s3 sync", text)
        self.assertNotIn("configure-aws-credentials", text)
        self.assertNotIn("AWS_ACCESS_KEY_ID", text)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", text)
        self.assertNotIn("curl ", text)
        self.assertNotIn("wget ", text)

    def test_workflow_checks_out_and_executes_exact_pr_head(self) -> None:
        text = self.workflow_text()
        exact_expression = "github.event.pull_request.head.sha || github.sha"
        self.assertGreaterEqual(text.count(exact_expression), 2)
        self.assertIn("--exact-head \"$EXACT_HEAD\"", text)
        self.assertIn("--parent-source", text)
        self.assertIn("--bounded-source", text)

    def test_artifact_step_contains_only_four_json_allowlisted_files(self) -> None:
        text = self.workflow_text()
        marker = "uses: actions/upload-artifact@v4"
        start = text.index(marker)
        end = text.find("\n      - name:", start + len(marker))
        segment = text[start:] if end < 0 else text[start:end]
        for filename in sorted(cic.ALLOWED_OUTPUT_FILENAMES):
            self.assertIn(filename, segment)
        self.assertNotIn(".csv", segment)
        self.assertNotIn("source-root", segment)

    def test_always_cleanup_occurs_after_artifact_upload(self) -> None:
        text = self.workflow_text()
        artifact_index = text.index("uses: actions/upload-artifact@v4")
        cleanup_index = text.index("- name: Always remove CIC source bytes")
        self.assertGreater(cleanup_index, artifact_index)
        cleanup = text[cleanup_index:]
        self.assertIn("if: always()", cleanup)
        self.assertIn("rm -rf", cleanup)
        self.assertIn("test ! -e", cleanup)


if __name__ == "__main__":
    unittest.main()
