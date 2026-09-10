from __future__ import annotations

import ast
import copy
import inspect
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import three_agent.network_lanl_publisher_access as access

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "evaluation" / "network_v3_02e_lanl_publisher_access_v1.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "lanl-publisher-access-contract.yml"


def load_profile() -> dict:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def valid_handles() -> dict[str, str]:
    return {
        family: f"https://csr.lanl.gov/data/cyber1/{binding['filename']}"
        for family, binding in access.SOURCE_BINDINGS.items()
    }


class LANLPublisherAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile()

    def assert_access_error(self, handles, readiness, gate_id) -> None:
        with self.assertRaises(access.LANLPublisherAccessError) as caught:
            access.evaluate_access_handles(handles, profile=self.profile)
        self.assertEqual(caught.exception.readiness, readiness)
        self.assertEqual(caught.exception.gate_id, gate_id)

    def test_no_handles_is_not_enough_real_source_evidence(self) -> None:
        decision = access.evaluate_access_handles({}, profile=self.profile)
        self.assertEqual(decision.readiness, access.NOT_ENOUGH)
        self.assertEqual(decision.failed_gate_ids, ("LANL_ACCESS_HANDLE_MISSING",))
        self.assertEqual(set(decision.missing_source_families), set(access.SOURCE_BINDINGS))
        self.assertEqual(decision.validated_source_families, ())

    def test_partial_handles_remain_not_enough(self) -> None:
        handles = valid_handles()
        handles.pop("redteam")
        decision = access.evaluate_access_handles(handles, profile=self.profile)
        self.assertEqual(decision.readiness, access.NOT_ENOUGH)
        self.assertEqual(decision.failed_gate_ids, ("LANL_SOURCE_FAMILY_MISSING",))
        self.assertEqual(decision.missing_source_families, ("redteam",))

    def test_all_five_synthetic_exact_publisher_handles_are_ready_for_next_spec(self) -> None:
        handles = valid_handles()
        decision = access.evaluate_access_handles(handles, profile=self.profile)
        self.assertEqual(decision.readiness, access.READY)
        self.assertEqual(decision.failed_gate_ids, ())
        self.assertEqual(
            decision.validated_source_families, tuple(access.SOURCE_BINDINGS)
        )
        durable = json.dumps(decision.receipt, sort_keys=True)
        for raw in handles.values():
            self.assertNotIn(raw, durable)
        self.assertNotIn("auth.txt.gz", durable)
        self.assertEqual(
            decision.receipt["publisher_reference"], access.PUBLISHER_REFERENCE
        )

    def test_http_is_not_accepted_as_publisher_access(self) -> None:
        handles = valid_handles()
        handles["auth"] = "http://csr.lanl.gov/data/cyber1/auth.txt.gz"
        self.assert_access_error(
            handles, access.FAIL_PROVENANCE, "LANL_ACCESS_URL_INVALID"
        )

    def test_mirror_or_alternate_host_fails_provenance(self) -> None:
        handles = valid_handles()
        handles["auth"] = "https://example.com/data/cyber1/auth.txt.gz"
        self.assert_access_error(
            handles, access.FAIL_PROVENANCE, "LANL_MIRROR_OR_ALTERNATE_HOST"
        )

    def test_embedded_userinfo_fails_security(self) -> None:
        handles = valid_handles()
        handles["auth"] = "https://user:pass@csr.lanl.gov/data/cyber1/auth.txt.gz"
        self.assert_access_error(
            handles,
            access.FAIL_SECURITY,
            "LANL_ACCESS_HANDLE_HAS_CREDENTIAL_AUTHORITY",
        )

    def test_query_or_fragment_requires_separate_review(self) -> None:
        for suffix in ("?token=fixture", "#fragment"):
            with self.subTest(suffix=suffix):
                handles = valid_handles()
                handles["auth"] += suffix
                self.assert_access_error(
                    handles,
                    access.FAIL_SECURITY,
                    "LANL_UNREVIEWED_QUERY_OR_FRAGMENT",
                )

    def test_filename_must_match_source_family(self) -> None:
        handles = valid_handles()
        handles["auth"] = "https://csr.lanl.gov/data/cyber1/proc.txt.gz"
        self.assert_access_error(
            handles, access.FAIL_PROVENANCE, "LANL_FILENAME_MISMATCH"
        )

    def test_path_must_remain_under_publisher_data_prefix(self) -> None:
        handles = valid_handles()
        handles["auth"] = "https://csr.lanl.gov/files/auth.txt.gz"
        self.assert_access_error(
            handles, access.FAIL_PROVENANCE, "LANL_ACCESS_URL_INVALID"
        )

    def test_literal_or_encoded_path_traversal_fails_security(self) -> None:
        for path in (
            "/data/../auth.txt.gz",
            "/data/%2e%2e/auth.txt.gz",
            "/data/cyber1/..%2fauth.txt.gz",
        ):
            with self.subTest(path=path):
                handles = valid_handles()
                handles["auth"] = "https://csr.lanl.gov" + path
                self.assert_access_error(
                    handles, access.FAIL_SECURITY, "LANL_ACCESS_PATH_ESCAPE"
                )

    def test_operator_form_content_is_rejected_from_access_input(self) -> None:
        for key in ("email", "email_address", "intended_use", "purpose", "form_content"):
            with self.subTest(key=key):
                handles = valid_handles()
                handles[key] = "must-not-be-stored"
                self.assert_access_error(
                    handles,
                    access.FAIL_SECURITY,
                    "LANL_OPERATOR_FORM_CONTENT_PERSISTED",
                )

    def test_redteam_truth_may_not_request_visible_slice_selection(self) -> None:
        handles = valid_handles()
        handles["redteam_driven_visible_slice"] = True
        self.assert_access_error(
            handles,
            access.FAIL_SECURITY,
            "LANL_REDTEAM_TRUTH_USED_TO_SELECT_VISIBLE_SOURCE",
        )

    def test_unknown_access_key_fails_schema(self) -> None:
        handles = valid_handles()
        handles["unknown"] = "https://csr.lanl.gov/data/cyber1/unknown.txt.gz"
        self.assert_access_error(
            handles, access.FAIL_SCHEMA, "LANL_ACCESS_INPUT_SCHEMA"
        )

    def test_profile_cannot_authorize_form_submission_or_acquisition(self) -> None:
        mutations = [
            ("publisher", "automated_form_submission_authorized"),
            ("publisher", "operator_identity_or_form_content_may_be_fabricated"),
            ("publisher", "operator_form_content_may_be_durable"),
            ("execution_authority", "network_acquisition_authorized_in_this_checkpoint"),
            ("execution_authority", "corpus_download_authorized_in_this_checkpoint"),
            ("execution_authority", "production_runner_authorized_in_this_checkpoint"),
        ]
        for section, field in mutations:
            with self.subTest(section=section, field=field):
                profile = copy.deepcopy(self.profile)
                profile[section][field] = True
                with self.assertRaises(access.LANLPublisherAccessError) as caught:
                    access.evaluate_access_handles({}, profile=profile)
                self.assertEqual(caught.exception.readiness, access.FAIL_SECURITY)

    def test_adapter_binding_drift_is_schema_failure(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["required_sources"][0]["adapter_version"] = "drifted/999"
        with self.assertRaises(access.LANLPublisherAccessError) as caught:
            access.evaluate_access_handles({}, profile=profile)
        self.assertEqual(caught.exception.readiness, access.FAIL_SCHEMA)
        self.assertEqual(caught.exception.gate_id, "LANL_ACCESS_PROFILE_DRIFT")

    def test_forbidden_operator_or_url_field_in_receipt_fails_security(self) -> None:
        decision = access.evaluate_access_handles({}, profile=self.profile)
        for key in ("email", "access_url", "token"):
            with self.subTest(key=key):
                receipt = dict(decision.receipt)
                receipt[key] = "forbidden"
                with self.assertRaises(access.LANLPublisherAccessError) as caught:
                    access.validate_durable_receipt(receipt, profile=self.profile)
                self.assertEqual(caught.exception.readiness, access.FAIL_SECURITY)
                self.assertEqual(
                    caught.exception.gate_id, "LANL_ACCESS_HANDLE_IN_DURABLE_OUTPUT"
                )

    def test_receipt_partition_and_fingerprint_are_validated(self) -> None:
        decision = access.evaluate_access_handles({}, profile=self.profile)
        receipt = dict(decision.receipt)
        receipt["contract_fingerprint"] = "sha256:" + "0" * 64
        with self.assertRaises(access.LANLPublisherAccessError) as caught:
            access.validate_durable_receipt(receipt, profile=self.profile)
        self.assertEqual(caught.exception.readiness, access.FAIL_PROVENANCE)

    def test_validator_has_no_network_form_submission_or_subprocess_authority(self) -> None:
        tree = ast.parse(inspect.getsource(access))
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

    def test_cli_without_handles_writes_safe_not_enough_receipt_and_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "readiness.json"
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = access.main(
                    [
                        "--profile",
                        str(PROFILE_PATH),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(code, 2)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["readiness"], access.NOT_ENOUGH)
            self.assertEqual(receipt["failed_gate_ids"], ["LANL_ACCESS_HANDLE_MISSING"])
            text = output.read_text(encoding="utf-8") + stdout.getvalue()
            for forbidden in access.DURABLE_FORBIDDEN_KEYS:
                self.assertNotIn(f'"{forbidden}"', text)


class LANLPublisherAccessWorkflowContractTests(unittest.TestCase):
    def workflow_text(self) -> str:
        self.assertTrue(WORKFLOW_PATH.is_file(), "LANL access contract workflow is required")
        return WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_workflow_has_no_network_or_form_submission_step(self) -> None:
        text = self.workflow_text()
        self.assertIn("name: lanl-publisher-access-contract", text)
        for forbidden in (
            "curl ",
            "wget ",
            "aws s3",
            "requests",
            "boto3",
            "csr.lanl.gov/data/",
            "secrets.",
        ):
            self.assertNotIn(forbidden, text)

    def test_workflow_checks_out_exact_head_and_runs_current_not_enough_state(self) -> None:
        text = self.workflow_text()
        expression = "github.event.pull_request.head.sha || github.sha"
        self.assertGreaterEqual(text.count(expression), 2)
        self.assertIn("tests.test_network_lanl_publisher_access", text)
        self.assertIn("network_lanl_publisher_access", text)
        self.assertIn("test \"$rc\" -eq 2", text)
        self.assertIn("NOT_ENOUGH_REAL_SOURCE_EVIDENCE", text)

    def test_workflow_uploads_only_compact_readiness_receipt(self) -> None:
        text = self.workflow_text()
        start = text.index("uses: actions/upload-artifact@v4")
        segment = text[start:]
        self.assertIn("lanl-access-readiness.json", segment)
        for forbidden in ("handles", ".gz", ".txt", "source-root", "download"):
            self.assertNotIn(forbidden, segment.casefold())


if __name__ == "__main__":
    unittest.main()
