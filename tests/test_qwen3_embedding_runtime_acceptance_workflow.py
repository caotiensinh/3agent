import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "qwen3-embedding-runtime-acceptance.yml"
REQUEST = REPO_ROOT / "config" / "model-candidates" / "qwen3-embedding-0.6b.acceptance-request.json"
SOURCE = REPO_ROOT / "config" / "model-candidates" / "qwen3-embedding-0.6b.source.json"


class Qwen3RuntimeAcceptanceWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_is_review_gated_and_read_only(self):
        self.assertIn("workflow_dispatch:", self.source)
        self.assertNotIn("  pull_request:\n", self.source)
        self.assertIn("  push:\n", self.source)
        self.assertIn("    branches:\n      - main", self.source)
        self.assertIn(
            "    paths:\n      - 'config/model-candidates/qwen3-embedding-0.6b.acceptance-request.json'",
            self.source,
        )
        self.assertIn("permissions:\n  contents: read", self.source)

    def test_acceptance_request_is_non_authoritative_and_matches_source(self):
        request = json.loads(REQUEST.read_text(encoding="utf-8"))
        source = json.loads(SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(request["schema"], "workspace.model-candidate-acceptance-request/v1")
        self.assertEqual(request["status"], "requested")
        self.assertEqual(request["gate"], "offline_runtime_acceptance")
        self.assertFalse(request["production_approval"])
        self.assertFalse(request["runtime_authority"])
        self.assertEqual(request["repo_id"], source["repo_id"])
        self.assertEqual(request["revision"], source["revision"])
        self.assertFalse(source["approval"]["approved"])

    def test_download_is_audit_only_and_acceptance_runs_without_network(self):
        self.assertIn("scripts/audit_hf_model_candidate.py", self.source)
        self.assertIn("--snapshot-output", self.source)
        self.assertIn("expected_anchors", self.source)
        self.assertIn("unshare --net", self.source)
        self.assertIn("HF_HUB_OFFLINE: '1'", self.source)
        self.assertIn("TRANSFORMERS_OFFLINE: '1'", self.source)
        self.assertIn("scripts/accept_hf_model_candidate.py", self.source)

    def test_model_bytes_are_deleted_before_receipts_are_uploaded(self):
        cleanup = self.source.index("- name: Delete model bytes and local model caches")
        upload = self.source.index("- name: Upload evidence receipts only")
        self.assertLess(cleanup, upload)
        self.assertIn("qwen3-embedding-verified-snapshot", self.source[cleanup:upload])

        upload_block = self.source[upload:]
        self.assertIn("qwen3-embedding-candidate-evidence.json", upload_block)
        self.assertIn("qwen3-embedding-runtime-acceptance.json", upload_block)
        self.assertNotIn("qwen3-embedding-verified-snapshot", upload_block)
        self.assertNotIn("model.safetensors", upload_block)

    def test_request_and_receipt_validation_cannot_grant_approval(self):
        self.assertIn("request.get('production_approval') is not False", self.source)
        self.assertIn("request.get('runtime_authority') is not False", self.source)
        self.assertIn("approval.get('approved') is not False", self.source)
        self.assertIn("runtime.get('runtime_download') is not False", self.source)
        self.assertIn("runtime.get('python_socket_attempts') != 0", self.source)
        self.assertIn("residency_eviction", self.source)

    def test_runner_temp_is_environment_driven(self):
        self.assertNotIn("Path.home() / 'work' / '_temp'", self.source)
        self.assertIn("os.environ['RUNNER_TEMP']", self.source)


if __name__ == "__main__":
    unittest.main()
