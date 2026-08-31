from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "lanl-publisher-access-contract.yml"


class LANLPublisherAccessWorkflowScopeTests(unittest.TestCase):
    def workflow_text(self) -> str:
        self.assertTrue(WORKFLOW_PATH.is_file(), "LANL publisher-access workflow is required")
        return WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_pull_request_trigger_is_materially_scoped(self) -> None:
        text = self.workflow_text()
        self.assertIn("pull_request:\n    paths:", text)

        required_paths = (
            ".github/workflows/lanl-publisher-access-contract.yml",
            "tests/test_network_lanl_publisher_access.py",
            "tests/test_network_lanl_publisher_access_workflow_scope.py",
            "evaluation/network_v3_02e_lanl_publisher_access_v1.json",
            "pyproject.toml",
            "src/three_agent/__init__.py",
            "src/three_agent/network_lanl_publisher_access.py",
            "src/three_agent/network_lanl_adapter.py",
            "src/three_agent/network_lanl_dns_adapter.py",
            "src/three_agent/network_lanl_flow_adapter.py",
            "src/three_agent/network_lanl_process_adapter.py",
            "src/three_agent/network_lanl_redteam_matcher.py",
            "src/three_agent/network_lanl_family.py",
            "src/three_agent/network_corpus_adapter.py",
            "src/three_agent/network_real_source_acceptance_contract.py",
        )
        for path in required_paths:
            with self.subTest(path=path):
                self.assertIn(f"      - '{path}'", text)

        for broad in ("src/**", "tests/**", "docs/**", "evaluation/**"):
            with self.subTest(broad=broad):
                self.assertNotIn(broad, text)

        self.assertNotIn("SECURITY_ANALYST_NETWORK_MONITORING", text)

    def test_exact_head_and_non_pr_triggers_remain_unchanged(self) -> None:
        text = self.workflow_text()
        expression = "github.event.pull_request.head.sha || github.sha"
        self.assertGreaterEqual(text.count(expression), 2)
        self.assertIn("push:\n    branches: [main]", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("persist-credentials: false", text)


if __name__ == "__main__":
    unittest.main()
