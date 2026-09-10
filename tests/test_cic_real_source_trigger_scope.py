from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "cic-real-source-evidence.yml"


class CICRealSourceTriggerScopeTests(unittest.TestCase):
    def pull_request_block(self) -> str:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        start = text.index("  pull_request:\n")
        end = text.index("  push:\n", start)
        return text[start:end]

    def test_pull_request_trigger_is_path_scoped(self) -> None:
        block = self.pull_request_block()
        self.assertIn("    paths:\n", block)
        required = (
            ".github/workflows/cic-real-source-evidence.yml",
            "src/three_agent/network_cic_real_source_evidence.py",
            "src/three_agent/network_real_source_runner.py",
            "src/three_agent/network_real_source_acceptance_contract.py",
            "evaluation/network_v3_02e_cic_real_source_ci_v1.json",
            "config/network-datasets.registry.json",
            "config/network-data-policy.json",
            "tests/test_network_cic_real_source_evidence.py",
            "tests/test_cic_real_source_trigger_scope.py",
        )
        for path in required:
            with self.subTest(path=path):
                self.assertIn(f"      - '{path}'\n", block)

    def test_trigger_does_not_use_broad_unrelated_wildcards(self) -> None:
        block = self.pull_request_block()
        for forbidden in ("src/**", "tests/**", "docs/**", "**/*.py", "**/*.md"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, block)
        self.assertNotIn("SECURITY_ANALYST_NETWORK_MONITORING", block)

    def test_exact_head_provenance_contract_is_preserved(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        expression = "github.event.pull_request.head.sha || github.sha"
        self.assertGreaterEqual(text.count(expression), 2)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", text)
        self.assertIn('--exact-head "$EXACT_HEAD"', text)


if __name__ == "__main__":
    unittest.main()
