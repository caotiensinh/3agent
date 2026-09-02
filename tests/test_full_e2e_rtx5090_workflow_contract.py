from pathlib import Path
import unittest


class FullE2ERtx5090WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = Path(".github/workflows/full-e2e-rtx5090.yml").read_text(encoding="utf-8")

    def test_workflow_is_manual_main_only_and_explicitly_authorized(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("\n  push:", self.workflow)
        self.assertNotIn("\n  pull_request:", self.workflow)
        self.assertIn("github.ref == 'refs/heads/main'", self.workflow)
        self.assertIn("inputs.confirm == 'FULL_E2E'", self.workflow)

    def test_workflow_targets_exact_rtx5090_runner_without_hardware_mutation(self) -> None:
        self.assertIn("runs-on: [self-hosted, Linux, X64, rtx5090]", self.workflow)
        lowered = self.workflow.lower()
        self.assertNotIn("ollama pull", lowered)
        self.assertNotIn("apt install", lowered)
        self.assertNotIn("nvidia-driver", lowered)
        self.assertNotIn("setup_ai_stack_ubuntu2404.sh", self.workflow)

    def test_exact_source_is_checked_out_and_verified(self) -> None:
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn('installed="$(git rev-parse HEAD)"', self.workflow)
        self.assertIn('test "$installed" = "$TARGET_SHA"', self.workflow)

    def test_existing_e2e_acceptance_is_reused_without_auto_update(self) -> None:
        self.assertIn("bash scripts/run_e2e_acceptance.sh", self.workflow)
        self.assertIn("THREE_AGENT_E2E_SKIP_UPDATE=1", self.workflow)
        self.assertIn("THREE_AGENT_REQUIRED_RTX5090_COUNT=2", self.workflow)
        self.assertIn('THREE_AGENT_ROOT="$GITHUB_WORKSPACE"', self.workflow)

    def test_only_sanitized_receipt_is_uploaded(self) -> None:
        self.assertIn("workspace-full-e2e-receipt.json", self.workflow)
        self.assertIn('"raw_evidence_uploaded": False', self.workflow)
        self.assertIn('"raw_stdout_uploaded": False', self.workflow)
        self.assertIn('"raw_stderr_uploaded": False', self.workflow)
        self.assertNotIn("data/acceptance/**", self.workflow)
        self.assertNotIn("full-e2e.stdout\n          ", self.workflow)
        self.assertNotIn("full-e2e.stderr\n          ", self.workflow)

    def test_pass_requires_fresh_local_evidence_hashes(self) -> None:
        for name in (
            "system.json",
            "workflow-result.json",
            "workflow-manifest.json",
            "research-handoff.json",
            "presentation.json",
            "daily-report.json",
        ):
            self.assertIn(name, self.workflow)
        self.assertIn('if result == "PASS" and set(hashes) != set(required):', self.workflow)
        self.assertIn('"schema": "workspace-e2e/physical-acceptance-v1"', self.workflow)


if __name__ == "__main__":
    unittest.main()
