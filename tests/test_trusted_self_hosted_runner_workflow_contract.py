from pathlib import Path
import unittest


class TrustedSelfHostedRunnerWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = Path(".github/workflows/trusted-self-hosted-r9-ci.yml").read_text(encoding="utf-8")

    def test_workflow_never_runs_on_pull_request(self) -> None:
        self.assertNotIn("pull_request:", self.workflow)
        self.assertIn("push:\n    branches: [main]", self.workflow)
        self.assertIn("workflow_dispatch:", self.workflow)

    def test_workflow_targets_exact_r9_runner_labels(self) -> None:
        self.assertIn("runs-on: [self-hosted, Linux, X64, r9]", self.workflow)

    def test_checkout_is_exact_and_credentials_are_not_persisted(self) -> None:
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)

    def test_exact_source_and_idempotency_are_verified(self) -> None:
        self.assertIn("THREE_AGENT_REPO_REF: ${{ github.sha }}", self.workflow)
        self.assertIn('git -C "$THREE_AGENT_INSTALL_DIR" rev-parse HEAD', self.workflow)
        self.assertIn('test "$before" = "$after"', self.workflow)

    def test_evidence_receipt_captures_required_runner_fields(self) -> None:
        for required in (
            '"workflow": os.environ["GITHUB_WORKFLOW"]',
            '"run_id": os.environ["GITHUB_RUN_ID"]',
            '"job": os.environ["GITHUB_JOB"]',
            '"target_sha": os.environ["TARGET_SHA"]',
            '"runner_name": os.environ.get("RUNNER_NAME", "unknown")',
            '"runner_os": os.environ.get("RUNNER_OS", "unknown")',
            '"runner_arch": os.environ.get("RUNNER_ARCH", "unknown")',
            '"result": "PASS"',
        ):
            self.assertIn(required, self.workflow)


if __name__ == "__main__":
    unittest.main()
