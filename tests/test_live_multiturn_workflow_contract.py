from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LiveMultiturnWorkflowContractTests(unittest.TestCase):
    def test_self_hosted_live_workflow_is_main_only_and_not_pr_triggered(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("runs-on: [self-hosted, Linux, X64]", text)
        self.assertNotIn("runs-on: [self-hosted, Linux, X64, rtx5090]", text)
        self.assertIn("group: workspace-live-chat-multiturn-main-v2", text)
        self.assertNotIn("group: workspace-live-chat-multiturn-main\n", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("branches: [main]", text)
        self.assertNotIn("pull_request:", text)

    def test_gpu_inventory_is_verified_inside_the_trusted_job(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("command -v nvidia-smi", text)
        self.assertIn("grep -c 'RTX 5090'", text)
        self.assertIn('test "$(nvidia-smi --query-gpu=name --format=csv,noheader | grep -c \'RTX 5090\')" -ge 2', text)

    def test_live_workflow_is_read_only_to_host_runtime(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('$RUNNER_TEMP/workspace-multiturn-', text)
        self.assertIn("workspace-chat-multiturn-acceptance", text)
        self.assertIn("persist-credentials: false", text)
        for forbidden in (
            "setup_ai_stack_ubuntu2404.sh",
            "apt-get",
            "apt install",
            "systemctl",
            "service restart",
            "nvidia-driver",
            "update_workspace_linux.sh",
            "$HOME/3agent/.venv",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_report_is_sanitized_and_artifact_is_bounded(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("raw prompts/answers: `not persisted`", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("retention-days: 14", text)

    def test_package_exposes_new_cli_without_replacing_chat_gateway(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.18.0"', text)
        self.assertIn(
            'workspace-chat-multiturn-acceptance = "three_agent.chat_multiturn_acceptance:main"',
            text,
        )
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v16:main"', text)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v16:main"', text)


if __name__ == "__main__":
    unittest.main()
