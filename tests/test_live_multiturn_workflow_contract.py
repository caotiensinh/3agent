from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LiveMultiturnWorkflowContractTests(unittest.TestCase):
    def test_self_hosted_live_workflow_is_main_only_and_not_pr_triggered(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("runs-on: [self-hosted, Linux, X64, workspace-benchmark]", text)
        self.assertNotIn("runs-on: [self-hosted, Linux, X64, rtx5090]", text)
        self.assertIn("group: workspace-live-chat-multiturn-main-v3", text)
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

    def test_acceptance_config_defaults_to_exact_checkout_not_runner_home(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("$GITHUB_WORKSPACE/config/workspace.secure.json", text)
        self.assertIn("CONFIG_OVERRIDE", text)
        self.assertNotIn("$HOME/3agent/config/workspace.secure.json", text)
        self.assertNotIn("cat $WORKSPACE_ACCEPTANCE_CONFIG_PATH", text)

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

    def test_failure_report_path_is_exported_before_live_command(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        export = 'echo "WORKSPACE_ACCEPTANCE_REPORT=$REPORT" >> "$GITHUB_ENV"'
        command = '"$WORKSPACE_ACCEPTANCE_VENV/bin/workspace-chat-multiturn-acceptance"'
        self.assertIn(export, text)
        self.assertIn(command, text)
        self.assertLess(text.index(export), text.index(command))
        self.assertIn("set +e", text)
        self.assertIn('exit "$rc"', text)

    def test_report_is_sanitized_and_artifact_is_bounded(self):
        text = (ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("raw prompts/answers: `not persisted`", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("if: always() && env.WORKSPACE_ACCEPTANCE_REPORT != ''", text)
        self.assertIn("retention-days: 14", text)

    def test_portable_gate_tracks_live_acceptance_contract_changes(self):
        text = (ROOT / ".github/workflows/portable-deploy-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(
            text.count("'.github/workflows/live-chat-multiturn-acceptance.yml'"),
            2,
        )
        self.assertGreaterEqual(
            text.count("'tests/test_live_multiturn_workflow_contract.py'"),
            2,
        )
        self.assertIn("workflow_dispatch:", text)

    def test_package_routes_live_acceptance_to_current_contract_service(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "1!0.0.2"', text)
        self.assertIn(
            'workspace-chat-multiturn-acceptance = "three_agent.chat_multiturn_acceptance_v2:main"',
            text,
        )
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v17:main"', text)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v17:main"', text)
        self.assertTrue((ROOT / "src/three_agent/chat_multiturn_acceptance_v2.py").is_file())
        v17 = (ROOT / "src/three_agent/chat_gateway_v17.py").read_text(encoding="utf-8")
        self.assertIn("ContractAwareProjectChatService", v17)
        self.assertIn("ContextAwareWorkflowV3HTTPHandler", v17)


if __name__ == "__main__":
    unittest.main()
