from pathlib import Path
import unittest


class SecurityReadonlyPilotWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = Path(".github/workflows/security-readonly-pilot.yml").read_text(encoding="utf-8")

    def test_workflow_is_manual_only_and_main_only(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("push:", self.workflow)
        self.assertNotIn("pull_request:", self.workflow)
        self.assertIn("if: github.ref == 'refs/heads/main'", self.workflow)

    def test_workflow_requires_literal_confirmation_without_embedding_input_in_shell(self) -> None:
        self.assertIn("PILOT_CONFIRMATION: ${{ inputs.confirmation }}", self.workflow)
        self.assertIn('test "$PILOT_CONFIRMATION" = "READ_ONLY_SECURITY_PILOT"', self.workflow)
        self.assertNotIn('test "${{ inputs.confirmation }}"', self.workflow)

    def test_workflow_uses_fixed_host_local_config_and_exact_installed_sha(self) -> None:
        self.assertIn('CONFIG_PATH="$HOME/.config/workspace/security_monitoring.pilot.json"', self.workflow)
        self.assertIn("THREE_AGENT_REPO_REF: ${{ github.sha }}", self.workflow)
        self.assertIn('--expected-sha "$TARGET_SHA"', self.workflow)
        self.assertIn('--installed-dir "$THREE_AGENT_INSTALL_DIR"', self.workflow)

    def test_workflow_installs_snmp_monitoring_extra_in_isolated_pilot_env(self) -> None:
        self.assertIn(
            '"$THREE_AGENT_INSTALL_DIR/.venv/bin/python" -m pip install -e "${THREE_AGENT_INSTALL_DIR}[monitoring-snmp]"',
            self.workflow,
        )

    def test_workflow_uploads_only_sanitized_receipt(self) -> None:
        self.assertIn("security-monitoring-readonly-pilot.json", self.workflow)
        self.assertNotIn("security_monitoring.pilot.json\n          ", self.workflow)
        self.assertNotIn("*.db", self.workflow)
        self.assertNotIn("*.log", self.workflow)

    def test_workflow_retains_read_only_boundaries(self) -> None:
        self.assertIn("run_security_readonly_pilot.py", self.workflow)
        self.assertNotIn("pcap", self.workflow.lower())
        self.assertNotIn("firewall", self.workflow.lower())
        self.assertNotIn("remediation", self.workflow.lower())


if __name__ == "__main__":
    unittest.main()
