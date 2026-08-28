import sys
import tempfile
import unittest
from pathlib import Path

from three_agent.config import GatewayConfig
from three_agent.gateways import ExecutionGateway


class GatewayTests(unittest.TestCase):
    def test_execution_gateway_allows_test_command_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "exec.jsonl"
            gateway = ExecutionGateway(GatewayConfig(True, True, log), test_mode_full_access=True)
            result = gateway.run("research", "TASK-X", [sys.executable, "-c", "print('ok')"])
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "ok")
            self.assertTrue(log.exists())

    def test_execution_gateway_denies_when_not_full_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "exec.jsonl"
            gateway = ExecutionGateway(GatewayConfig(True, True, log), test_mode_full_access=False)
            with self.assertRaises(PermissionError):
                gateway.run("research", None, [sys.executable, "-c", "print('no')"])


if __name__ == "__main__":
    unittest.main()
