from __future__ import annotations

import ast
import inspect
import textwrap
import unittest

from three_agent.chat_gateway import (
    PCAP_APPROVAL_CONFIRMATION,
    SecurityMonitoringHTTPHandler,
)
from three_agent.security_monitoring.incident_capture import CAPTURE_CONFIRMATION


class PcapApprovalConfirmationTests(unittest.TestCase):
    def test_approval_and_execution_use_distinct_literal_confirmations(self):
        self.assertEqual(PCAP_APPROVAL_CONFIRMATION, "APPROVE_PCAP")
        self.assertEqual(CAPTURE_CONFIRMATION, "AUTHORIZE_PCAP")
        self.assertNotEqual(PCAP_APPROVAL_CONFIRMATION, CAPTURE_CONFIRMATION)

        source = textwrap.dedent(
            inspect.getsource(SecurityMonitoringHTTPHandler._security_pcap_approve)
        )
        tree = ast.parse(source)

        confirmation_pop = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "pop"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "payload"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "confirmation"
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == ""
            for node in ast.walk(tree)
        )
        self.assertTrue(confirmation_pop)

        approval_check = any(
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == "confirmation"
            and any(isinstance(operator, ast.NotEq) for operator in node.ops)
            and any(
                isinstance(comparator, ast.Name)
                and comparator.id == "PCAP_APPROVAL_CONFIRMATION"
                for comparator in node.comparators
            )
            for node in ast.walk(tree)
        )
        self.assertTrue(approval_check)

        string_constants = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertIn("PCAP_APPROVAL_CONFIRMATION_REQUIRED", string_constants)

        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("execute_capture_approval", called_names)


if __name__ == "__main__":
    unittest.main()
