from __future__ import annotations

import inspect
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
        source = inspect.getsource(SecurityMonitoringHTTPHandler._security_pcap_approve)
        self.assertIn('payload.pop("confirmation", "")', source)
        self.assertIn("PCAP_APPROVAL_CONFIRMATION_REQUIRED", source)
        self.assertNotIn("execute_capture_approval", source)


if __name__ == "__main__":
    unittest.main()
