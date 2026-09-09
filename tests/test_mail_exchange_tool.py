from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.mail_exchange_tools import (
    MAIL_EXCHANGE_STATUS_METADATA,
    MAIL_EXCHANGE_STATUS_TOOL_ID,
    build_mail_exchange_plan,
    read_mail_exchange_client_state,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class MailExchangeToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only(self) -> None:
        metadata = MAIL_EXCHANGE_STATUS_METADATA[0]
        self.assertEqual(metadata.id, MAIL_EXCHANGE_STATUS_TOOL_ID)
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.effect, "read")

    def test_windows_plan_has_no_remote_mail_action(self) -> None:
        plan = build_mail_exchange_plan(platform_name="Windows")
        self.assertIn("Get-Process", plan[4])
        self.assertNotIn("Send-MailMessage", plan[4])
        self.assertNotIn("Credential", plan[4])
        self.assertNotIn("Invoke-WebRequest", plan[4])

    def test_collection_is_evidence_only(self) -> None:
        authority = RecordingAuthority()
        completed = SimpleNamespace(returncode=0, stdout="OUTLOOK\n", stderr="")
        with patch("three_agent.diagnostics.mail_exchange_tools.subprocess.run", return_value=completed) as run:
            result = read_mail_exchange_client_state(authority=authority, platform_name="Linux")
        self.assertEqual(authority.calls, [(MAIL_EXCHANGE_STATUS_TOOL_ID, "mail_exchange_client_state", "local:mail-exchange:client-state", "read")])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(result["mailbox_content_read"])
        self.assertFalse(result["authentication_claimed"])
        self.assertFalse(result["remote_exchange_health_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")


if __name__ == "__main__":
    unittest.main()
