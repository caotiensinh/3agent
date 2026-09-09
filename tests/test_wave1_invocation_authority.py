from __future__ import annotations

import unittest
from unittest.mock import patch

from three_agent.capability_authority import CapabilityAuthorityDenied, TaskCapabilityAuthority
from three_agent.capability_invocation_adapter import (
    CapabilityInvocationAdapterError,
    CapabilityInvocationRequest,
    current_runtime_invocation_identity,
    invoke_runtime_tool,
)
from three_agent.diagnostics.backup_status_tools import BACKUP_STATUS_TOOL_ID
from three_agent.diagnostics.cloud_files_tools import CLOUD_FILES_STATUS_TOOL_ID
from three_agent.diagnostics.identity_account_state_tools import IDENTITY_ACCOUNT_STATE_TOOL_ID
from three_agent.diagnostics.mail_exchange_tools import MAIL_EXCHANGE_STATUS_TOOL_ID
from three_agent.diagnostics.voip_tools import VOIP_CLIENT_STATE_TOOL_ID


WAVE1_CASES = (
    (CLOUD_FILES_STATUS_TOOL_ID, "read_cloud_files_client_state"),
    (MAIL_EXCHANGE_STATUS_TOOL_ID, "read_mail_exchange_client_state"),
    (VOIP_CLIENT_STATE_TOOL_ID, "read_voip_client_state"),
    (IDENTITY_ACCOUNT_STATE_TOOL_ID, "read_identity_account_state"),
    (BACKUP_STATUS_TOOL_ID, "read_backup_local_state"),
)


def _authority(tool_id: str, *, allowed: bool = True) -> TaskCapabilityAuthority:
    return TaskCapabilityAuthority._build(
        task_id="TASK-WAVE1-INVOKE",
        sensitivity="internal",
        allowed_sources=(),
        allowed_tools=(tool_id,) if allowed else (),
        write_scope="none",
        network_scope="deny",
    )


def _request(tool_id: str, parameters: dict[str, object] | None = None) -> CapabilityInvocationRequest:
    snapshot_fingerprint, descriptor_fingerprint = current_runtime_invocation_identity(tool_id)
    return CapabilityInvocationRequest.create(
        task_id="TASK-WAVE1-INVOKE",
        tool_id=tool_id,
        snapshot_fingerprint=snapshot_fingerprint,
        descriptor_fingerprint=descriptor_fingerprint,
        parameters=parameters,
    )


class Wave1InvocationAuthorityTests(unittest.TestCase):
    def test_each_wave1_collector_crosses_canonical_adapter_with_exact_authority(self) -> None:
        for tool_id, handler_name in WAVE1_CASES:
            with self.subTest(tool_id=tool_id):
                request = _request(tool_id, {"timeout": 2.0})
                authority = _authority(tool_id)
                fake_result = {
                    "tool_id": tool_id,
                    "scope": "local_evidence_only",
                    "interpretation": "evidence_only",
                }
                with patch(
                    f"three_agent.capability_invocation_adapter.{handler_name}",
                    return_value=fake_result,
                ) as handler:
                    result = invoke_runtime_tool(request, authority=authority)

                handler.assert_called_once_with(authority=authority, timeout=2.0)
                self.assertEqual(result.tool_id, tool_id)
                self.assertTrue(result.decision_receipt.allowed)
                self.assertEqual(result.decision_receipt.effect, "read")
                self.assertFalse(result.decision_receipt.automatic_action_allowed)
                self.assertIn('"interpretation":"evidence_only"', result.bounded_payload.text)

    def test_wave1_invocation_requires_explicit_task_capability(self) -> None:
        for tool_id, handler_name in WAVE1_CASES:
            with self.subTest(tool_id=tool_id):
                request = _request(tool_id)
                with patch(f"three_agent.capability_invocation_adapter.{handler_name}") as handler:
                    with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
                        invoke_runtime_tool(request, authority=_authority(tool_id, allowed=False))
                    handler.assert_not_called()

    def test_wave1_platform_spoof_is_rejected_before_handler(self) -> None:
        for tool_id, handler_name in WAVE1_CASES:
            with self.subTest(tool_id=tool_id):
                request = _request(tool_id, {"platform_name": "windows"})
                with patch(f"three_agent.capability_invocation_adapter.{handler_name}") as handler:
                    with self.assertRaisesRegex(
                        CapabilityInvocationAdapterError,
                        "UNSUPPORTED_INVOCATION_PARAMETERS:platform_name",
                    ):
                        invoke_runtime_tool(request, authority=_authority(tool_id))
                    handler.assert_not_called()

    def test_wave1_timeout_is_bounded_before_handler(self) -> None:
        for tool_id, handler_name in WAVE1_CASES:
            with self.subTest(tool_id=tool_id):
                request = _request(tool_id, {"timeout": 31.0})
                with patch(f"three_agent.capability_invocation_adapter.{handler_name}") as handler:
                    with self.assertRaisesRegex(CapabilityInvocationAdapterError, "INVALID_TIMEOUT"):
                        invoke_runtime_tool(request, authority=_authority(tool_id))
                    handler.assert_not_called()


if __name__ == "__main__":
    unittest.main()
