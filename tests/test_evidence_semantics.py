from __future__ import annotations

import unittest

from three_agent.diagnostics.backup_status_tools import BACKUP_STATUS_TOOL_ID
from three_agent.diagnostics.cloud_files_tools import CLOUD_FILES_STATUS_TOOL_ID
from three_agent.diagnostics.evidence_semantics import (
    WAVE1_EVIDENCE_DESCRIPTORS,
    evidence_semantic_descriptor,
)
from three_agent.diagnostics.identity_account_state_tools import IDENTITY_ACCOUNT_STATE_TOOL_ID
from three_agent.diagnostics.mail_exchange_tools import MAIL_EXCHANGE_STATUS_TOOL_ID
from three_agent.diagnostics.voip_tools import VOIP_CLIENT_STATE_TOOL_ID


class EvidenceSemanticsTests(unittest.TestCase):
    def test_wave1_descriptors_cover_every_merged_evidence_primitive(self) -> None:
        expected = {
            CLOUD_FILES_STATUS_TOOL_ID,
            MAIL_EXCHANGE_STATUS_TOOL_ID,
            VOIP_CLIENT_STATE_TOOL_ID,
            IDENTITY_ACCOUNT_STATE_TOOL_ID,
            BACKUP_STATUS_TOOL_ID,
        }
        self.assertEqual({item.tool_id for item in WAVE1_EVIDENCE_DESCRIPTORS}, expected)

    def test_wave1_descriptors_grant_no_route_capability_or_execution_authority(self) -> None:
        for descriptor in WAVE1_EVIDENCE_DESCRIPTORS:
            self.assertEqual(descriptor.satisfied_capability_tags, (), descriptor.tool_id)
            self.assertTrue(descriptor.local_only, descriptor.tool_id)
            self.assertFalse(descriptor.execution_enabled, descriptor.tool_id)
            self.assertEqual(descriptor.selection_authority, "none", descriptor.tool_id)
            self.assertIn("root_cause", descriptor.prohibited_claims, descriptor.tool_id)

    def test_semantic_lookup_is_exact_and_unknown_ids_fail_closed(self) -> None:
        descriptor = evidence_semantic_descriptor(IDENTITY_ACCOUNT_STATE_TOOL_ID)
        self.assertEqual(descriptor.evidence_kind, "local_identity_account_state")
        self.assertIn("directory_health", descriptor.prohibited_claims)
        self.assertEqual(descriptor.satisfied_capability_tags, ())

        with self.assertRaises(KeyError):
            evidence_semantic_descriptor("identity.account_state")

    def test_sensitive_remote_claims_remain_explicitly_prohibited(self) -> None:
        self.assertIn(
            "backup_success",
            evidence_semantic_descriptor(BACKUP_STATUS_TOOL_ID).prohibited_claims,
        )
        self.assertIn(
            "sync_success",
            evidence_semantic_descriptor(CLOUD_FILES_STATUS_TOOL_ID).prohibited_claims,
        )
        self.assertIn(
            "remote_exchange_health",
            evidence_semantic_descriptor(MAIL_EXCHANGE_STATUS_TOOL_ID).prohibited_claims,
        )
        self.assertIn(
            "sip_registration",
            evidence_semantic_descriptor(VOIP_CLIENT_STATE_TOOL_ID).prohibited_claims,
        )


if __name__ == "__main__":
    unittest.main()
