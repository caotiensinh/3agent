from __future__ import annotations

import unittest

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.diagnostics.backup_status_tools import BACKUP_STATUS_TOOL_ID
from three_agent.diagnostics.cloud_files_tools import CLOUD_FILES_STATUS_TOOL_ID
from three_agent.diagnostics.identity_account_state_tools import IDENTITY_ACCOUNT_STATE_TOOL_ID
from three_agent.diagnostics.mail_exchange_tools import MAIL_EXCHANGE_STATUS_TOOL_ID
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
)
from three_agent.diagnostics.voip_tools import VOIP_CLIENT_STATE_TOOL_ID
from three_agent.task_contract import DIAGNOSTIC_STAGED_LOCAL_READ_TOOLS


WAVE1_TOOL_IDS = (
    CLOUD_FILES_STATUS_TOOL_ID,
    MAIL_EXCHANGE_STATUS_TOOL_ID,
    VOIP_CLIENT_STATE_TOOL_ID,
    IDENTITY_ACCOUNT_STATE_TOOL_ID,
    BACKUP_STATUS_TOOL_ID,
)
WAVE1_EXACT_RESOURCES = {
    CLOUD_FILES_STATUS_TOOL_ID: ("cloud_files_client_state", "local:cloud-files:client-state"),
    MAIL_EXCHANGE_STATUS_TOOL_ID: ("mail_exchange_client_state", "local:mail-exchange:client-state"),
    VOIP_CLIENT_STATE_TOOL_ID: ("voip_client_state", "local:voip:client-state"),
    IDENTITY_ACCOUNT_STATE_TOOL_ID: ("identity_account_state", "local:identity:account-state"),
    BACKUP_STATUS_TOOL_ID: ("backup_local_state", "local:backup:state"),
}


class Wave1EvidenceRegistryConvergenceTests(unittest.TestCase):
    def test_wave1_collectors_are_registered_as_local_read_only_runtime_evidence(self) -> None:
        registry = runtime_micro_tool_registry()
        for tool_id in WAVE1_TOOL_IDS:
            metadata = registry.get(tool_id)
            self.assertIs(metadata.validate(), metadata, tool_id)
            self.assertEqual(metadata.network_access, "none", tool_id)
            self.assertEqual(metadata.effect, "read", tool_id)
            self.assertFalse(metadata.requires_admin, tool_id)

    def test_wave1_registry_convergence_does_not_create_false_route_bindings(self) -> None:
        binding_by_tag = {
            binding.capability_tag: binding.tool_ids
            for binding in default_runtime_capability_bindings()
        }
        broad_tags = {
            "identity.account_state",
            "backup.status",
            "mail.client",
            "mail.account",
            "cloud.sync",
            "cloud.permissions",
            "voip.registration",
        }
        for capability_tag in broad_tags:
            self.assertNotIn(capability_tag, binding_by_tag)

        bound_tool_ids = {
            tool_id
            for tool_ids in binding_by_tag.values()
            for tool_id in tool_ids
        }
        self.assertTrue(set(WAVE1_TOOL_IDS).isdisjoint(bound_tool_ids))

    def test_wave1_route_vocabulary_stays_staged_but_exact_local_invocation_is_authorized(self) -> None:
        self.assertEqual(set(WAVE1_TOOL_IDS), DIAGNOSTIC_STAGED_LOCAL_READ_TOOLS)
        for tool_id in WAVE1_TOOL_IDS:
            with self.subTest(tool_id=tool_id):
                authority = TaskCapabilityAuthority._build(
                    task_id="TASK-WAVE1-INVOKE",
                    sensitivity="internal",
                    allowed_sources=(),
                    allowed_tools=(tool_id,),
                    write_scope="none",
                    network_scope="deny",
                )
                resource_kind, resource_ref = WAVE1_EXACT_RESOURCES[tool_id]
                decision = authority.authorize(
                    tool_id,
                    resource_kind=resource_kind,
                    resource_ref=resource_ref,
                    effect="read",
                )
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason_code, "CAPABILITY_AUTHORIZED")

                wrong = authority.authorize(
                    tool_id,
                    resource_kind=resource_kind,
                    resource_ref="local:staged:evidence",
                    effect="read",
                )
                self.assertFalse(wrong.allowed)
                self.assertEqual(wrong.reason_code, "RESOURCE_REF_NOT_AUTHORIZED")

    def test_wave1_tool_ids_remain_distinct_evidence_primitives(self) -> None:
        self.assertEqual(len(WAVE1_TOOL_IDS), len(set(WAVE1_TOOL_IDS)))
        self.assertNotEqual(CLOUD_FILES_STATUS_TOOL_ID, MAIL_EXCHANGE_STATUS_TOOL_ID)
        self.assertNotEqual(IDENTITY_ACCOUNT_STATE_TOOL_ID, BACKUP_STATUS_TOOL_ID)


if __name__ == "__main__":
    unittest.main()
