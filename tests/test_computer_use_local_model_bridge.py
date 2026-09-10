import unittest

from three_agent.computer_use_local_model_bridge import (
    LOCAL_MODEL_PROPOSAL_SCHEMA,
    LocalModelComputerBridgeError,
    translate_local_model_proposal,
)

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


def translate(payload):
    return translate_local_model_proposal(
        payload,
        model_ref="qwen3.6-35b",
        session_id="session:local",
        task_id="task:local",
        plan_fingerprint=H1,
        node_id="node:local",
        state_precondition_sha256=H1,
        idempotency_key=H2,
    )


class LocalModelComputerBridgeTests(unittest.TestCase):
    def test_read_only_proposal_normalizes_to_canonical_action(self):
        proposal = translate(
            {
                "schema_version": LOCAL_MODEL_PROPOSAL_SCHEMA,
                "proposal_id": "proposal_1",
                "operation": "browser.dom.observe",
                "resource_kind": "browser_document",
                "resource_ref": "browser:profile:isolated/tab:tab1",
                "arguments": {"include_dom": True},
            }
        )
        action = proposal.canonical_action
        self.assertEqual(action.provider_ref, "local:qwen3.6-35b")
        self.assertEqual(action.effect, "read")
        self.assertEqual(action.risk_class, "R0_OBSERVE")
        self.assertFalse(action.requires_writer)

    def test_mutating_proposal_cannot_downgrade_effect_risk_or_writer(self):
        proposal = translate(
            {
                "schema_version": LOCAL_MODEL_PROPOSAL_SCHEMA,
                "proposal_id": "proposal_2",
                "operation": "browser.interact",
                "resource_kind": "browser_document",
                "resource_ref": "browser:profile:isolated/tab:tab1",
                "arguments": {"interaction": "click", "target_ref": "button:save"},
                "expected_postcondition": "save-complete",
            }
        )
        action = proposal.canonical_action
        self.assertEqual(action.effect, "write")
        self.assertEqual(action.risk_class, "R2_STATE_CHANGE")
        self.assertTrue(action.requires_writer)

    def test_provider_cannot_supply_authority_fields(self):
        for field, value in (
            ("effect", "read"),
            ("risk_class", "R0_OBSERVE"),
            ("requires_writer", False),
            ("task_id", "task:forged"),
            ("session_id", "session:forged"),
            ("authority", "allow-all"),
        ):
            payload = {
                "schema_version": LOCAL_MODEL_PROPOSAL_SCHEMA,
                "proposal_id": "proposal_extra",
                "operation": "browser.dom.observe",
                "resource_kind": "browser_document",
                "resource_ref": "browser:profile:isolated/tab:tab1",
                "arguments": {},
                field: value,
            }
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    LocalModelComputerBridgeError,
                    "LOCAL_MODEL_PROPOSAL_FIELD_NOT_ALLOWED",
                ):
                    translate(payload)

    def test_unknown_operation_fails_closed(self):
        with self.assertRaisesRegex(
            LocalModelComputerBridgeError,
            "LOCAL_MODEL_UNKNOWN_COMPUTER_OPERATION",
        ):
            translate(
                {
                    "schema_version": LOCAL_MODEL_PROPOSAL_SCHEMA,
                    "proposal_id": "proposal_unknown",
                    "operation": "system.exec.root",
                    "resource_kind": "system",
                    "resource_ref": "system:root",
                    "arguments": {},
                }
            )

    def test_malformed_and_noncanonical_json_fail_closed(self):
        with self.assertRaisesRegex(
            LocalModelComputerBridgeError,
            "LOCAL_MODEL_PROPOSAL_MUST_BE_OBJECT",
        ):
            translate_local_model_proposal(
                [],
                model_ref="qwen3.6-35b",
                session_id="session:local",
                task_id="task:local",
                plan_fingerprint=H1,
                node_id="node:local",
                state_precondition_sha256=H1,
                idempotency_key=H2,
            )

        with self.assertRaisesRegex(
            LocalModelComputerBridgeError,
            "LOCAL_MODEL_PROPOSAL_NOT_CANONICAL_JSON",
        ):
            translate(
                {
                    "schema_version": LOCAL_MODEL_PROPOSAL_SCHEMA,
                    "proposal_id": "proposal_nan",
                    "operation": "browser.dom.observe",
                    "resource_kind": "browser_document",
                    "resource_ref": "browser:profile:isolated/tab:tab1",
                    "arguments": {"confidence": float("nan")},
                }
            )

    def test_schema_version_is_strict(self):
        with self.assertRaisesRegex(
            LocalModelComputerBridgeError,
            "LOCAL_MODEL_PROPOSAL_SCHEMA_VERSION_MISMATCH",
        ):
            translate(
                {
                    "schema_version": "workspace-local-computer-proposal/v0",
                    "proposal_id": "proposal_old",
                    "operation": "browser.dom.observe",
                    "resource_kind": "browser_document",
                    "resource_ref": "browser:profile:isolated/tab:tab1",
                    "arguments": {},
                }
            )

    def test_oversize_payload_is_rejected(self):
        with self.assertRaisesRegex(
            LocalModelComputerBridgeError,
            "LOCAL_MODEL_PROPOSAL_BOUND_EXCEEDED",
        ):
            translate(
                {
                    "schema_version": LOCAL_MODEL_PROPOSAL_SCHEMA,
                    "proposal_id": "proposal_big",
                    "operation": "browser.dom.observe",
                    "resource_kind": "browser_document",
                    "resource_ref": "browser:profile:isolated/tab:tab1",
                    "arguments": {"blob": "x" * (20 * 1024)},
                }
            )


if __name__ == "__main__":
    unittest.main()
