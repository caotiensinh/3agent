from __future__ import annotations

import unittest

from three_agent.computer_use import (
    ComputerActionRequest,
    ComputerObservation,
    ComputerUseError,
    derive_action_policy,
    require_fresh_observation,
    select_execution_route,
)

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64
NOW = "2026-09-10T00:00:00Z"


def action(**overrides):
    values = {
        "session_id": "computer-session:1",
        "action_id": "computer-action:1",
        "task_id": "task:1",
        "plan_fingerprint": H1,
        "node_id": "node:1",
        "provider_ref": "provider:local",
        "operation": "browser.interact",
        "effect": "write",
        "resource_kind": "browser_element",
        "resource_ref": "profile:isolated/tab:12/ref:button-save",
        "arguments": {"button": "left"},
        "state_precondition_sha256": H2,
        "expected_postcondition": "save indicator is visible",
        "risk_class": "R2_STATE_CHANGE",
        "requires_writer": True,
        "idempotency_key": H3,
    }
    values.update(overrides)
    return ComputerActionRequest(**values)


def observation(**overrides):
    values = {
        "session_id": "computer-session:1",
        "task_id": "task:1",
        "state_id": "state:1",
        "state_sha256": H2,
        "surface": "browser",
        "active_target_ref": "profile:isolated/tab:12",
        "captured_at": NOW,
        "structured_observation": {"role": "button", "name": "Save"},
        "screenshot_sha256": None,
    }
    values.update(overrides)
    return ComputerObservation(**values)


class ComputerUseContractTests(unittest.TestCase):
    def test_action_contract_is_deterministic(self):
        first = action()
        second = action(arguments={"button": "left"})
        self.assertEqual(first.canonical_dict(), second.canonical_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_unknown_operation_fails_closed(self):
        with self.assertRaisesRegex(ComputerUseError, "UNKNOWN_COMPUTER_OPERATION"):
            action(operation="computer.execute.anything").validate()

    def test_operation_cannot_lie_about_effect(self):
        with self.assertRaisesRegex(ComputerUseError, "COMPUTER_ACTION_EFFECT_MISMATCH"):
            action(effect="read").validate()

    def test_operation_cannot_lie_about_risk(self):
        with self.assertRaisesRegex(ComputerUseError, "COMPUTER_ACTION_RISK_MISMATCH"):
            action(risk_class="R0_OBSERVE").validate()

    def test_state_changing_operation_requires_writer(self):
        with self.assertRaisesRegex(
            ComputerUseError,
            "COMPUTER_ACTION_WRITER_REQUIREMENT_MISMATCH",
        ):
            action(requires_writer=False).validate()

    def test_resource_ref_rejects_raw_url(self):
        with self.assertRaisesRegex(ComputerUseError, "INVALID_RESOURCE_REF"):
            action(resource_ref="https://example.com/save").validate()

    def test_observation_requires_normalized_utc_timestamp(self):
        with self.assertRaisesRegex(
            ComputerUseError,
            "CAPTURED_AT_MUST_BE_NORMALIZED_UTC",
        ):
            observation(captured_at="2026-09-10T09:00:00+09:00").validate()

    def test_fresh_observation_matches_action_precondition(self):
        require_fresh_observation(action(), observation())

    def test_stale_observation_is_rejected(self):
        with self.assertRaisesRegex(ComputerUseError, "COMPUTER_ACTION_STATE_STALE"):
            require_fresh_observation(action(), observation(state_sha256=H1))

    def test_cross_session_action_is_rejected(self):
        with self.assertRaisesRegex(ComputerUseError, "COMPUTER_ACTION_SESSION_STALE"):
            require_fresh_observation(
                action(),
                observation(session_id="computer-session:2"),
            )

    def test_route_prefers_api_over_model_requested_pixels(self):
        decision = select_execution_route(
            available_routes=("vision_pointer", "api", "dom"),
            authorized_routes=("api", "dom", "vision_pointer"),
            provider_preference="vision_pointer",
        )
        self.assertEqual(decision.route, "api")
        self.assertEqual(decision.reason_code, "SAFEST_AUTHORIZED_ROUTE_SELECTED")

    def test_route_respects_authority_before_availability(self):
        decision = select_execution_route(
            available_routes=("api", "dom", "accessibility"),
            authorized_routes=("accessibility",),
        )
        self.assertEqual(decision.route, "accessibility")

    def test_no_authorized_route_fails_closed(self):
        with self.assertRaisesRegex(
            ComputerUseError,
            "NO_AUTHORIZED_COMPUTER_EXECUTION_ROUTE",
        ):
            select_execution_route(
                available_routes=("dom",),
                authorized_routes=("api",),
            )

    def test_derived_policy_is_deterministic(self):
        self.assertEqual(
            derive_action_policy("browser.navigate"),
            {
                "effect": "network_read",
                "risk_class": "R1_REVERSIBLE_INTERACTION",
                "requires_writer": False,
            },
        )
        self.assertEqual(
            derive_action_policy("computer.keyboard.interact"),
            {
                "effect": "write",
                "risk_class": "R2_STATE_CHANGE",
                "requires_writer": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
