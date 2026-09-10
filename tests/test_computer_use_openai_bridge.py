import unittest

from three_agent.computer_use import ComputerObservation
from three_agent.computer_use_openai_bridge import (
    OpenAIComputerBridgeError,
    build_openai_computer_call_output,
    map_openai_computer_error,
    translate_openai_computer_call,
)

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64


def observation(*, screenshot=H3):
    return ComputerObservation(
        session_id="session:openai",
        task_id="task:openai",
        state_id="state:openai",
        state_sha256=H1,
        surface="browser",
        active_target_ref="browser:profile:isolated/tab:tab1",
        captured_at="2026-09-10T00:00:00Z",
        structured_observation={"title": "Observed"},
        screenshot_sha256=screenshot,
    ).validate()


def translate(payload):
    return translate_openai_computer_call(
        payload,
        session_id="session:openai",
        task_id="task:openai",
        plan_fingerprint=H1,
        node_id="node:openai",
        browser_resource_ref="browser:profile:isolated/tab:tab1",
        state_precondition_sha256=H2,
        idempotency_key=H3,
    )


class OpenAIComputerBridgeTests(unittest.TestCase):
    def test_screenshot_call_translates_to_read_only_canonical_observation_action(self):
        proposal = translate(
            {
                "type": "computer_call",
                "id": "item_123",
                "call_id": "call_123",
                "action": {"type": "screenshot"},
                "pending_safety_checks": [],
            }
        )
        action = proposal.canonical_action
        self.assertEqual(action.provider_ref, "openai:call_123")
        self.assertEqual(action.operation, "browser.dom.observe")
        self.assertEqual(action.effect, "read")
        self.assertEqual(action.risk_class, "R0_OBSERVE")
        self.assertFalse(action.requires_writer)

    def test_provider_mutating_action_fails_closed_without_semantic_target_mapping(self):
        for provider_action in (
            {"type": "click", "x": 10, "y": 20, "button": "left"},
            {"type": "type", "text": "secret"},
            {"type": "scroll", "x": 10, "y": 20, "scroll_x": 0, "scroll_y": 300},
            {"type": "drag", "path": [{"x": 1, "y": 2}]},
        ):
            with self.subTest(provider_action=provider_action["type"]):
                with self.assertRaisesRegex(
                    OpenAIComputerBridgeError,
                    "OPENAI_COMPUTER_ACTION_REQUIRES_REVIEWED_SEMANTIC_TARGET",
                ):
                    translate(
                        {
                            "type": "computer_call",
                            "call_id": "call_mutating",
                            "action": provider_action,
                        }
                    )

    def test_provider_specific_fields_cannot_expand_screenshot_action(self):
        with self.assertRaisesRegex(
            OpenAIComputerBridgeError,
            "OPENAI_SCREENSHOT_ACTION_FIELD_NOT_ALLOWED",
        ):
            translate(
                {
                    "type": "computer_call",
                    "call_id": "call_extra",
                    "action": {"type": "screenshot", "grant_admin": True},
                }
            )

    def test_pending_safety_checks_are_metadata_not_authority(self):
        proposal = translate(
            {
                "type": "computer_call",
                "call_id": "call_safe",
                "action": {"type": "screenshot"},
                "pending_safety_checks": [
                    {"id": "check_1", "code": "confirm", "message": "Confirm"},
                    {"id": "check_1", "code": "confirm", "message": "Duplicate"},
                    {"id": "check_2", "code": "other", "message": "Other"},
                ],
            }
        )
        self.assertEqual(proposal.pending_safety_check_ids, ("check_1", "check_2"))
        self.assertEqual(proposal.canonical_action.operation, "browser.dom.observe")

    def test_provider_output_requires_retained_screenshot_and_exact_digest(self):
        with self.assertRaisesRegex(
            OpenAIComputerBridgeError,
            "OPENAI_SCREENSHOT_OUTPUT_NOT_RETAINED",
        ):
            build_openai_computer_call_output(
                call_id="call_123",
                observation=observation(screenshot=None),
                screenshot_file_id="file_123",
                screenshot_sha256=H3,
            )
        with self.assertRaisesRegex(
            OpenAIComputerBridgeError,
            "OPENAI_SCREENSHOT_OUTPUT_DIGEST_MISMATCH",
        ):
            build_openai_computer_call_output(
                call_id="call_123",
                observation=observation(),
                screenshot_file_id="file_123",
                screenshot_sha256=H2,
            )

    def test_provider_output_uses_only_file_id_after_retention(self):
        output = build_openai_computer_call_output(
            call_id="call_123",
            observation=observation(),
            screenshot_file_id="file_123",
            screenshot_sha256=H3,
        )
        self.assertEqual(
            output.canonical_provider_dict(),
            {
                "type": "computer_call_output",
                "call_id": "call_123",
                "output": {"type": "computer_screenshot", "file_id": "file_123"},
            },
        )

    def test_provider_errors_map_to_bounded_internal_classes(self):
        self.assertEqual(map_openai_computer_error(status=504), "OPENAI_COMPUTER_TIMEOUT")
        self.assertEqual(map_openai_computer_error(status=403), "OPENAI_COMPUTER_AUTH_DENIED")
        self.assertEqual(map_openai_computer_error(status=429), "OPENAI_COMPUTER_RATE_LIMITED")
        self.assertEqual(map_openai_computer_error(status=503), "OPENAI_COMPUTER_PROVIDER_UNAVAILABLE")
        self.assertEqual(map_openai_computer_error(status=400, error="bad request"), "OPENAI_COMPUTER_PROVIDER_FAILED")


if __name__ == "__main__":
    unittest.main()
