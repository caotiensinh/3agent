import json
import unittest

from three_agent.computer_use import ComputerObservation
from three_agent.computer_use_anthropic_bridge import (
    AnthropicComputerBridgeError,
    build_anthropic_computer_tool_result,
    map_anthropic_computer_error,
    translate_anthropic_computer_tool_use,
)

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64


def observation(*, screenshot=H3):
    return ComputerObservation(
        session_id="session:anthropic",
        task_id="task:anthropic",
        state_id="state:anthropic",
        state_sha256=H1,
        surface="browser",
        active_target_ref="browser:profile:isolated/tab:tab1",
        captured_at="2026-09-10T00:00:00Z",
        structured_observation={"title": "Observed"},
        screenshot_sha256=screenshot,
    ).validate()


def translate(payload, *, allowed_tool_names=("computer",)):
    return translate_anthropic_computer_tool_use(
        payload,
        session_id="session:anthropic",
        task_id="task:anthropic",
        plan_fingerprint=H1,
        node_id="node:anthropic",
        browser_resource_ref="browser:profile:isolated/tab:tab1",
        state_precondition_sha256=H2,
        idempotency_key=H3,
        allowed_tool_names=allowed_tool_names,
    )


class AnthropicComputerBridgeTests(unittest.TestCase):
    def test_screenshot_tool_use_translates_to_read_only_canonical_observation_action(self):
        proposal = translate(
            {
                "type": "tool_use",
                "id": "toolu_123",
                "name": "computer",
                "input": {"action": "screenshot"},
            }
        )
        action = proposal.canonical_action
        self.assertEqual(proposal.tool_use_id, "toolu_123")
        self.assertEqual(proposal.tool_name, "computer")
        self.assertEqual(action.provider_ref, "anthropic:toolu_123")
        self.assertEqual(action.operation, "browser.dom.observe")
        self.assertEqual(action.effect, "read")
        self.assertEqual(action.risk_class, "R0_OBSERVE")
        self.assertFalse(action.requires_writer)

    def test_mutating_computer_actions_fail_closed_without_semantic_target_mapping(self):
        actions = (
            {"action": "left_click", "coordinate": [10, 20]},
            {"action": "type", "text": "secret"},
            {"action": "key", "text": "CTRL+L"},
            {"action": "mouse_move", "coordinate": [10, 20]},
            {"action": "scroll", "coordinate": [10, 20], "scroll_direction": "down", "scroll_amount": 3},
        )
        for provider_input in actions:
            with self.subTest(action=provider_input["action"]):
                with self.assertRaisesRegex(
                    AnthropicComputerBridgeError,
                    "ANTHROPIC_COMPUTER_ACTION_REQUIRES_REVIEWED_SEMANTIC_TARGET",
                ):
                    translate(
                        {
                            "type": "tool_use",
                            "id": "toolu_mutating",
                            "name": "computer",
                            "input": provider_input,
                        }
                    )

    def test_provider_specific_fields_cannot_expand_screenshot_action(self):
        with self.assertRaisesRegex(
            AnthropicComputerBridgeError,
            "ANTHROPIC_SCREENSHOT_ACTION_FIELD_NOT_ALLOWED",
        ):
            translate(
                {
                    "type": "tool_use",
                    "id": "toolu_extra",
                    "name": "computer",
                    "input": {"action": "screenshot", "grant_admin": True},
                }
            )

    def test_wrong_tool_name_is_rejected_by_trusted_allowlist(self):
        with self.assertRaisesRegex(
            AnthropicComputerBridgeError,
            "ANTHROPIC_COMPUTER_TOOL_NAME_NOT_ALLOWED",
        ):
            translate(
                {
                    "type": "tool_use",
                    "id": "toolu_shell",
                    "name": "bash",
                    "input": {"action": "screenshot"},
                }
            )

    def test_tool_name_allowlist_is_configuration_not_provider_authority(self):
        proposal = translate(
            {
                "type": "tool_use",
                "id": "toolu_custom",
                "name": "workspace_computer",
                "input": {"action": "screenshot"},
            },
            allowed_tool_names=("workspace_computer",),
        )
        self.assertEqual(proposal.tool_name, "workspace_computer")
        self.assertEqual(proposal.canonical_action.operation, "browser.dom.observe")

    def test_tool_result_requires_retained_screenshot_and_exact_digest(self):
        with self.assertRaisesRegex(
            AnthropicComputerBridgeError,
            "ANTHROPIC_SCREENSHOT_OUTPUT_NOT_RETAINED",
        ):
            build_anthropic_computer_tool_result(
                tool_use_id="toolu_123",
                observation=observation(screenshot=None),
                screenshot_sha256=H3,
            )
        with self.assertRaisesRegex(
            AnthropicComputerBridgeError,
            "ANTHROPIC_SCREENSHOT_OUTPUT_DIGEST_MISMATCH",
        ):
            build_anthropic_computer_tool_result(
                tool_use_id="toolu_123",
                observation=observation(),
                screenshot_sha256=H2,
            )

    def test_tool_result_is_metadata_only_and_bound_to_tool_use_id(self):
        result = build_anthropic_computer_tool_result(
            tool_use_id="toolu_123",
            observation=observation(),
            screenshot_sha256=H3,
        )
        provider = result.canonical_provider_dict()
        self.assertEqual(provider["type"], "tool_result")
        self.assertEqual(provider["tool_use_id"], "toolu_123")
        self.assertFalse(provider["is_error"])
        self.assertEqual(len(provider["content"]), 1)
        self.assertEqual(provider["content"][0]["type"], "text")
        retained = json.loads(provider["content"][0]["text"])
        self.assertEqual(retained["retention"], "workspace_retained_metadata_only")
        self.assertEqual(retained["screenshot_sha256"], H3)
        self.assertEqual(retained["state_sha256"], H1)
        serialized = str(provider)
        self.assertNotIn("base64", serialized)
        self.assertNotIn("data:image", serialized)
        self.assertNotIn("file://", serialized)

    def test_provider_errors_map_to_bounded_internal_classes(self):
        self.assertEqual(map_anthropic_computer_error(status=504), "ANTHROPIC_COMPUTER_TIMEOUT")
        self.assertEqual(map_anthropic_computer_error(status=403), "ANTHROPIC_COMPUTER_AUTH_DENIED")
        self.assertEqual(map_anthropic_computer_error(status=429), "ANTHROPIC_COMPUTER_RATE_LIMITED")
        self.assertEqual(map_anthropic_computer_error(status=503), "ANTHROPIC_COMPUTER_PROVIDER_UNAVAILABLE")
        self.assertEqual(
            map_anthropic_computer_error(status=400, error="bad request"),
            "ANTHROPIC_COMPUTER_PROVIDER_FAILED",
        )


if __name__ == "__main__":
    unittest.main()
