import base64
import json
import unittest
from unittest.mock import patch

from three_agent.computer_use_windows_observation import WindowsPowerShellObservationBackend


class WindowsPowerShellInvocationContractTests(unittest.TestCase):
    @staticmethod
    def _payload(*, screenshot=False):
        return {
            "window_id": "0xABC123",
            "process_id": 4242,
            "process_name": "notepad",
            "metadata": {
                "window_title": "Notepad",
                "session_id": 1,
                "responding": True,
                "uia_node_count": 1,
            },
            "accessibility": {
                "automation_id": "root",
                "control_type": "ControlType.Window",
                "name": "Notepad",
                "is_password": False,
                "children": [],
            },
            "screenshot_base64": base64.b64encode(b"png").decode("ascii") if screenshot else None,
            "captured_at": "2026-09-10T06:10:00Z",
        }

    def _capture_command(self, *, include_screenshot):
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(self._payload(screenshot=include_screenshot)),
                "stderr": "",
            },
        )()
        backend = WindowsPowerShellObservationBackend(powershell_executable="powershell.exe")
        with patch("three_agent.computer_use_windows_observation.os.name", "nt"):
            with patch(
                "three_agent.computer_use_windows_observation.subprocess.run",
                return_value=completed,
            ) as run:
                backend.capture_read_only(
                    include_screenshot=include_screenshot,
                    max_uia_nodes=32,
                    max_uia_depth=4,
                )
        return run.call_args.args[0], run.call_args.kwargs

    def test_command_switch_has_exactly_one_payload_argument(self):
        command, kwargs = self._capture_command(include_screenshot=False)

        self.assertIs(kwargs["shell"], False)
        command_index = command.index("-Command")

        # Incident invariant CU160-PS-ARG-BINDING-20260910:
        # powershell.exe -Command receives exactly one complete command payload.
        # No script parameter token may be appended as another argv element.
        self.assertEqual(command_index, len(command) - 2)
        self.assertEqual(len(command[command_index + 1 :]), 1)

        invocation = command[command_index + 1]
        self.assertTrue(invocation.startswith("& {\n"))
        self.assertIn("param([bool]$IncludeScreenshot, [int]$MaxNodes, [int]$MaxDepth)", invocation)
        self.assertTrue(
            invocation.rstrip().endswith(
                "} -IncludeScreenshot:$false -MaxNodes 32 -MaxDepth 4"
            )
        )

        forbidden_trailing_tokens = {
            "-IncludeScreenshot",
            "-MaxNodes",
            "-MaxDepth",
            "$true",
            "$false",
        }
        self.assertTrue(forbidden_trailing_tokens.isdisjoint(command[command_index + 2 :]))

    def test_true_boolean_binding_stays_inside_single_scriptblock_payload(self):
        command, _kwargs = self._capture_command(include_screenshot=True)
        command_index = command.index("-Command")

        self.assertEqual(command_index, len(command) - 2)
        invocation = command[command_index + 1]
        self.assertTrue(
            invocation.rstrip().endswith(
                "} -IncludeScreenshot:$true -MaxNodes 32 -MaxDepth 4"
            )
        )

    def test_fixed_payload_keeps_dynamic_execution_primitives_out(self):
        command, _kwargs = self._capture_command(include_screenshot=False)
        invocation = command[command.index("-Command") + 1]

        self.assertNotIn("Invoke-Expression", invocation)
        self.assertNotIn("Start-Process", invocation)
        self.assertNotIn("Set-ItemProperty", invocation)
        self.assertNotIn("cmd.exe /c", invocation.lower())


if __name__ == "__main__":
    unittest.main()
