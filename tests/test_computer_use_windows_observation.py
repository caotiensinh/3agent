import json
import unittest
from unittest.mock import patch

from three_agent.computer_use_windows_observation import (
    MAX_WINDOWS_SCREENSHOT_BYTES,
    WindowsObservationConfig,
    WindowsObservationError,
    WindowsPowerShellObservationBackend,
    WindowsReadOnlyCapture,
    capture_windows_observation,
)

NOW = "2026-09-10T06:10:00Z"


class FakeWindowsBackend:
    def __init__(self, capture):
        self.capture = capture
        self.calls = []

    def capture_read_only(self, *, include_screenshot, max_uia_nodes, max_uia_depth):
        self.calls.append((include_screenshot, max_uia_nodes, max_uia_depth))
        return self.capture


def capture(*, screenshot_bytes=None, accessibility=None, metadata=None):
    return WindowsReadOnlyCapture(
        window_id="0xABC123",
        process_id=4242,
        process_name="notepad",
        metadata=metadata or {
            "window_title": "notes.txt - Notepad",
            "session_id": 1,
            "responding": True,
            "uia_node_count": 2,
        },
        accessibility_snapshot=accessibility or {
            "automation_id": "root",
            "control_type": "ControlType.Window",
            "name": "notes.txt - Notepad",
            "is_password": False,
            "children": [
                {
                    "automation_id": "editor",
                    "control_type": "ControlType.Document",
                    "name": "Document",
                    "is_password": False,
                    "children": [],
                }
            ],
        },
        captured_at=NOW,
        screenshot_bytes=screenshot_bytes,
    )


class WindowsObservationTests(unittest.TestCase):
    def test_read_only_capture_builds_canonical_desktop_observation(self):
        backend = FakeWindowsBackend(capture())
        observation = capture_windows_observation(
            config=WindowsObservationConfig(),
            backend=backend,
            session_id="session:windows",
            task_id="task:windows",
        )
        self.assertEqual(observation.surface, "desktop")
        self.assertEqual(observation.active_target_ref, "windows:window:0xABC123/process:4242")
        self.assertEqual(observation.structured_observation["process_name"], "notepad")
        self.assertIsNone(observation.screenshot_sha256)
        self.assertEqual(backend.calls, [(False, 256, 8)])

    def test_equivalent_capture_produces_stable_state_hash(self):
        first = capture_windows_observation(
            config=WindowsObservationConfig(),
            backend=FakeWindowsBackend(capture()),
            session_id="session:windows",
            task_id="task:windows",
        )
        second = capture_windows_observation(
            config=WindowsObservationConfig(),
            backend=FakeWindowsBackend(capture()),
            session_id="session:windows",
            task_id="task:windows",
        )
        self.assertEqual(first.state_sha256, second.state_sha256)
        self.assertEqual(first.state_id, second.state_id)

    def test_password_ui_fields_are_redacted_before_retention(self):
        backend = FakeWindowsBackend(capture(accessibility={
            "automation_id": "login",
            "control_type": "ControlType.Edit",
            "name": "TOP-SECRET-PASSWORD",
            "value": "hunter2",
            "help_text": "credential secret",
            "is_password": True,
            "children": [],
        }))
        observation = capture_windows_observation(
            config=WindowsObservationConfig(),
            backend=backend,
            session_id="session:windows",
            task_id="task:windows",
        )
        rendered = json.dumps(observation.structured_observation, sort_keys=True)
        self.assertNotIn("TOP-SECRET-PASSWORD", rendered)
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("credential secret", rendered)
        self.assertIn("REDACTED_SECURE_UI", rendered)
        self.assertTrue(observation.structured_observation["accessibility"]["secure_content_redacted"])

    def test_general_privacy_redaction_still_applies_after_secure_ui_scrub(self):
        backend = FakeWindowsBackend(capture(metadata={
            "window_title": "Diagnostics",
            "access_token": "should-not-retain",
        }))
        observation = capture_windows_observation(
            config=WindowsObservationConfig(),
            backend=backend,
            session_id="session:windows",
            task_id="task:windows",
        )
        rendered = json.dumps(observation.structured_observation, sort_keys=True)
        self.assertNotIn("should-not-retain", rendered)

    def test_screenshot_is_denied_by_default(self):
        with self.assertRaisesRegex(WindowsObservationError, "WINDOWS_SCREENSHOT_POLICY_DENIED"):
            capture_windows_observation(
                config=WindowsObservationConfig(),
                backend=FakeWindowsBackend(capture(screenshot_bytes=b"png")),
                session_id="session:windows",
                task_id="task:windows",
                include_screenshot=True,
            )

    def test_on_demand_screenshot_retains_hash_only(self):
        raw = b"small-png-bytes"
        observation = capture_windows_observation(
            config=WindowsObservationConfig(screenshot_policy="on_demand"),
            backend=FakeWindowsBackend(capture(screenshot_bytes=raw)),
            session_id="session:windows",
            task_id="task:windows",
            include_screenshot=True,
        )
        self.assertTrue(observation.screenshot_sha256.startswith("sha256:"))
        self.assertNotIn(raw.decode(), json.dumps(observation.canonical_dict()))

    def test_unrequested_screenshot_from_backend_fails_closed(self):
        with self.assertRaisesRegex(WindowsObservationError, "WINDOWS_UNREQUESTED_SCREENSHOT_RETURNED"):
            capture_windows_observation(
                config=WindowsObservationConfig(),
                backend=FakeWindowsBackend(capture(screenshot_bytes=b"unexpected")),
                session_id="session:windows",
                task_id="task:windows",
            )

    def test_oversized_screenshot_fails_closed(self):
        with self.assertRaisesRegex(WindowsObservationError, "WINDOWS_SCREENSHOT_BOUND_EXCEEDED"):
            capture_windows_observation(
                config=WindowsObservationConfig(screenshot_policy="on_demand"),
                backend=FakeWindowsBackend(capture(screenshot_bytes=b"x" * (MAX_WINDOWS_SCREENSHOT_BYTES + 1))),
                session_id="session:windows",
                task_id="task:windows",
                include_screenshot=True,
            )

    def test_uia_node_count_is_independently_bounded(self):
        accessibility = {
            "automation_id": "root",
            "control_type": "ControlType.Window",
            "name": "root",
            "is_password": False,
            "children": [
                {"automation_id": f"c{i}", "control_type": "ControlType.Text", "name": str(i), "children": []}
                for i in range(4)
            ],
        }
        with self.assertRaisesRegex(WindowsObservationError, "WINDOWS_UIA_NODE_BOUND_EXCEEDED"):
            capture_windows_observation(
                config=WindowsObservationConfig(max_uia_nodes=3),
                backend=FakeWindowsBackend(capture(accessibility=accessibility)),
                session_id="session:windows",
                task_id="task:windows",
            )

    def test_invalid_process_identity_fails_closed(self):
        invalid = WindowsReadOnlyCapture(
            window_id="0xABC123",
            process_id=0,
            process_name="notepad",
            metadata={},
            accessibility_snapshot={"children": []},
            captured_at=NOW,
        )
        with self.assertRaisesRegex(WindowsObservationError, "INVALID_WINDOWS_PROCESS_ID"):
            capture_windows_observation(
                config=WindowsObservationConfig(),
                backend=FakeWindowsBackend(invalid),
                session_id="session:windows",
                task_id="task:windows",
            )

    def test_real_backend_fails_closed_off_windows(self):
        backend = WindowsPowerShellObservationBackend()
        with patch("three_agent.computer_use_windows_observation.os.name", "posix"):
            with self.assertRaisesRegex(WindowsObservationError, "WINDOWS_BACKEND_REQUIRES_WINDOWS"):
                backend.capture_read_only(
                    include_screenshot=False,
                    max_uia_nodes=32,
                    max_uia_depth=4,
                )

    def test_powershell_backend_uses_fixed_non_shell_read_only_command(self):
        payload = {
            "window_id": "0xABC123",
            "process_id": 4242,
            "process_name": "notepad",
            "metadata": {"window_title": "Notepad", "session_id": 1, "responding": True, "uia_node_count": 1},
            "accessibility": {"automation_id": "root", "control_type": "ControlType.Window", "name": "Notepad", "is_password": False, "children": []},
            "screenshot_base64": None,
            "captured_at": NOW,
        }
        completed = type("Completed", (), {
            "returncode": 0,
            "stdout": json.dumps(payload),
            "stderr": "",
        })()
        backend = WindowsPowerShellObservationBackend(powershell_executable="powershell.exe")
        with patch("three_agent.computer_use_windows_observation.os.name", "nt"):
            with patch("three_agent.computer_use_windows_observation.subprocess.run", return_value=completed) as run:
                result = backend.capture_read_only(
                    include_screenshot=False,
                    max_uia_nodes=32,
                    max_uia_depth=4,
                )
        self.assertEqual(result.process_id, 4242)
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["shell"], False)
        command = run.call_args.args[0]
        self.assertIn("-NoProfile", command)
        self.assertIn("-NonInteractive", command)
        script = command[command.index("-Command") + 1]
        self.assertIn("UIAutomationClient", script)
        self.assertNotIn("Invoke-Expression", script)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn("Set-ItemProperty", script)


if __name__ == "__main__":
    unittest.main()
