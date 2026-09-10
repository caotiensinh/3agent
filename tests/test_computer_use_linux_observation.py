from __future__ import annotations

import inspect
import json
import unittest
from unittest.mock import patch

import three_agent.computer_use_linux_observation as linux_observation
from three_agent.computer_use_linux_observation import (
    MAX_LINUX_SCREENSHOT_BYTES,
    LinuxAtspiObservationBackend,
    LinuxObservationConfig,
    LinuxObservationError,
    LinuxReadOnlyCapture,
    capture_linux_observation,
)

NOW = "2026-09-10T14:40:00Z"
TARGET = "atspi-0123456789abcdef0123456789abcdef"


class FakeSemanticBackend:
    def __init__(self, capture: LinuxReadOnlyCapture):
        self.capture = capture
        self.calls = []

    def capture_read_only(self, *, max_atspi_nodes: int, max_atspi_depth: int):
        self.calls.append((max_atspi_nodes, max_atspi_depth))
        return self.capture


class FakeScreenshotBackend:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.calls = 0

    def capture_screenshot(self) -> bytes:
        self.calls += 1
        return self.payload


def capture(*, accessibility=None, metadata=None) -> LinuxReadOnlyCapture:
    return LinuxReadOnlyCapture(
        target_id=TARGET,
        process_id=4242,
        application_name="WorkSpace Fixture",
        metadata=metadata or {"window_name": "Fixture", "atspi_node_count": 2},
        accessibility_snapshot=accessibility or {
            "accessible_id": TARGET,
            "role": "frame",
            "name": "Fixture",
            "interfaces": ["Component"],
            "is_enabled": True,
            "is_focused": True,
            "is_showing": True,
            "is_visible": True,
            "is_secure": False,
            "children": [
                {
                    "accessible_id": "atspi-11111111111111111111111111111111",
                    "role": "push button",
                    "name": "Apply",
                    "interfaces": ["Action", "Component"],
                    "is_enabled": True,
                    "is_focused": False,
                    "is_showing": True,
                    "is_visible": True,
                    "is_secure": False,
                    "children": [],
                }
            ],
        },
        captured_at=NOW,
    )


class FakeStateSet:
    def __init__(self, states):
        self.states = set(states)

    def contains(self, state):
        return state in self.states


class FakeStateType:
    ACTIVE = "ACTIVE"
    ENABLED = "ENABLED"
    FOCUSED = "FOCUSED"
    SHOWING = "SHOWING"
    VISIBLE = "VISIBLE"
    PROTECTED = "PROTECTED"


class FakeAccessible:
    def __init__(self, *, accessible_id, name, role, pid=4242, states=(), interfaces=(), children=()):
        self._id = accessible_id
        self._name = name
        self._role = role
        self._pid = pid
        self._states = FakeStateSet(states)
        self._interfaces = list(interfaces)
        self._children = list(children)
        self._parent = None
        for child in self._children:
            child._parent = self

    def get_accessible_id(self): return self._id
    def get_name(self): return self._name
    def get_role_name(self): return self._role
    def get_process_id(self): return self._pid
    def get_state_set(self): return self._states
    def get_interfaces(self): return self._interfaces
    def get_child_count(self): return len(self._children)
    def get_child_at_index(self, index): return self._children[index]
    def get_parent(self): return self._parent
    def get_index_in_parent(self): return self._parent._children.index(self) if self._parent else 0
    def get_application(self):
        current = self
        while current._parent is not None and current._parent._parent is not None:
            current = current._parent
        return current


class FakeAtspi:
    StateType = FakeStateType

    def __init__(self, desktop):
        self.desktop = desktop

    def get_desktop(self, index):
        return self.desktop if index == 0 else None

    def get_version(self):
        return (2, 52, 0)


class LinuxObservationTests(unittest.TestCase):
    def test_semantic_capture_builds_canonical_linux_observation(self):
        backend = FakeSemanticBackend(capture())
        observation = capture_linux_observation(
            config=LinuxObservationConfig(),
            backend=backend,
            session_id="session:linux",
            task_id="task:linux",
        )
        self.assertEqual(observation.surface, "desktop")
        self.assertEqual(observation.active_target_ref, f"linux:atspi:{TARGET}/process:4242")
        self.assertEqual(observation.structured_observation["backend"], "atspi2")
        self.assertEqual(backend.calls, [(256, 8)])
        self.assertIsNone(observation.screenshot_sha256)

    def test_equivalent_semantic_capture_has_stable_state_hash(self):
        first = capture_linux_observation(
            config=LinuxObservationConfig(), backend=FakeSemanticBackend(capture()),
            session_id="session:linux", task_id="task:linux",
        )
        second = capture_linux_observation(
            config=LinuxObservationConfig(), backend=FakeSemanticBackend(capture()),
            session_id="session:linux", task_id="task:linux",
        )
        self.assertEqual(first.state_sha256, second.state_sha256)

    def test_screenshot_fallback_is_denied_by_default(self):
        with self.assertRaisesRegex(LinuxObservationError, "LINUX_SCREENSHOT_POLICY_DENIED"):
            capture_linux_observation(
                config=LinuxObservationConfig(), backend=FakeSemanticBackend(capture()),
                session_id="session:linux", task_id="task:linux",
                include_screenshot=True, screenshot_backend=FakeScreenshotBackend(b"png"),
            )

    def test_screenshot_backend_cannot_be_injected_when_not_requested(self):
        with self.assertRaisesRegex(LinuxObservationError, "LINUX_UNREQUESTED_SCREENSHOT_BACKEND"):
            capture_linux_observation(
                config=LinuxObservationConfig(), backend=FakeSemanticBackend(capture()),
                session_id="session:linux", task_id="task:linux",
                screenshot_backend=FakeScreenshotBackend(b"png"),
            )

    def test_on_demand_screenshot_retains_digest_only(self):
        screenshot = FakeScreenshotBackend(b"private-pixels")
        observation = capture_linux_observation(
            config=LinuxObservationConfig(screenshot_policy="on_demand"),
            backend=FakeSemanticBackend(capture()), session_id="session:linux", task_id="task:linux",
            include_screenshot=True, screenshot_backend=screenshot,
        )
        self.assertEqual(screenshot.calls, 1)
        self.assertTrue(observation.screenshot_sha256.startswith("sha256:"))
        self.assertNotIn("private-pixels", json.dumps(observation.canonical_dict()))

    def test_oversized_screenshot_fails_closed(self):
        with self.assertRaisesRegex(LinuxObservationError, "LINUX_SCREENSHOT_BOUND_EXCEEDED"):
            capture_linux_observation(
                config=LinuxObservationConfig(screenshot_policy="on_demand"),
                backend=FakeSemanticBackend(capture()), session_id="session:linux", task_id="task:linux",
                include_screenshot=True,
                screenshot_backend=FakeScreenshotBackend(b"x" * (MAX_LINUX_SCREENSHOT_BYTES + 1)),
            )

    def test_privacy_filter_rejects_retaining_secret_metadata(self):
        observation = capture_linux_observation(
            config=LinuxObservationConfig(),
            backend=FakeSemanticBackend(capture(metadata={"window_name": "Fixture", "access_token": "secret-value"})),
            session_id="session:linux", task_id="task:linux",
        )
        self.assertNotIn("secret-value", json.dumps(observation.structured_observation, sort_keys=True))

    def test_node_bound_is_independently_enforced(self):
        root = capture().accessibility_snapshot
        with self.assertRaisesRegex(LinuxObservationError, "LINUX_ATSPI_NODE_BOUND_EXCEEDED"):
            capture_linux_observation(
                config=LinuxObservationConfig(max_atspi_nodes=1),
                backend=FakeSemanticBackend(capture(accessibility=root)),
                session_id="session:linux", task_id="task:linux",
            )

    def test_concrete_atspi_backend_uses_direct_semantic_api(self):
        button = FakeAccessible(
            accessible_id="button-raw-id", name="Apply", role="push button",
            states=("ENABLED", "SHOWING", "VISIBLE"), interfaces=("Action", "Component"),
        )
        window = FakeAccessible(
            accessible_id="window-raw-id", name="Fixture", role="frame",
            states=("ACTIVE", "ENABLED", "SHOWING", "VISIBLE"), children=(button,),
        )
        app = FakeAccessible(accessible_id="app", name="Fixture App", role="application", children=(window,))
        desktop = FakeAccessible(accessible_id="desktop", name="Desktop", role="desktop frame", children=(app,))
        atspi = FakeAtspi(desktop)
        backend = LinuxAtspiObservationBackend()
        with patch.object(linux_observation.sys, "platform", "linux"):
            with patch.object(linux_observation, "_load_atspi", return_value=atspi):
                result = backend.capture_read_only(max_atspi_nodes=16, max_atspi_depth=4)
        self.assertEqual(result.process_id, 4242)
        self.assertEqual(result.application_name, "Fixture App")
        self.assertEqual(result.metadata["atspi_node_count"], 2)
        self.assertEqual(result.accessibility_snapshot["children"][0]["name"], "Apply")

    def test_secure_atspi_node_is_redacted_before_snapshot(self):
        password = FakeAccessible(
            accessible_id="password", name="actual-password", role="password text",
            states=("PROTECTED", "ENABLED", "SHOWING", "VISIBLE"), interfaces=("EditableText",),
        )
        window = FakeAccessible(
            accessible_id="window", name="Login", role="frame", states=("ACTIVE",), children=(password,),
        )
        app = FakeAccessible(accessible_id="app", name="Login App", role="application", children=(window,))
        desktop = FakeAccessible(accessible_id="desktop", name="Desktop", role="desktop frame", children=(app,))
        with patch.object(linux_observation.sys, "platform", "linux"):
            with patch.object(linux_observation, "_load_atspi", return_value=FakeAtspi(desktop)):
                result = LinuxAtspiObservationBackend().capture_read_only(max_atspi_nodes=16, max_atspi_depth=4)
        rendered = json.dumps(result.accessibility_snapshot)
        self.assertNotIn("actual-password", rendered)
        self.assertIn("REDACTED_SECURE_UI", rendered)

    def test_linux_observation_module_has_no_shell_execution_surface(self):
        source = inspect.getsource(linux_observation)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
