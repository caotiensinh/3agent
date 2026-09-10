from __future__ import annotations

import multiprocessing
import os
import time
import unittest

from three_agent.computer_use_linux_interaction import (
    LinuxAtspiInteractionBackend,
    LinuxInteractionCommand,
)
from three_agent.computer_use_linux_observation import (
    LinuxAtspiObservationBackend,
    LinuxObservationConfig,
    capture_linux_observation,
)

FIXTURE_TITLE = "WorkSpace CU-180 AT-SPI Acceptance"
ENTRY_NAME = "CU180 Entry"
BUTTON_NAME = "CU180 Invoke"
VALUE_TEXT = "workspace-cu180-live-value"


def _run_gtk_fixture() -> None:
    os.environ["NO_AT_BRIDGE"] = "0"
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

    window = Gtk.Window(title=FIXTURE_TITLE)
    window.set_default_size(560, 220)
    window.set_border_width(24)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)

    entry = Gtk.Entry()
    entry.set_text("before")
    entry.get_accessible().set_name(ENTRY_NAME)
    box.pack_start(entry, False, False, 0)

    button = Gtk.Button(label="Invoke")
    button.get_accessible().set_name(BUTTON_NAME)

    def invoked(_button):
        window.set_title(FIXTURE_TITLE + " INVOKED")

    button.connect("clicked", invoked)
    box.pack_start(button, False, False, 0)
    window.add(box)
    window.connect("destroy", Gtk.main_quit)
    window.show_all()
    window.present()
    Gtk.main()


def _find_named_node(value, name):
    if not isinstance(value, dict):
        return None
    if value.get("name") == name:
        return value
    for child in value.get("children", []):
        found = _find_named_node(child, name)
        if found is not None:
            return found
    return None


@unittest.skipUnless(os.name == "posix", "live AT-SPI2 acceptance requires Linux")
class LinuxAtspiLiveAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["NO_AT_BRIDGE"] = "0"
        cls.fixture = multiprocessing.Process(target=_run_gtk_fixture, daemon=True)
        cls.fixture.start()
        cls.semantic_backend = LinuxAtspiObservationBackend()
        cls.config = LinuxObservationConfig(max_atspi_nodes=128, max_atspi_depth=6)
        cls.pre = None
        deadline = time.monotonic() + 30
        last_error = None
        while time.monotonic() < deadline:
            if not cls.fixture.is_alive():
                raise RuntimeError("CU180_GTK_FIXTURE_EXITED")
            try:
                candidate = capture_linux_observation(
                    config=cls.config,
                    backend=cls.semantic_backend,
                    session_id="session:cu180-live",
                    task_id="task:cu180-live",
                )
                if _find_named_node(candidate.structured_observation["accessibility"], ENTRY_NAME):
                    cls.pre = candidate
                    break
            except Exception as exc:
                last_error = exc
            time.sleep(0.25)
        if cls.pre is None:
            cls.fixture.terminate()
            cls.fixture.join(timeout=5)
            raise RuntimeError(f"CU180_ATSPI_FIXTURE_NOT_OBSERVED:{type(last_error).__name__}:{last_error}")

    @classmethod
    def tearDownClass(cls):
        fixture = getattr(cls, "fixture", None)
        if fixture is not None and fixture.is_alive():
            fixture.terminate()
            fixture.join(timeout=5)

    def _command(self, *, node, interaction, value=None):
        arguments = {
            "interaction": interaction,
            "accessible_id": node["accessible_id"],
            "role": node["role"],
        }
        if value is not None:
            arguments["value"] = value
        return LinuxInteractionCommand(
            session_id="session:cu180-live",
            task_id="task:cu180-live",
            operation="computer.accessibility.interact",
            interaction_kind=interaction,
            resource_ref=f"local:desktop:window:{self.pre.structured_observation['target_id']}",
            target_id=self.pre.structured_observation["target_id"],
            process_id=self.pre.structured_observation["process_id"],
            accessible_id=node["accessible_id"],
            role=node["role"],
            arguments=arguments,
            expected_postcondition={
                "invoke": "LINUX_ATSPI_ACTION_INVOKED",
                "value": "LINUX_ATSPI_TEXT_SET",
            }[interaction],
        )

    def test_live_atspi_observation_and_semantic_value_mutation(self):
        node = _find_named_node(self.pre.structured_observation["accessibility"], ENTRY_NAME)
        self.assertIsNotNone(node)
        self.assertIn("EditableText", node["interfaces"])
        backend = LinuxAtspiInteractionBackend(
            observation_backend=self.semantic_backend,
            observation_config=self.config,
        )
        command = self._command(node=node, interaction="value", value=VALUE_TEXT)
        inspection = backend.inspect_target(command)
        self.assertFalse(inspection.secure_input)
        result = backend.dispatch(command)
        self.assertIn("LINUX_ATSPI_TEXT_SET", result.observed_postconditions)

        _atspi, _window, element = backend._resolve(command)
        text_interface = element.get_text_iface()
        self.assertIsNotNone(text_interface)
        self.assertEqual(str(text_interface.get_text(0, -1)), VALUE_TEXT)

    def test_live_atspi_semantic_invoke_mutation(self):
        current = capture_linux_observation(
            config=self.config,
            backend=self.semantic_backend,
            session_id="session:cu180-live",
            task_id="task:cu180-live",
        )
        node = _find_named_node(current.structured_observation["accessibility"], BUTTON_NAME)
        self.assertIsNotNone(node)
        self.assertIn("Action", node["interfaces"])
        self.__class__.pre = current
        backend = LinuxAtspiInteractionBackend(
            observation_backend=self.semantic_backend,
            observation_config=self.config,
        )
        result = backend.dispatch(self._command(node=node, interaction="invoke"))
        self.assertIn("LINUX_ATSPI_ACTION_INVOKED", result.observed_postconditions)

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            post = capture_linux_observation(
                config=self.config,
                backend=self.semantic_backend,
                session_id="session:cu180-live",
                task_id="task:cu180-live",
            )
            if post.structured_observation["metadata"].get("window_name") == FIXTURE_TITLE + " INVOKED":
                return
            time.sleep(0.1)
        self.fail("AT-SPI Action did not trigger the GTK button postcondition")


if __name__ == "__main__":
    unittest.main()
