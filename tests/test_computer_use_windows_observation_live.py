import ctypes
import os
import subprocess
import time
import unittest
from ctypes import wintypes

from three_agent.computer_use_windows_observation import (
    WindowsObservationConfig,
    WindowsPowerShellObservationBackend,
    capture_windows_observation,
)


WINDOW_TITLE = "WorkSpace CU-160 Acceptance Window"


@unittest.skipUnless(os.name == "nt", "live Windows observation acceptance requires Windows")
class WindowsObservationLiveAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = rf'''
Add-Type -AssemblyName System.Windows.Forms
$form = New-Object System.Windows.Forms.Form
$form.Text = "{WINDOW_TITLE}"
$form.Width = 640
$form.Height = 240
$form.TopMost = $true
$label = New-Object System.Windows.Forms.Label
$label.Text = "CU-160 read-only observation acceptance"
$label.AutoSize = $true
$label.Left = 24
$label.Top = 40
$form.Controls.Add($label)
$form.Add_Shown({{ $form.Activate() }})
[System.Windows.Forms.Application]::Run($form)
'''
        cls._process = subprocess.Popen(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-STA", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls._hwnd = cls._wait_for_window(WINDOW_TITLE, timeout_seconds=15)
        if not cls._hwnd:
            stderr = ""
            if cls._process.poll() is not None and cls._process.stderr is not None:
                stderr = cls._process.stderr.read()
            cls._terminate_process()
            raise RuntimeError(f"CU160_ACCEPTANCE_WINDOW_NOT_FOUND: {stderr[:1000]}")
        cls._focus_window(cls._hwnd)

    @classmethod
    def tearDownClass(cls):
        cls._terminate_process()

    @classmethod
    def _terminate_process(cls):
        process = getattr(cls, "_process", None)
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    @staticmethod
    def _wait_for_window(title, *, timeout_seconds):
        user32 = ctypes.windll.user32
        found = {"hwnd": 0}
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def enum_callback(hwnd, _lparam):
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            if buffer.value == title:
                found["hwnd"] = int(hwnd)
                return False
            return True

        callback = callback_type(enum_callback)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            found["hwnd"] = 0
            user32.EnumWindows(callback, 0)
            if found["hwnd"]:
                return found["hwnd"]
            time.sleep(0.25)
        return 0

    @staticmethod
    def _focus_window(hwnd):
        user32 = ctypes.windll.user32
        SW_RESTORE = 9
        user32.ShowWindow(wintypes.HWND(hwnd), SW_RESTORE)
        user32.BringWindowToTop(wintypes.HWND(hwnd))
        if not user32.SetForegroundWindow(wintypes.HWND(hwnd)):
            raise RuntimeError("CU160_ACCEPTANCE_SET_FOREGROUND_FAILED")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if int(user32.GetForegroundWindow()) == hwnd:
                return
            time.sleep(0.1)
        raise RuntimeError("CU160_ACCEPTANCE_FOREGROUND_NOT_CONFIRMED")

    def test_real_powershell_backend_observes_live_uia_window_without_screenshot(self):
        backend = WindowsPowerShellObservationBackend(timeout_seconds=20)
        raw_capture = backend.capture_read_only(
            include_screenshot=False,
            max_uia_nodes=32,
            max_uia_depth=4,
        )

        self.assertEqual(raw_capture.process_id, self._process.pid)
        self.assertEqual(raw_capture.process_name.lower(), "powershell")
        self.assertIsNone(raw_capture.screenshot_bytes)
        self.assertLessEqual(raw_capture.metadata["uia_node_count"], 32)
        self.assertEqual(raw_capture.accessibility_snapshot["control_type"], "ControlType.Window")
        self.assertEqual(raw_capture.accessibility_snapshot["name"], WINDOW_TITLE)

        observation = capture_windows_observation(
            config=WindowsObservationConfig(max_uia_nodes=32, max_uia_depth=4),
            backend=backend,
            session_id="session:cu160-live",
            task_id="task:cu160-live",
        )
        self.assertEqual(observation.surface, "desktop")
        self.assertEqual(observation.structured_observation["platform"], "windows")
        self.assertEqual(observation.structured_observation["process_id"], self._process.pid)
        self.assertEqual(observation.structured_observation["accessibility"]["name"], WINDOW_TITLE)
        self.assertIsNone(observation.screenshot_sha256)
        self.assertTrue(observation.state_sha256.startswith("sha256:"))
        self.assertTrue(observation.active_target_ref.startswith("windows:window:0x"))


if __name__ == "__main__":
    unittest.main()
