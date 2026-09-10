from __future__ import annotations

import ctypes
import os
import re
import subprocess
import time
import unittest
from ctypes import wintypes

from three_agent.computer_use_windows_interaction import WindowsPowerShellInteractionBackend
from three_agent.computer_use_windows_observation import WindowsPowerShellObservationBackend


WINDOW_TITLE = "WorkSpace CU-170 Diagnostic Window"
_SAFE_REASON_RE = re.compile(r"\bWINDOWS_[A-Z0-9_]{3,128}\b")
_LINE_CHAR_RE = re.compile(r"At line:(\d+) char:(\d+)", re.IGNORECASE)
_ERROR_CLASSES = (
    "ParserError",
    "MethodException",
    "RuntimeException",
    "CommandNotFoundException",
    "InvalidOperation",
    "ParameterBindingException",
)


def _safe_powershell_failure(stderr: str) -> str:
    reasons = sorted(set(_SAFE_REASON_RE.findall(stderr or "")))
    if reasons:
        return "reason=" + ",".join(reasons[:4])
    error_class = next((item for item in _ERROR_CLASSES if item.lower() in (stderr or "").lower()), "UnknownPowerShellError")
    location = _LINE_CHAR_RE.search(stderr or "")
    if location:
        return f"class={error_class};line={location.group(1)};char={location.group(2)}"
    return f"class={error_class};location=unavailable"


def _bounded_selector_metadata(node, *, limit: int = 16) -> str:
    items: list[str] = []

    def walk(value) -> None:
        if len(items) >= limit or not isinstance(value, dict):
            return
        automation_id = value.get("automation_id")
        control_type = value.get("control_type")
        safe_id = automation_id if isinstance(automation_id, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", automation_id) else "EMPTY"
        safe_type = control_type if isinstance(control_type, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", control_type) else "UNKNOWN"
        items.append(f"{safe_type}:{safe_id}")
        children = value.get("children")
        if isinstance(children, list):
            for child in children:
                walk(child)

    walk(node)
    return ",".join(items)


@unittest.skipUnless(os.name == "nt", "bounded CU-170 diagnostic requires Windows")
class WindowsInteractionBoundedDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = rf'''
Add-Type -AssemblyName System.Windows.Forms
$form = New-Object System.Windows.Forms.Form
$form.Text = "{WINDOW_TITLE}"
$form.Width = 500
$form.Height = 180
$form.TopMost = $true
$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Name = "InputBox"
$textbox.Left = 24
$textbox.Top = 35
$textbox.Width = 320
$form.Controls.Add($textbox)
$form.Add_Shown({{ $form.Activate() }})
[System.Windows.Forms.Application]::Run($form)
'''
        cls._process = subprocess.Popen(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-STA", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls._hwnd = cls._wait_for_window(WINDOW_TITLE, timeout_seconds=15)
        if not cls._hwnd:
            cls._terminate_process()
            raise RuntimeError("CU170_DIAGNOSTIC_WINDOW_NOT_FOUND")
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
    def _wait_for_window(title: str, *, timeout_seconds: int) -> int:
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
    def _focus_window(hwnd: int) -> None:
        user32 = ctypes.windll.user32
        user32.ShowWindow(wintypes.HWND(hwnd), 9)
        user32.BringWindowToTop(wintypes.HWND(hwnd))
        if not user32.SetForegroundWindow(wintypes.HWND(hwnd)):
            raise RuntimeError("CU170_DIAGNOSTIC_SET_FOREGROUND_FAILED")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if int(user32.GetForegroundWindow()) == hwnd:
                return
            time.sleep(0.1)
        raise RuntimeError("CU170_DIAGNOSTIC_FOREGROUND_NOT_CONFIRMED")

    def test_fixed_backend_script_inspect_mode_with_bounded_failure_metadata(self):
        self._focus_window(self._hwnd)
        env = os.environ.copy()
        env["WORKSPACE_CU170_MODE"] = "inspect"
        env["WORKSPACE_CU170_WINDOW_ID"] = f"0x{self._hwnd:X}"
        env["WORKSPACE_CU170_AUTOMATION_ID"] = "InputBox"
        env["WORKSPACE_CU170_TEXT_B64"] = ""
        env["WORKSPACE_CU170_EXPECTED_TEXT_B64"] = ""
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                WindowsPowerShellInteractionBackend._SCRIPT,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            shell=False,
            env=env,
        )
        if completed.returncode != 0:
            observation_backend = WindowsPowerShellObservationBackend(timeout_seconds=20)
            raw = observation_backend.capture_read_only(
                include_screenshot=False,
                max_uia_nodes=32,
                max_uia_depth=4,
            )
            selector_metadata = _bounded_selector_metadata(raw.accessibility_snapshot)
            self.fail(
                "CU170_BOUNDED_DIAGNOSTIC:"
                + _safe_powershell_failure(completed.stderr)
                + ";selectors="
                + selector_metadata
            )
        self.assertLessEqual(len(completed.stdout.encode("utf-8")), 16 * 1024)
        self.assertIn('"process_id"', completed.stdout)
        self.assertIn('"secure_input"', completed.stdout)


if __name__ == "__main__":
    unittest.main()
