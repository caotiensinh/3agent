from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .computer_use import ComputerObservation
from .computer_use_privacy import ComputerPrivacyError, sanitize_computer_content

MAX_WINDOWS_METADATA_BYTES = 8 * 1024
MAX_WINDOWS_ACCESSIBILITY_BYTES = 32 * 1024
MAX_WINDOWS_SCREENSHOT_BYTES = 8 * 1024 * 1024
MAX_WINDOWS_UIA_NODES = 256
MAX_WINDOWS_UIA_DEPTH = 8
_SCREENSHOT_POLICIES = frozenset({"deny", "on_demand"})
_TARGET_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class WindowsObservationError(ValueError):
    """Read-only Windows observation violated platform, privacy, or size rules."""


@dataclass(frozen=True)
class WindowsObservationConfig:
    screenshot_policy: str = "deny"
    max_uia_nodes: int = MAX_WINDOWS_UIA_NODES
    max_uia_depth: int = MAX_WINDOWS_UIA_DEPTH

    def validate(self) -> "WindowsObservationConfig":
        if self.screenshot_policy not in _SCREENSHOT_POLICIES:
            raise WindowsObservationError("INVALID_WINDOWS_SCREENSHOT_POLICY")
        if not isinstance(self.max_uia_nodes, int) or not (1 <= self.max_uia_nodes <= MAX_WINDOWS_UIA_NODES):
            raise WindowsObservationError("INVALID_WINDOWS_UIA_NODE_LIMIT")
        if not isinstance(self.max_uia_depth, int) or not (0 <= self.max_uia_depth <= MAX_WINDOWS_UIA_DEPTH):
            raise WindowsObservationError("INVALID_WINDOWS_UIA_DEPTH_LIMIT")
        return self


@dataclass(frozen=True)
class WindowsReadOnlyCapture:
    window_id: str
    process_id: int
    process_name: str
    metadata: Mapping[str, Any]
    accessibility_snapshot: Mapping[str, Any]
    captured_at: str
    screenshot_bytes: bytes | None = None


class WindowsReadOnlyBackend(Protocol):
    """Read-only Windows acquisition contract; never exposes input or mutation."""

    def capture_read_only(
        self,
        *,
        include_screenshot: bool,
        max_uia_nodes: int,
        max_uia_depth: int,
    ) -> WindowsReadOnlyCapture:
        ...


def _canonical_bytes(value: Mapping[str, Any], *, limit: int, error_code: str) -> bytes:
    if not isinstance(value, Mapping):
        raise WindowsObservationError(f"{error_code}_MUST_BE_OBJECT")
    try:
        payload = json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsObservationError(f"{error_code}_NOT_CANONICAL_JSON") from exc
    if len(payload) > limit:
        raise WindowsObservationError(f"{error_code}_BOUND_EXCEEDED")
    return payload


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _target_part(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _TARGET_PART_RE.fullmatch(value):
        raise WindowsObservationError(f"INVALID_WINDOWS_{field_name.upper()}")
    return value


def _sanitize_mapping(value: Mapping[str, Any], *, error_code: str) -> Mapping[str, Any]:
    try:
        sanitized = sanitize_computer_content(value)
    except ComputerPrivacyError as exc:
        raise WindowsObservationError(error_code) from exc
    if not isinstance(sanitized, Mapping):
        raise WindowsObservationError(error_code)
    return sanitized


def _scrub_secure_uia(value: Any) -> Any:
    """Remove normal text evidence from password/secure UIA nodes recursively."""

    if isinstance(value, Mapping):
        source = dict(value)
        is_password = source.get("is_password") is True or source.get("isPassword") is True
        if is_password:
            safe: dict[str, Any] = {}
            for key, item in source.items():
                normalized = str(key).lower().replace("_", "")
                if normalized in {"name", "value", "helptext", "legacyvalue", "text", "description"}:
                    safe[key] = "[REDACTED_SECURE_UI]"
                else:
                    safe[key] = _scrub_secure_uia(item)
            safe["secure_content_redacted"] = True
            return safe
        return {str(key): _scrub_secure_uia(item) for key, item in source.items()}
    if isinstance(value, list):
        return [_scrub_secure_uia(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub_secure_uia(item) for item in value]
    return value


def _count_uia_nodes(value: Any) -> int:
    if not isinstance(value, Mapping):
        return 0
    total = 1
    children = value.get("children")
    if isinstance(children, list):
        total += sum(_count_uia_nodes(child) for child in children)
    return total


def capture_windows_observation(
    *,
    config: WindowsObservationConfig,
    backend: WindowsReadOnlyBackend,
    session_id: str,
    task_id: str,
    include_screenshot: bool = False,
) -> ComputerObservation:
    """Capture one bounded, privacy-sanitized Windows desktop observation."""

    config.validate()
    if include_screenshot and config.screenshot_policy != "on_demand":
        raise WindowsObservationError("WINDOWS_SCREENSHOT_POLICY_DENIED")

    capture = backend.capture_read_only(
        include_screenshot=include_screenshot,
        max_uia_nodes=config.max_uia_nodes,
        max_uia_depth=config.max_uia_depth,
    )
    if not isinstance(capture, WindowsReadOnlyCapture):
        raise WindowsObservationError("INVALID_WINDOWS_BACKEND_CAPTURE")
    window_id = _target_part(capture.window_id, "window_id")
    if not isinstance(capture.process_id, int) or capture.process_id <= 0:
        raise WindowsObservationError("INVALID_WINDOWS_PROCESS_ID")
    process_name = _target_part(capture.process_name, "process_name")

    metadata = _sanitize_mapping(capture.metadata, error_code="WINDOWS_METADATA_PRIVACY_REJECTED")
    secure_scrubbed = _scrub_secure_uia(capture.accessibility_snapshot)
    if not isinstance(secure_scrubbed, Mapping):
        raise WindowsObservationError("WINDOWS_ACCESSIBILITY_SNAPSHOT_MUST_BE_OBJECT")
    if _count_uia_nodes(secure_scrubbed) > config.max_uia_nodes:
        raise WindowsObservationError("WINDOWS_UIA_NODE_BOUND_EXCEEDED")
    accessibility = _sanitize_mapping(
        secure_scrubbed,
        error_code="WINDOWS_ACCESSIBILITY_PRIVACY_REJECTED",
    )

    metadata_bytes = _canonical_bytes(
        metadata,
        limit=MAX_WINDOWS_METADATA_BYTES,
        error_code="WINDOWS_METADATA",
    )
    accessibility_bytes = _canonical_bytes(
        accessibility,
        limit=MAX_WINDOWS_ACCESSIBILITY_BYTES,
        error_code="WINDOWS_ACCESSIBILITY_SNAPSHOT",
    )

    screenshot_sha256 = None
    if include_screenshot:
        if not isinstance(capture.screenshot_bytes, bytes):
            raise WindowsObservationError("WINDOWS_SCREENSHOT_REQUIRED")
        if len(capture.screenshot_bytes) > MAX_WINDOWS_SCREENSHOT_BYTES:
            raise WindowsObservationError("WINDOWS_SCREENSHOT_BOUND_EXCEEDED")
        screenshot_sha256 = _sha256_bytes(capture.screenshot_bytes)
    elif capture.screenshot_bytes is not None:
        raise WindowsObservationError("WINDOWS_UNREQUESTED_SCREENSHOT_RETURNED")

    target_ref = f"windows:window:{window_id}/process:{capture.process_id}"
    structured = {
        "platform": "windows",
        "window_id": window_id,
        "process_id": capture.process_id,
        "process_name": process_name,
        "metadata": json.loads(metadata_bytes.decode("utf-8")),
        "accessibility": json.loads(accessibility_bytes.decode("utf-8")),
    }
    state_payload = json.dumps(
        {
            "target_ref": target_ref,
            "structured": structured,
            "screenshot_sha256": screenshot_sha256,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    state_sha256 = _sha256_bytes(state_payload)
    return ComputerObservation(
        session_id=session_id,
        task_id=task_id,
        state_id="state:" + state_sha256.removeprefix("sha256:"),
        state_sha256=state_sha256,
        surface="desktop",
        active_target_ref=target_ref,
        captured_at=capture.captured_at,
        structured_observation=structured,
        screenshot_sha256=screenshot_sha256,
    ).validate()


class WindowsPowerShellObservationBackend:
    """Standard-user fixed-script backend for foreground-window/UIA observation.

    The backend accepts no shell text from callers. The PowerShell program is
    constant and performs observation only. It intentionally provides no invoke,
    value-set, pointer, keyboard, process-start, registry-write, or elevation API.
    """

    _SCRIPT = r'''
param([bool]$IncludeScreenshot, [int]$MaxNodes, [int]$MaxDepth)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win32Foreground {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
}
"@

$hwnd = [Win32Foreground]::GetForegroundWindow()
if ($hwnd -eq [IntPtr]::Zero) { throw 'WINDOWS_FOREGROUND_WINDOW_NOT_FOUND' }
[uint32]$pidValue = 0
[void][Win32Foreground]::GetWindowThreadProcessId($hwnd, [ref]$pidValue)
if ($pidValue -le 0) { throw 'WINDOWS_FOREGROUND_PROCESS_NOT_FOUND' }
$process = Get-Process -Id $pidValue -ErrorAction Stop
$root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
if ($null -eq $root) { throw 'WINDOWS_UIA_ROOT_NOT_FOUND' }

$count = 0
function Convert-UiaNode([System.Windows.Automation.AutomationElement]$Element, [int]$Depth) {
  if ($null -eq $Element -or $Depth -gt $MaxDepth -or $script:count -ge $MaxNodes) { return $null }
  $script:count++
  $current = $Element.Current
  $node = [ordered]@{
    automation_id = [string]$current.AutomationId
    control_type = [string]$current.ControlType.ProgrammaticName
    name = [string]$current.Name
    is_enabled = [bool]$current.IsEnabled
    is_offscreen = [bool]$current.IsOffscreen
    is_password = [bool]$current.IsPassword
    children = @()
  }
  if ($current.IsPassword) { $node.name = '[REDACTED_SECURE_UI]' }
  if ($Depth -lt $MaxDepth -and $script:count -lt $MaxNodes) {
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $child = $walker.GetFirstChild($Element)
    while ($null -ne $child -and $script:count -lt $MaxNodes) {
      $converted = Convert-UiaNode $child ($Depth + 1)
      if ($null -ne $converted) { $node.children += $converted }
      $child = $walker.GetNextSibling($child)
    }
  }
  return $node
}

$uia = Convert-UiaNode $root 0
$screenshot = $null
if ($IncludeScreenshot) {
  Add-Type -AssemblyName System.Drawing
  Add-Type -AssemblyName System.Windows.Forms
  $bounds = [System.Windows.Forms.Screen]::FromHandle($hwnd).Bounds
  $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  try {
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $stream = New-Object System.IO.MemoryStream
    try {
      $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
      $screenshot = [Convert]::ToBase64String($stream.ToArray())
    } finally { $stream.Dispose() }
  } finally {
    $graphics.Dispose()
    $bitmap.Dispose()
  }
}

[ordered]@{
  window_id = ('0x{0:X}' -f $hwnd.ToInt64())
  process_id = [int]$pidValue
  process_name = [string]$process.ProcessName
  metadata = [ordered]@{
    window_title = [string]$process.MainWindowTitle
    session_id = [int]$process.SessionId
    responding = [bool]$process.Responding
    uia_node_count = [int]$count
  }
  accessibility = $uia
  screenshot_base64 = $screenshot
  captured_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
} | ConvertTo-Json -Depth 20 -Compress
'''

    def __init__(self, *, powershell_executable: str = "powershell.exe", timeout_seconds: int = 15) -> None:
        if not isinstance(powershell_executable, str) or not powershell_executable.strip():
            raise WindowsObservationError("INVALID_POWERSHELL_EXECUTABLE")
        if not isinstance(timeout_seconds, int) or not (1 <= timeout_seconds <= 60):
            raise WindowsObservationError("INVALID_WINDOWS_OBSERVATION_TIMEOUT")
        self._powershell_executable = powershell_executable
        self._timeout_seconds = timeout_seconds

    def capture_read_only(
        self,
        *,
        include_screenshot: bool,
        max_uia_nodes: int,
        max_uia_depth: int,
    ) -> WindowsReadOnlyCapture:
        if os.name != "nt":
            raise WindowsObservationError("WINDOWS_BACKEND_REQUIRES_WINDOWS")
        config = WindowsObservationConfig(
            screenshot_policy="on_demand" if include_screenshot else "deny",
            max_uia_nodes=max_uia_nodes,
            max_uia_depth=max_uia_depth,
        ).validate()
        boolean_literal = "$true" if include_screenshot else "$false"
        invocation = (
            "& {\n"
            f"{self._SCRIPT}\n"
            "} "
            f"-IncludeScreenshot:{boolean_literal} "
            f"-MaxNodes {config.max_uia_nodes} "
            f"-MaxDepth {config.max_uia_depth}"
        )
        command = [
            self._powershell_executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            invocation,
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WindowsObservationError("WINDOWS_OBSERVATION_BACKEND_FAILED") from exc
        if completed.returncode != 0:
            raise WindowsObservationError("WINDOWS_OBSERVATION_BACKEND_FAILED")
        if len(completed.stdout.encode("utf-8")) > (MAX_WINDOWS_ACCESSIBILITY_BYTES * 4 + MAX_WINDOWS_SCREENSHOT_BYTES * 2):
            raise WindowsObservationError("WINDOWS_BACKEND_OUTPUT_BOUND_EXCEEDED")
        try:
            payload = json.loads(completed.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise WindowsObservationError("WINDOWS_BACKEND_OUTPUT_INVALID_JSON") from exc
        if not isinstance(payload, Mapping):
            raise WindowsObservationError("WINDOWS_BACKEND_OUTPUT_MUST_BE_OBJECT")

        screenshot_bytes = None
        encoded = payload.get("screenshot_base64")
        if include_screenshot:
            if not isinstance(encoded, str) or not encoded:
                raise WindowsObservationError("WINDOWS_SCREENSHOT_REQUIRED")
            try:
                screenshot_bytes = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as exc:
                raise WindowsObservationError("WINDOWS_SCREENSHOT_INVALID_BASE64") from exc
        elif encoded is not None:
            raise WindowsObservationError("WINDOWS_UNREQUESTED_SCREENSHOT_RETURNED")

        metadata = payload.get("metadata")
        accessibility = payload.get("accessibility")
        if not isinstance(metadata, Mapping) or not isinstance(accessibility, Mapping):
            raise WindowsObservationError("WINDOWS_BACKEND_STRUCTURED_OUTPUT_INVALID")
        return WindowsReadOnlyCapture(
            window_id=payload.get("window_id"),
            process_id=payload.get("process_id"),
            process_name=payload.get("process_name"),
            metadata=metadata,
            accessibility_snapshot=accessibility,
            captured_at=payload.get("captured_at"),
            screenshot_bytes=screenshot_bytes,
        )
