from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

AUDIO_DEVICES_TOOL_ID = "audio.devices.snapshot"

AUDIO_TOOL_METADATA = (
    ToolMetadata(
        id=AUDIO_DEVICES_TOOL_ID,
        platform="any",
        category="audio",
        keywords=(
            "audio device",
            "microphone",
            "speaker",
            "headset",
            "sound device",
            "mic not working",
            "no sound",
            "khong co am thanh",
            "micro khong hoat dong",
            "loa khong keu",
            "マイク",
            "スピーカー",
            "音が出ない",
            "オーディオデバイス",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

LINUX_AUDIO_DEVICE_FILES = (
    Path("/proc/asound/cards"),
    Path("/proc/asound/devices"),
    Path("/proc/asound/pcm"),
)

_WINDOWS_AUDIO_QUERY = (
    "Get-CimInstance Win32_SoundDevice | "
    "Select-Object Name,Status,Manufacturer,PNPDeviceID | "
    "ConvertTo-Json -Compress"
)


def audio_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(AUDIO_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported audio-device platform: {value or 'unknown'}")


def build_windows_audio_device_plan() -> tuple[str, ...]:
    """Return one fixed read-only PowerShell query for local Windows sound devices."""
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_AUDIO_QUERY,
    )


def _read_linux_audio_files() -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for path in LINUX_AUDIO_DEVICE_FILES:
        key = path.as_posix()
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            results[key] = {
                "available": False,
                "error_type": type(exc).__name__,
            }
            continue
        bounded = bound_text_result(raw, max_bytes=16 * 1024)
        results[key] = {
            "available": True,
            "text": bounded.text,
            "output_boundary": bounded.metadata(),
        }
    return results


def read_audio_devices(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect local audio-device inventory evidence without diagnosing root cause.

    Windows uses a fixed Win32_SoundDevice query. Linux reads only fixed `/proc/asound`
    inventory files. The tool does not change default devices, volume, mute state,
    drivers, permissions, services, or application configuration. It also does not
    claim that a missing/failed inventory proves a physical microphone or speaker fault.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        AUDIO_DEVICES_TOOL_ID,
        resource_kind="audio_devices",
        resource_ref="local:audio:devices",
        effect="read",
    )

    base: dict[str, Any] = {
        "tool_id": AUDIO_DEVICES_TOOL_ID,
        "platform": target_platform,
        "scope": "local_audio_device_inventory",
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
    }

    if target_platform == "windows":
        completed = subprocess.run(
            build_windows_audio_device_plan(),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
        return {
            **base,
            "source": "Win32_SoundDevice",
            "returncode": completed.returncode,
            **bound_process_output(completed.stdout, completed.stderr),
        }

    return {
        **base,
        "source": "proc_asound",
        "files": _read_linux_audio_files(),
    }


__all__ = [
    "AUDIO_DEVICES_TOOL_ID",
    "AUDIO_TOOL_METADATA",
    "LINUX_AUDIO_DEVICE_FILES",
    "audio_micro_tool_registry",
    "build_windows_audio_device_plan",
    "read_audio_devices",
]
