from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.audio_tools import (
    AUDIO_DEVICES_TOOL_ID,
    AUDIO_TOOL_METADATA,
    LINUX_AUDIO_DEVICE_FILES,
    audio_micro_tool_registry,
    build_windows_audio_device_plan,
    read_audio_devices,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(
        self,
        capability: str,
        *,
        resource_kind: str,
        resource_ref: str,
        effect: str,
    ) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class DenyingAuthority:
    def require(self, *args, **kwargs) -> None:
        raise PermissionError("denied")


class AudioDevicesToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only_and_sensitive(self) -> None:
        self.assertEqual(len(AUDIO_TOOL_METADATA), 1)
        tool = AUDIO_TOOL_METADATA[0]
        self.assertEqual(tool.id, AUDIO_DEVICES_TOOL_ID)
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertTrue(tool.sensitive_outputs)
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(audio_micro_tool_registry().metadata_view()), 1)

    def test_windows_plan_is_fixed_read_only_argv(self) -> None:
        plan = build_windows_audio_device_plan()
        self.assertEqual(plan[0:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-CimInstance Win32_SoundDevice", plan[4])
        self.assertIn("ConvertTo-Json -Compress", plan[4])
        self.assertNotIn("Set-", plan[4])
        self.assertNotIn("Remove-", plan[4])

    def test_linux_sources_are_fixed_proc_asound_paths(self) -> None:
        self.assertEqual(
            tuple(path.as_posix() for path in LINUX_AUDIO_DEVICE_FILES),
            (
                "/proc/asound/cards",
                "/proc/asound/devices",
                "/proc/asound/pcm",
            ),
        )

    @patch("three_agent.diagnostics.audio_tools.subprocess.run")
    def test_windows_read_requires_exact_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"Name":"USB Headset","Status":"OK"}]',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_audio_devices(
            authority=authority,  # type: ignore[arg-type]
            platform_name="Windows",
        )
        self.assertEqual(
            authority.calls,
            [
                (
                    AUDIO_DEVICES_TOOL_ID,
                    "audio_devices",
                    "local:audio:devices",
                    "read",
                )
            ],
        )
        self.assertEqual(result["source"], "Win32_SoundDevice")
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.audio_tools.subprocess.run")
    def test_authority_denial_happens_before_windows_subprocess(self, run_mock) -> None:
        with self.assertRaises(PermissionError):
            read_audio_devices(
                authority=DenyingAuthority(),  # type: ignore[arg-type]
                platform_name="Windows",
            )
        run_mock.assert_not_called()

    @patch("pathlib.Path.read_text")
    def test_linux_inventory_reads_only_fixed_sources(self, read_text_mock) -> None:
        read_text_mock.side_effect = (
            " 0 [PCH]: HDA-Intel - HDA Intel PCH\n",
            "  2: [ 0- 0]: digital audio playback\n",
            "00-00: ALCxxx : playback 1 : capture 1\n",
        )
        authority = RecordingAuthority()
        result = read_audio_devices(
            authority=authority,  # type: ignore[arg-type]
            platform_name="Linux",
        )
        self.assertEqual(result["source"], "proc_asound")
        self.assertEqual(len(result["files"]), 3)
        self.assertTrue(all(item["available"] for item in result["files"].values()))
        self.assertEqual(read_text_mock.call_count, 3)
        self.assertFalse(result["root_cause_claimed"])

    @patch("pathlib.Path.read_text")
    def test_authority_denial_happens_before_linux_file_reads(self, read_text_mock) -> None:
        with self.assertRaises(PermissionError):
            read_audio_devices(
                authority=DenyingAuthority(),  # type: ignore[arg-type]
                platform_name="Linux",
            )
        read_text_mock.assert_not_called()

    @patch("pathlib.Path.read_text", side_effect=FileNotFoundError("no asound"))
    def test_missing_linux_inventory_is_only_missing_evidence_not_hardware_failure(self, read_text_mock) -> None:
        authority = RecordingAuthority()
        result = read_audio_devices(
            authority=authority,  # type: ignore[arg-type]
            platform_name="Linux",
        )
        self.assertEqual(read_text_mock.call_count, 3)
        self.assertTrue(all(not item["available"] for item in result["files"].values()))
        self.assertFalse(result["root_cause_claimed"])
        self.assertNotIn("hardware_failed", result)
        self.assertNotIn("microphone_failed", result)
        self.assertNotIn("speaker_failed", result)

    def test_unsupported_platform_fails_closed(self) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported audio-device platform"):
            read_audio_devices(
                authority=authority,  # type: ignore[arg-type]
                platform_name="Darwin",
            )
        self.assertEqual(authority.calls, [])


if __name__ == "__main__":
    unittest.main()
