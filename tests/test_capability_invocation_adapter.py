from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from three_agent.capability_authority import CapabilityAuthorityDenied, TaskCapabilityAuthority
from three_agent.capability_invocation_adapter import (
    CapabilityInvocationAdapterError,
    CapabilityInvocationRequest,
    current_runtime_invocation_identity,
    invoke_runtime_tool,
    reviewed_runtime_handler_ids,
)
from three_agent.capability_registry_snapshot import snapshot_micro_tool_registry
from three_agent.diagnostics.runtime_registry import runtime_tool_metadata
from three_agent.micro_tool_registry import MicroToolRegistry


def _sha(char: str) -> str:
    return "sha256:" + char * 64


def _authority(
    tool_id: str,
    *,
    task_id: str = "TASK-L16",
    allow_tool: bool = True,
    network_scope: str = "deny",
) -> TaskCapabilityAuthority:
    return TaskCapabilityAuthority._build(
        task_id=task_id,
        sensitivity="internal",
        allowed_sources=(),
        allowed_tools=(tool_id,) if allow_tool else (),
        write_scope="none",
        network_scope=network_scope,
    )


def _request(
    tool_id: str = "system.platform.identify",
    *,
    task_id: str = "TASK-L16",
    parameters: dict[str, object] | None = None,
) -> CapabilityInvocationRequest:
    snapshot_fingerprint, descriptor_fingerprint = current_runtime_invocation_identity(tool_id)
    return CapabilityInvocationRequest.create(
        task_id=task_id,
        tool_id=tool_id,
        snapshot_fingerprint=snapshot_fingerprint,
        descriptor_fingerprint=descriptor_fingerprint,
        parameters=parameters,
    )


class CapabilityInvocationAdapterTests(unittest.TestCase):
    def test_reviewed_handler_coverage_matches_all_current_runtime_tools(self) -> None:
        runtime_ids = tuple(sorted(item.id for item in runtime_tool_metadata()))
        self.assertEqual(len(runtime_ids), 32)
        self.assertEqual(reviewed_runtime_handler_ids(), runtime_ids)

    def test_positive_invocation_requires_authority_and_returns_bounded_receipt(self) -> None:
        request = _request()
        authority = _authority(request.tool_id)
        fake_result = {
            "tool_id": request.tool_id,
            "credential": "token=TOPSECRET",
            "blob": "x" * (128 * 1024),
        }
        with patch(
            "three_agent.capability_invocation_adapter.execute_common_read",
            return_value=fake_result,
        ) as handler:
            result = invoke_runtime_tool(request, authority=authority)

        handler.assert_called_once_with(request.tool_id, authority=authority)
        self.assertEqual(result.tool_id, request.tool_id)
        self.assertTrue(result.decision_receipt.allowed)
        self.assertEqual(result.decision_receipt.task_id, request.task_id)
        self.assertEqual(result.decision_receipt.request_ref_sha256, request.fingerprint)
        self.assertFalse(result.decision_receipt.automatic_action_allowed)
        self.assertEqual(result.decision_receipt.authority, "advisory")
        self.assertTrue(result.bounded_payload.truncated)
        self.assertGreater(result.bounded_payload.redactions, 0)
        self.assertNotIn("TOPSECRET", result.bounded_payload.text)
        self.assertLessEqual(result.bounded_payload.returned_bytes, 64 * 1024)
        self.assertFalse(result.canonical_dict()["payload_complete"])

    def test_unknown_tool_fails_before_handler_resolution(self) -> None:
        request = CapabilityInvocationRequest.create(
            task_id="TASK-L16",
            tool_id="unknown.runtime.tool",
            snapshot_fingerprint=_sha("1"),
            descriptor_fingerprint=_sha("2"),
        )
        with self.assertRaisesRegex(CapabilityInvocationAdapterError, "UNKNOWN_RUNTIME_TOOL_ID"):
            invoke_runtime_tool(request, authority=_authority("system.platform.identify"))

    def test_stale_snapshot_and_descriptor_fail_before_handler(self) -> None:
        baseline = _request()
        authority = _authority(baseline.tool_id)
        with patch("three_agent.capability_invocation_adapter.execute_common_read") as handler:
            stale_snapshot = replace(baseline, snapshot_fingerprint=_sha("1"))
            with self.assertRaisesRegex(
                CapabilityInvocationAdapterError,
                "STALE_CAPABILITY_REGISTRY_SNAPSHOT",
            ):
                invoke_runtime_tool(stale_snapshot, authority=authority)
            stale_descriptor = replace(baseline, descriptor_fingerprint=_sha("2"))
            with self.assertRaisesRegex(
                CapabilityInvocationAdapterError,
                "STALE_CAPABILITY_DESCRIPTOR",
            ):
                invoke_runtime_tool(stale_descriptor, authority=authority)
            handler.assert_not_called()

    def test_task_mismatch_and_missing_capability_fail_before_handler(self) -> None:
        request = _request()
        with patch("three_agent.capability_invocation_adapter.execute_common_read") as handler:
            with self.assertRaisesRegex(CapabilityInvocationAdapterError, "TASK_AUTHORITY_MISMATCH"):
                invoke_runtime_tool(
                    request,
                    authority=_authority(request.tool_id, task_id="TASK-OTHER"),
                )
            with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
                invoke_runtime_tool(
                    request,
                    authority=_authority(request.tool_id, allow_tool=False),
                )
            handler.assert_not_called()

    def test_arbitrary_execution_and_platform_spoof_parameters_are_rejected(self) -> None:
        snapshot_fingerprint, descriptor_fingerprint = current_runtime_invocation_identity(
            "system.platform.identify"
        )
        for field in ("handler", "module", "path", "command", "argv", "shell"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    CapabilityInvocationAdapterError,
                    "ARBITRARY_EXECUTION_PARAMETER_FORBIDDEN",
                ):
                    CapabilityInvocationRequest.create(
                        task_id="TASK-L16",
                        tool_id="system.platform.identify",
                        snapshot_fingerprint=snapshot_fingerprint,
                        descriptor_fingerprint=descriptor_fingerprint,
                        parameters={field: "attacker-controlled"},
                    )

        with self.assertRaisesRegex(
            CapabilityInvocationAdapterError,
            "CALLABLE_INVOCATION_PARAMETER_FORBIDDEN",
        ):
            CapabilityInvocationRequest.create(
                task_id="TASK-L16",
                tool_id="system.platform.identify",
                snapshot_fingerprint=snapshot_fingerprint,
                descriptor_fingerprint=descriptor_fingerprint,
                parameters={"timeout": lambda: None},
            )

        request = CapabilityInvocationRequest.create(
            task_id="TASK-L16",
            tool_id="system.platform.identify",
            snapshot_fingerprint=snapshot_fingerprint,
            descriptor_fingerprint=descriptor_fingerprint,
            parameters={"platform_name": "windows"},
        )
        with self.assertRaisesRegex(
            CapabilityInvocationAdapterError,
            "UNSUPPORTED_INVOCATION_PARAMETERS:platform_name",
        ):
            invoke_runtime_tool(request, authority=_authority(request.tool_id))

    def test_public_network_target_is_rejected_before_probe_handler(self) -> None:
        request = _request(
            "network.reachability.internal",
            parameters={"host": "8.8.8.8"},
        )
        authority = _authority(
            request.tool_id,
            network_scope="internal_only",
        )
        with patch(
            "three_agent.capability_invocation_adapter.probe_internal_reachability"
        ) as handler:
            with self.assertRaisesRegex(
                CapabilityInvocationAdapterError,
                "INTERNAL_IP_LITERAL_REQUIRED",
            ):
                invoke_runtime_tool(request, authority=authority)
            handler.assert_not_called()

    def test_rtsp_invocation_uses_reviewed_protocol_handler_and_internal_authority(self) -> None:
        request = _request(
            "network.rtsp.probe",
            parameters={"host": "192.168.11.196", "timeout": 1.25},
        )
        authority = _authority(
            request.tool_id,
            network_scope="internal_only",
        )
        fake_result = {
            "tool_id": request.tool_id,
            "target": "192.168.11.196",
            "port": 554,
            "rtsp_service_observed": True,
            "interpretation": "evidence_only",
        }
        with patch(
            "three_agent.capability_invocation_adapter.probe_rtsp_service",
            return_value=fake_result,
        ) as handler:
            result = invoke_runtime_tool(request, authority=authority)

        handler.assert_called_once_with(
            "192.168.11.196",
            authority=authority,
            timeout_seconds=1.25,
        )
        self.assertEqual(result.tool_id, "network.rtsp.probe")
        self.assertTrue(result.decision_receipt.allowed)
        self.assertEqual(result.decision_receipt.effect, "network_read")
        self.assertIn('"port":554', result.bounded_payload.text)
        self.assertIn('"interpretation":"evidence_only"', result.bounded_payload.text)

    def test_rtsp_public_target_is_rejected_before_protocol_handler(self) -> None:
        request = _request(
            "network.rtsp.probe",
            parameters={"host": "8.8.8.8"},
        )
        authority = _authority(
            request.tool_id,
            network_scope="internal_only",
        )
        with patch("three_agent.capability_invocation_adapter.probe_rtsp_service") as handler:
            with self.assertRaisesRegex(
                CapabilityInvocationAdapterError,
                "INTERNAL_IP_LITERAL_REQUIRED",
            ):
                invoke_runtime_tool(request, authority=authority)
            handler.assert_not_called()

    def test_service_resource_injection_is_rejected_before_handler(self) -> None:
        request = _request(
            "service.status.read",
            parameters={"service_name": "ssh;whoami"},
        )
        with patch("three_agent.capability_invocation_adapter.execute_common_read") as handler:
            with self.assertRaisesRegex(CapabilityInvocationAdapterError, "INVALID_SERVICE_NAME"):
                invoke_runtime_tool(request, authority=_authority(request.tool_id))
            handler.assert_not_called()

    def test_registry_effect_drift_is_denied_by_canonical_authority_before_handler(self) -> None:
        metadata = list(runtime_tool_metadata())
        changed = []
        for item in metadata:
            if item.id == "system.platform.identify":
                changed.append(replace(item, effect="compute"))
            else:
                changed.append(item)
        registry = MicroToolRegistry(changed)
        snapshot = snapshot_micro_tool_registry(registry)
        descriptor = next(
            item for item in snapshot.descriptors if item.id == "system.platform.identify"
        )
        request = CapabilityInvocationRequest.create(
            task_id="TASK-L16",
            tool_id="system.platform.identify",
            snapshot_fingerprint=snapshot.fingerprint,
            descriptor_fingerprint=descriptor.fingerprint,
        )
        authority = _authority(request.tool_id)
        with patch(
            "three_agent.capability_invocation_adapter.runtime_micro_tool_registry",
            return_value=registry,
        ), patch(
            "three_agent.capability_invocation_adapter.execute_common_read"
        ) as handler:
            with self.assertRaisesRegex(
                CapabilityAuthorityDenied,
                "CAPABILITY_EFFECT_NOT_ALLOWED",
            ):
                invoke_runtime_tool(request, authority=authority)
            handler.assert_not_called()

    def test_non_mapping_handler_result_fails_closed(self) -> None:
        request = _request()
        authority = _authority(request.tool_id)
        with patch(
            "three_agent.capability_invocation_adapter.execute_common_read",
            return_value="not-a-mapping",
        ):
            with self.assertRaisesRegex(
                CapabilityInvocationAdapterError,
                "HANDLER_RESULT_MUST_BE_MAPPING",
            ):
                invoke_runtime_tool(request, authority=authority)


if __name__ == "__main__":
    unittest.main()
