from __future__ import annotations

import unittest

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.task_contract import TaskContractCompiler


class CapabilityAuthorityResourcePolicyTests(unittest.TestCase):
    @staticmethod
    def _authority(tool_id: str) -> TaskCapabilityAuthority:
        contract = TaskContractCompiler().compile(
            task_id=f"L13-{tool_id}",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=(tool_id,),
        )
        return TaskCapabilityAuthority.from_contract(contract)

    def test_exact_local_resource_contracts_remain_authorized(self) -> None:
        cases = (
            ("windows.event.system", "event_channel", "windows:event:System", "read"),
            ("windows.printer.queue", "print_queue", "windows:printer:queue", "read"),
            ("system.platform.identify", "system_inventory", "local:platform", "read"),
            ("system.resource.snapshot", "performance_snapshot", "local:resources", "read"),
            ("system.storage.capacity", "filesystem_capacity", "local:storage:default", "read"),
            ("network.interface.snapshot", "network_config", "local:interfaces", "read"),
            ("network.ipconfig.snapshot", "network_config", "local:ipconfig", "read"),
            ("network.route.snapshot", "network_config", "local:routes", "read"),
            ("network.dns.snapshot", "network_config", "local:dns", "read"),
            ("time.sync.status", "time_config", "local:time-sync", "read"),
            ("windows.group_policy.result", "group_policy", "local:gpresult:user", "read"),
            ("identity.session.snapshot", "identity_session", "local:identity:current", "read"),
            ("audio.devices.snapshot", "audio_devices", "local:audio:devices", "read"),
            ("process.top.snapshot", "process_inventory", "local:processes:top", "read"),
            ("hardware.usb.snapshot", "usb_devices", "local:usb:devices", "read"),
            ("camera.devices.snapshot", "camera_devices", "local:camera:devices", "read"),
        )
        for tool_id, kind, ref, effect in cases:
            with self.subTest(tool_id=tool_id):
                self.assertTrue(
                    self._authority(tool_id).require(
                        tool_id,
                        resource_kind=kind,
                        resource_ref=ref,
                        effect=effect,
                    ).allowed
                )

    def test_wrong_local_resource_kind_fails_closed(self) -> None:
        authority = self._authority("camera.devices.snapshot")
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "RESOURCE_KIND_NOT_AUTHORIZED",
        ):
            authority.require(
                "camera.devices.snapshot",
                resource_kind="filesystem_capacity",
                resource_ref="local:camera:devices",
                effect="read",
            )

    def test_wrong_local_resource_ref_fails_closed(self) -> None:
        authority = self._authority("process.top.snapshot")
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "RESOURCE_REF_NOT_AUTHORIZED",
        ):
            authority.require(
                "process.top.snapshot",
                resource_kind="process_inventory",
                resource_ref="local:processes:all",
                effect="read",
            )

    def test_service_resource_is_dynamic_but_strictly_bounded(self) -> None:
        authority = self._authority("service.status.read")
        self.assertTrue(
            authority.require(
                "service.status.read",
                resource_kind="service",
                resource_ref="local:service:sshd.service",
                effect="read",
            ).allowed
        )
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "RESOURCE_REF_NOT_AUTHORIZED",
        ):
            authority.require(
                "service.status.read",
                resource_kind="service",
                resource_ref="local:service:../../secret",
                effect="read",
            )

    def test_group_policy_scope_is_closed_to_reviewed_values(self) -> None:
        authority = self._authority("windows.group_policy.result")
        self.assertTrue(
            authority.require(
                "windows.group_policy.result",
                resource_kind="group_policy",
                resource_ref="local:gpresult:computer",
                effect="read",
            ).allowed
        )
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "RESOURCE_REF_NOT_AUTHORIZED",
        ):
            authority.require(
                "windows.group_policy.result",
                resource_kind="group_policy",
                resource_ref="local:gpresult:domain",
                effect="read",
            )

    def test_private_network_endpoint_and_tool_specific_suffix_are_required(self) -> None:
        authority = self._authority("network.quality.internal")
        self.assertTrue(
            authority.require(
                "network.quality.internal",
                resource_kind="network_endpoint",
                resource_ref="192.168.11.10:icmp-quality",
                effect="network_read",
            ).allowed
        )
        for ref in (
            "8.8.8.8:icmp-quality",
            "192.168.11.10:icmp",
            "example.com:icmp-quality",
        ):
            with self.subTest(ref=ref):
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied,
                    "RESOURCE_REF_NOT_AUTHORIZED",
                ):
                    authority.require(
                        "network.quality.internal",
                        resource_kind="network_endpoint",
                        resource_ref=ref,
                        effect="network_read",
                    )

    def test_office_network_probe_is_pinned_to_private_ip_and_fixed_port(self) -> None:
        authority = self._authority("network.ssh.probe")
        self.assertTrue(
            authority.require(
                "network.ssh.probe",
                resource_kind="network_endpoint",
                resource_ref="10.0.0.8:22",
                effect="network_read",
            ).allowed
        )
        for ref in ("10.0.0.8:23", "1.1.1.1:22", "host.local:22"):
            with self.subTest(ref=ref):
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied,
                    "RESOURCE_REF_NOT_AUTHORIZED",
                ):
                    authority.require(
                        "network.ssh.probe",
                        resource_kind="network_endpoint",
                        resource_ref=ref,
                        effect="network_read",
                    )


if __name__ == "__main__":
    unittest.main()
