import unittest

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.security_monitoring.capability_registry import (
    AUTHORITY_LEVELS,
    SECURITY_TAXONOMY,
    CuratedSecurityOperation,
    SecurityCapability,
    SecurityCapabilityDenied,
    SecurityCapabilityError,
    SecurityCapabilityRegistry,
)
from three_agent.security_monitoring.contracts import AssetInventoryRecord, SecretReference
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine
from three_agent.task_contract import TaskContractCompiler


class SecurityCapabilityRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = SecurityCapabilityRegistry()

    def test_taxonomy_is_closed_and_contains_blueprint_domains(self):
        self.assertIn("network.pcap", SECURITY_TAXONOMY)
        self.assertIn("security.incident_triage", SECURITY_TAXONOMY)
        self.assertIn("security.vulnerability_assessment", SECURITY_TAXONOMY)
        self.assertEqual(AUTHORITY_LEVELS, frozenset({"L0", "L1", "L2", "L3"}))

    def test_v01_defaults_are_only_l0_l1_and_expose_no_offensive_backend(self):
        caps = self.registry.list_approved()
        self.assertTrue(caps)
        self.assertTrue(all(cap.authority_level in {"L0", "L1"} for cap in caps))
        exposed_parts = []
        for cap in caps:
            exposed_parts.extend((cap.capability_id, cap.taxonomy_id))
            for operation in cap.operations:
                exposed_parts.append(operation.operation_id)
                exposed_parts.append(operation.backend_capability or "")
        exposed = " ".join(exposed_parts).lower()
        for forbidden in (
            "ddos",
            "payload",
            "phishing",
            "sqlmap",
            "metasploit",
            "hashcat",
            "nmap",
            "icmp_echo",
            "tcp_connect",
        ):
            self.assertNotIn(forbidden, exposed)

    def test_taxonomy_routing_only_returns_reviewed_capabilities(self):
        rows = self.registry.capabilities_for_taxonomy("network.flow")
        self.assertEqual(
            {row.capability_id for row in rows},
            {"network.flow.observe", "network.flow.analyze"},
        )
        with self.assertRaisesRegex(SecurityCapabilityError, "unknown taxonomy_id"):
            self.registry.capabilities_for_taxonomy("network.shell")

    def test_unknown_or_uncurated_operation_fails_closed(self):
        with self.assertRaisesRegex(
            SecurityCapabilityDenied,
            "SECURITY_CAPABILITY_UNKNOWN",
        ):
            self.registry.resolve("security.not-real", "do_anything")
        with self.assertRaisesRegex(
            SecurityCapabilityDenied,
            "SECURITY_OPERATION_NOT_CURATED",
        ):
            self.registry.resolve("network.pcap.read", "shell_command")

    def test_internal_analysis_is_registry_authorized_without_backend_execution(self):
        authorization = self.registry.authorize_internal(
            "security.incident_triage.analyze",
            "triage_findings",
        )
        self.assertTrue(authorization.allowed)
        self.assertEqual(authorization.authority_domain, "internal")
        self.assertEqual(authorization.backend_capability, "internal_compute")
        self.assertEqual(authorization.effect, "compute")
        self.assertTrue(authorization.authority_fingerprint.startswith("sha256:"))

    def test_task_bridge_reuses_existing_task_capability_authority(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PCAP",
            task_type="analysis",
            sensitivity="internal",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        authorization = self.registry.require_task_authority(
            authority,
            "network.pcap.read",
            "read_capture",
            resource_kind="path",
            resource_ref="evidence/capture.pcap",
        )
        self.assertTrue(authorization.allowed)
        self.assertEqual(authorization.backend_capability, "read_file")
        self.assertEqual(authorization.reason_code, "SECURITY_TASK_AUTHORITY_CONFIRMED")

    def test_task_bridge_cannot_mint_missing_task_authority(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-NO-READ",
            task_type="classification",
            sensitivity="internal",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_NOT_ALLOWED",
        ):
            self.registry.require_task_authority(
                authority,
                "network.pcap.read",
                "read_capture",
                resource_kind="path",
                resource_ref="evidence/capture.pcap",
            )

    def test_monitoring_bridge_reuses_inventory_and_policy_authority(self):
        credential = SecretReference("secret-ref:router-snmp")
        asset = AssetInventoryRecord(
            asset_id="router-01",
            role="router",
            management_host="192.168.11.1",
            collector_capabilities=("snmpv3_read",),
            credential_ref=credential,
        ).validate()
        engine = MonitoringPolicyEngine(MonitoringPolicy())
        authorization = self.registry.require_monitoring_authority(
            engine,
            asset,
            "network.interface.observe",
            "read_interface_counters",
            target_host="192.168.11.1",
            credential_ref=credential,
        )
        self.assertTrue(authorization.allowed)
        self.assertEqual(authorization.backend_capability, "snmpv3_read")
        self.assertEqual(
            authorization.reason_code,
            "SECURITY_MONITORING_AUTHORITY_CONFIRMED",
        )

    def test_monitoring_bridge_cannot_expand_inventory_target(self):
        credential = SecretReference("secret-ref:router-snmp")
        asset = AssetInventoryRecord(
            asset_id="router-01",
            role="router",
            management_host="192.168.11.1",
            collector_capabilities=("snmpv3_read",),
            credential_ref=credential,
        ).validate()
        engine = MonitoringPolicyEngine(MonitoringPolicy())
        with self.assertRaisesRegex(PermissionError, "TARGET_NOT_APPROVED"):
            self.registry.require_monitoring_authority(
                engine,
                asset,
                "network.interface.observe",
                "read_interface_counters",
                target_host="192.168.11.254",
                credential_ref=credential,
            )

    def test_wrong_authority_domain_fails_closed(self):
        with self.assertRaisesRegex(
            SecurityCapabilityDenied,
            "SECURITY_AUTHORITY_DOMAIN_MISMATCH",
        ):
            self.registry.authorize_internal("network.pcap.read", "read_capture")

    def test_custom_capability_rejects_unknown_taxonomy(self):
        capability = SecurityCapability(
            capability_id="custom.invalid",
            taxonomy_id="security.anything",
            name="Invalid",
            authority_level="L1",
            authority_domain="internal",
            operations=(CuratedSecurityOperation("analyze", "compute"),),
        )
        with self.assertRaisesRegex(SecurityCapabilityError, "unknown taxonomy_id"):
            capability.validate()


if __name__ == "__main__":
    unittest.main()
