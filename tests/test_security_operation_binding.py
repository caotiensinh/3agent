import unittest

from three_agent.security_monitoring.capability_registry import (
    SecurityCapabilityRegistry,
)
from three_agent.security_monitoring.capability_router import SecurityCapabilityRouter
from three_agent.security_monitoring.operation_binding import (
    CLOSED_HANDLER_IDS,
    DEFAULT_SECURITY_OPERATION_BINDINGS,
    SecurityOperationBinding,
    SecurityOperationBindingError,
    SecurityOperationBindingRegistry,
    SecurityOperationHandlerUnbound,
    reviewed_runtime_handler_exists,
    verify_reviewed_runtime_handlers,
)
from three_agent.security_monitoring.operation_plan import SecurityOperationPlanCompiler


class SecurityOperationBindingTests(unittest.TestCase):
    def setUp(self):
        self.capabilities = SecurityCapabilityRegistry()
        self.bindings = SecurityOperationBindingRegistry(self.capabilities)
        self.router = SecurityCapabilityRouter(self.capabilities)
        self.compiler = SecurityOperationPlanCompiler(self.capabilities)

    def test_manifest_has_exact_approved_operation_coverage(self):
        expected = {
            (capability.capability_id, operation.operation_id)
            for capability in self.capabilities.list_approved()
            for operation in capability.operations
        }
        actual = {
            (binding.capability_id, binding.operation_id)
            for binding in DEFAULT_SECURITY_OPERATION_BINDINGS
        }
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 15)

    def test_binding_coverage_is_measured_and_explicit(self):
        coverage = self.bindings.coverage()
        self.assertEqual(coverage.total_operations, 15)
        self.assertEqual(coverage.bound_operations, 5)
        self.assertEqual(coverage.unbound_operations, 10)
        self.assertEqual(coverage.bound_percent, 33.333)
        self.assertEqual(len(coverage.unbound_operation_refs), 10)
        self.assertRegex(coverage.binding_fingerprint, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(coverage.registry_fingerprint, self.capabilities.fingerprint)

    def test_every_bound_handler_has_a_direct_reviewed_runtime_target(self):
        attestation = verify_reviewed_runtime_handlers(self.bindings)
        self.assertEqual(set(attestation), set(CLOSED_HANDLER_IDS))
        self.assertTrue(all(attestation.values()))
        self.assertFalse(reviewed_runtime_handler_exists("analysis.dynamic.import"))

    def test_bound_metadata_exposes_symbolic_ids_not_commands_or_import_paths(self):
        payload = repr(
            [
                binding.public_dict()
                for binding in DEFAULT_SECURITY_OPERATION_BINDINGS
                if binding.status == "bound"
            ]
        ).lower()
        for forbidden in (
            "argv",
            "shell",
            "subprocess",
            "importlib",
            "__import__",
            "three_agent.",
            "nmap",
            "metasploit",
            "sqlmap",
            "hashcat",
        ):
            self.assertNotIn(forbidden, payload)

    def test_unbound_operation_fails_closed_with_specific_debt_reason(self):
        binding = self.bindings.resolve("network.pcap.read", "read_capture")
        self.assertEqual(binding.status, "unbound")
        self.assertEqual(
            binding.reason_code,
            "UNBOUND_PCAP_EVIDENCE_READ_ADAPTER_REQUIRED",
        )
        with self.assertRaisesRegex(
            SecurityOperationHandlerUnbound,
            "UNBOUND_PCAP_EVIDENCE_READ_ADAPTER_REQUIRED",
        ):
            self.bindings.require_bound("network.pcap.read", "read_capture")

    def test_dns_plan_binds_to_reviewed_pure_function_without_execution_authority(self):
        plan = self.compiler.compile(self.router.route("analyze DNS evidence"))
        result = self.bindings.bind_plan(plan)
        self.assertEqual(result.status, "all_bound")
        self.assertFalse(result.execution_authorized)
        self.assertEqual(result.authority, "advisory")
        self.assertEqual(len(result.steps), 1)
        step = result.steps[0]
        self.assertEqual(step.handler_id, "analysis.dns_behavior.extract_features")
        self.assertEqual(step.handler_kind, "pure_function")

    def test_network_monitoring_plan_binds_only_to_existing_readonly_handlers(self):
        plan = self.compiler.compile(
            self.router.route("network monitoring from local flow and security telemetry")
        )
        result = self.bindings.bind_plan(plan)
        self.assertEqual(result.status, "all_bound")
        self.assertEqual(
            {step.handler_id for step in result.steps},
            {
                "monitoring.dispatch.local_net_read",
                "monitoring.passive_jsonl.read_batch",
            },
        )
        self.assertFalse(result.execution_authorized)

    def test_pcap_plan_is_partial_instead_of_guessing_missing_handlers(self):
        plan = self.compiler.compile(
            self.router.route("analyze this PCAP packet capture for suspicious flows")
        )
        result = self.bindings.bind_plan(plan)
        self.assertEqual(result.status, "partial")
        self.assertFalse(result.execution_authorized)
        self.assertEqual(
            [(step.capability_id, step.operation_id, step.status) for step in result.steps],
            [
                ("network.pcap.read", "read_capture", "unbound"),
                ("network.flow.analyze", "analyze_flow_evidence", "unbound"),
            ],
        )

    def test_denied_route_plan_never_acquires_handlers(self):
        plan = self.compiler.compile(self.router.route("run nmap against 192.168.1.0/24"))
        result = self.bindings.bind_plan(plan)
        self.assertEqual(result.status, "not_planned")
        self.assertEqual(result.steps, ())
        self.assertFalse(result.execution_authorized)

    def test_manifest_missing_one_operation_is_rejected(self):
        with self.assertRaisesRegex(
            SecurityOperationBindingError,
            "operation binding coverage mismatch",
        ):
            SecurityOperationBindingRegistry(
                self.capabilities,
                DEFAULT_SECURITY_OPERATION_BINDINGS[:-1],
            )

    def test_unknown_handler_id_cannot_enter_bound_manifest(self):
        bad = SecurityOperationBinding(
            capability_id="network.dns.analyze",
            operation_id="analyze_dns_evidence",
            status="bound",
            reason_code="BOUND_TO_REVIEWED_RUNTIME_HANDLER",
            handler_id="analysis.dynamic.import",
            handler_kind="pure_function",
        )
        with self.assertRaisesRegex(
            SecurityOperationBindingError,
            "closed handler set",
        ):
            bad.validate()

    def test_unbound_binding_cannot_smuggle_handler_metadata(self):
        bad = SecurityOperationBinding(
            capability_id="network.flow.analyze",
            operation_id="analyze_flow_evidence",
            status="unbound",
            reason_code="UNBOUND_GENERIC_FLOW_ANALYSIS_CONTRACT_REQUIRED",
            handler_id="analysis.dns_behavior.extract_features",
            handler_kind="pure_function",
        )
        with self.assertRaisesRegex(
            SecurityOperationBindingError,
            "unbound operation cannot expose a handler",
        ):
            bad.validate()


if __name__ == "__main__":
    unittest.main()
