import unittest
from dataclasses import replace

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.security_monitoring.capability_registry import (
    SecurityCapabilityDenied,
    SecurityCapabilityRegistry,
)
from three_agent.security_monitoring.capability_router import SecurityCapabilityRouter
from three_agent.security_monitoring.contracts import AssetInventoryRecord, SecretReference
from three_agent.security_monitoring.operation_plan import (
    SecurityOperationPlanCompiler,
    SecurityOperationPlanError,
)
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine
from three_agent.task_contract import TaskContractCompiler


class SecurityOperationPlanTests(unittest.TestCase):
    def setUp(self):
        self.registry = SecurityCapabilityRegistry()
        self.router = SecurityCapabilityRouter(self.registry)
        self.compiler = SecurityOperationPlanCompiler(self.registry)

    def test_internal_route_compiles_to_ready_compute_step(self):
        decision = self.router.route("analyze DNS evidence for unusual domain behavior")
        plan = self.compiler.compile(decision)
        self.assertEqual(plan.status, "planned")
        self.assertEqual(len(plan.steps), 1)
        step = plan.steps[0]
        self.assertEqual(step.capability_id, "network.dns.analyze")
        self.assertEqual(step.operation_id, "analyze_dns_evidence")
        self.assertEqual(step.authority_domain, "internal")
        self.assertEqual(step.preflight_state, "ready_internal")
        self.assertEqual(step.effect, "compute")
        self.assertIsNone(step.backend_capability)
        authorization = self.compiler.authorize_internal_step(step)
        self.assertTrue(authorization.allowed)
        self.assertEqual(authorization.backend_capability, "internal_compute")

    def test_pcap_plan_preserves_safe_step_order_and_authority_boundary(self):
        decision = self.router.route("analyze this PCAP packet capture for suspicious flows")
        plan = self.compiler.compile(decision)
        self.assertEqual(
            [(step.capability_id, step.operation_id) for step in plan.steps],
            [
                ("network.pcap.read", "read_capture"),
                ("network.flow.analyze", "analyze_flow_evidence"),
            ],
        )
        self.assertEqual(plan.steps[0].authority_domain, "task")
        self.assertEqual(plan.steps[0].preflight_state, "authority_required")
        self.assertEqual(plan.steps[0].backend_capability, "read_file")
        self.assertEqual(plan.steps[1].authority_domain, "internal")
        self.assertEqual(plan.steps[1].preflight_state, "ready_internal")
        self.assertFalse(plan.auto_execute)
        self.assertEqual(plan.authority, "advisory")

    def test_task_step_reuses_existing_task_authority_and_cannot_mint_it(self):
        plan = self.compiler.compile(self.router.route("analyze this PCAP capture file"))
        task_step = plan.steps[0]

        allowed_contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-READ",
            task_type="analysis",
            sensitivity="internal",
        )
        allowed = TaskCapabilityAuthority.from_contract(allowed_contract)
        authorization = self.compiler.require_task_step_authority(
            allowed,
            task_step,
            resource_kind="path",
            resource_ref="evidence/capture.pcap",
        )
        self.assertTrue(authorization.allowed)
        self.assertEqual(authorization.backend_capability, "read_file")

        denied_contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-DENY",
            task_type="classification",
            sensitivity="internal",
        )
        denied = TaskCapabilityAuthority.from_contract(denied_contract)
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
            self.compiler.require_task_step_authority(
                denied,
                task_step,
                resource_kind="path",
                resource_ref="evidence/capture.pcap",
            )

    def test_monitoring_step_requires_existing_inventory_and_policy_authority(self):
        decision = self.router.route("diagnose packet loss from interface error and drop counter")
        plan = self.compiler.compile(decision)
        step = plan.steps[0]
        self.assertEqual(step.authority_domain, "monitoring")
        self.assertEqual(step.backend_capability, "snmpv3_read")
        credential = SecretReference("secret-ref:router-snmp")
        asset = AssetInventoryRecord(
            asset_id="router-01",
            role="router",
            management_host="192.168.11.1",
            collector_capabilities=("snmpv3_read",),
            credential_ref=credential,
        ).validate()
        engine = MonitoringPolicyEngine(MonitoringPolicy())
        authorization = self.compiler.require_monitoring_step_authority(
            engine,
            asset,
            step,
            target_host="192.168.11.1",
            credential_ref=credential,
        )
        self.assertTrue(authorization.allowed)
        self.assertEqual(authorization.backend_capability, "snmpv3_read")

        with self.assertRaisesRegex(PermissionError, "TARGET_NOT_APPROVED"):
            self.compiler.require_monitoring_step_authority(
                engine,
                asset,
                step,
                target_host="192.168.11.254",
                credential_ref=credential,
            )

    def test_denied_and_no_route_decisions_never_gain_steps(self):
        denied = self.compiler.compile(self.router.route("run nmap against 192.168.1.0/24"))
        self.assertEqual(denied.status, "denied")
        self.assertEqual(denied.steps, ())
        self.assertIn("PLAN_DENIED_BY_ROUTER", denied.reason_codes)

        no_route = self.compiler.compile(self.router.route("prepare lunch meeting notes"))
        self.assertEqual(no_route.status, "no_route")
        self.assertEqual(no_route.steps, ())
        self.assertIn("PLAN_HAS_NO_APPROVED_ROUTE", no_route.reason_codes)

    def test_stale_registry_fingerprint_fails_closed(self):
        decision = self.router.route("analyze DNS evidence")
        stale = replace(decision, registry_fingerprint="sha256:" + "0" * 64)
        with self.assertRaisesRegex(
            SecurityOperationPlanError,
            "ROUTING_REGISTRY_FINGERPRINT_MISMATCH",
        ):
            self.compiler.compile(stale)

    def test_tampered_selection_cannot_change_taxonomy_or_authority(self):
        decision = self.router.route("analyze DNS evidence")
        selection = decision.selections[0]
        wrong_taxonomy = replace(selection, taxonomy_id="security.authentication")
        with self.assertRaisesRegex(
            SecurityCapabilityDenied,
            "PLAN_TAXONOMY_CAPABILITY_MISMATCH",
        ):
            self.compiler.compile(replace(decision, selections=(wrong_taxonomy,)))

        wrong_domain = replace(selection, authority_domain="monitoring")
        with self.assertRaisesRegex(
            SecurityOperationPlanError,
            "PLAN_AUTHORITY_DOMAIN_MISMATCH",
        ):
            self.compiler.compile(replace(decision, selections=(wrong_domain,)))

    def test_plan_is_deterministic_and_does_not_expose_raw_request_or_commands(self):
        request = "Điều tra sự cố và xây dựng incident timeline từ evidence"
        first = self.compiler.compile(self.router.route(request))
        second = self.compiler.compile(self.router.route(request))
        self.assertEqual(first, second)
        self.assertRegex(first.plan_fingerprint, r"^sha256:[0-9a-f]{64}$")
        rendered = repr(first.public_dict()).lower()
        self.assertNotIn(request.lower(), rendered)
        for forbidden in ("argv", "shell", "command", "password", "credential_ref"):
            self.assertNotIn(forbidden, rendered)

    def test_plan_validate_rejects_step_content_tamper_with_stale_step_id(self):
        plan = self.compiler.compile(self.router.route("analyze DNS evidence"))
        tampered_step = replace(plan.steps[0], capability_id="network.flow.analyze")
        tampered_plan = replace(plan, steps=(tampered_step,))
        with self.assertRaisesRegex(
            SecurityOperationPlanError,
            "step_id does not match deterministic content",
        ):
            tampered_plan.validate()

    def test_plan_validate_rejects_content_tamper_with_stale_plan_fingerprint(self):
        plan = self.compiler.compile(self.router.route("analyze DNS evidence"))
        tampered_plan = replace(
            plan,
            reason_codes=plan.reason_codes + ("TAMPERED_REASON",),
        )
        with self.assertRaisesRegex(
            SecurityOperationPlanError,
            "plan_fingerprint does not match canonical plan content",
        ):
            tampered_plan.validate()

    def test_wrong_authority_helper_fails_closed(self):
        internal_plan = self.compiler.compile(self.router.route("analyze DNS evidence"))
        with self.assertRaisesRegex(
            SecurityCapabilityDenied,
            "PLAN_STEP_AUTHORITY_DOMAIN_MISMATCH",
        ):
            contract = TaskContractCompiler().compile(
                task_id="TASK-WRONG-DOMAIN",
                task_type="analysis",
                sensitivity="internal",
            )
            self.compiler.require_task_step_authority(
                TaskCapabilityAuthority.from_contract(contract),
                internal_plan.steps[0],
                resource_kind="path",
                resource_ref="evidence/dns.jsonl",
            )


if __name__ == "__main__":
    unittest.main()
