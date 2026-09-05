import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.security_monitoring.ai_analyst import LocalAIAnalyst
from three_agent.security_monitoring.capability_registry import SecurityCapabilityRegistry
from three_agent.security_monitoring.collectors import CollectorResult
from three_agent.security_monitoring.contracts import AssetInventoryRecord, SecretReference
from three_agent.security_monitoring.dispatch import DefaultCollectorDispatcher
from three_agent.security_monitoring.operation_binding import SecurityOperationHandlerUnbound
from three_agent.security_monitoring.operation_invocation import (
    AnalystInvocationRequest,
    CollectorInvocationRequest,
    DNSAnalysisInvocationRequest,
    PassiveTelemetryInvocationRequest,
    SecurityOperationInvocationDenied,
    SecurityOperationInvoker,
)
from three_agent.security_monitoring.operation_plan import (
    SecurityOperationPlan,
    SecurityOperationPlanCompiler,
    SecurityOperationPlanError,
    SecurityOperationStep,
)
from three_agent.security_monitoring.passive_sensors import (
    PassiveJsonlSensorAdapter,
    PassiveSensorBatch,
    PassiveSensorConfig,
)
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine
from three_agent.security_monitoring.reporting import DeterministicReport, PeriodSummary


class _FakeSnmpBackend:
    def read_interface_counters(self, *, target_host, credential_ref, timeout_seconds):
        self.last_call = (target_host, credential_ref.handle, timeout_seconds)
        return [
            {
                "interface": "eth0",
                "rx_bytes": 100,
                "tx_bytes": 200,
                "rx_errors": 0,
                "tx_errors": 0,
                "speed_bps": 1_000_000_000,
            }
        ]


class _NeverCalledClient:
    def generate_json(self, *args, **kwargs):  # pragma: no cover - must stay unused
        raise AssertionError("model client must not be called when enabled=False")


def _period(label):
    return PeriodSummary(
        label=label,
        starts_at="2026-09-01T00:00:00+00:00",
        ends_at="2026-09-02T00:00:00+00:00",
        hourly_runs=0,
        average_coverage_pct=None,
        event_count=0,
        finding_count=0,
        open_high_critical=0,
        severity_counts={},
        finding_status_counts={},
        data_gap_count=0,
        metric_summaries=(),
    )


def _report():
    return DeterministicReport(
        report_id="report-v05",
        cutoff_at="2026-09-02T00:00:00+00:00",
        generated_at="2026-09-02T00:00:01+00:00",
        today=_period("today"),
        rolling_7d=_period("rolling_7d"),
        rolling_30d=_period("rolling_30d"),
        evidence_refs=(),
        findings=(),
    )


def _plan(capability_id, operation_id):
    registry = SecurityCapabilityRegistry()
    compiler = SecurityOperationPlanCompiler(registry)
    capability, operation = registry.resolve(capability_id, operation_id)
    request_sha256 = "sha256:" + "1" * 64
    step = SecurityOperationStep(
        step_id=compiler._step_id(request_sha256, 1, capability_id, operation_id),
        sequence=1,
        taxonomy_id=capability.taxonomy_id,
        capability_id=capability_id,
        operation_id=operation_id,
        authority_level=capability.authority_level,
        authority_domain=capability.authority_domain,
        backend_capability=operation.backend_capability,
        effect=operation.effect,
        evidence_required=capability.evidence_required,
        preflight_state=("ready_internal" if capability.authority_domain == "internal" else "authority_required"),
    ).validate()
    reasons = ("TEST_REVIEWED_ROUTE", "DETERMINISTIC_OPERATION_PLAN_COMPILED")
    fingerprint = compiler._plan_fingerprint(
        request_sha256=request_sha256,
        route_status="routed",
        status="planned",
        steps=(step,),
        registry_fingerprint=registry.fingerprint,
        reason_codes=reasons,
    )
    return SecurityOperationPlan(
        request_sha256=request_sha256,
        route_status="routed",
        status="planned",
        steps=(step,),
        registry_fingerprint=registry.fingerprint,
        plan_fingerprint=fingerprint,
        reason_codes=reasons,
    ).validate()


class SecurityOperationInvocationTests(unittest.TestCase):
    def test_dns_internal_invocation_is_bounded_and_receipted(self):
        plan = _plan("network.dns.analyze", "analyze_dns_evidence")
        invoker = SecurityOperationInvoker()
        request = DNSAnalysisInvocationRequest(
            event_id="dns-v05-1",
            source_type="suricata_eve",
            raw_line=json.dumps(
                {
                    "event_type": "dns",
                    "dns": {
                        "rrname": "example.com",
                        "rrtype": "A",
                        "rcode": "NOERROR",
                        "answers": [{"rdata": "192.0.2.10"}],
                    },
                }
            ),
        )
        result = invoker.invoke(plan, step_id=plan.steps[0].step_id, request=request)
        self.assertEqual(result.output.query_length, len("example.com"))
        self.assertEqual(result.receipt.handler_id, "analysis.dns_behavior.extract_features")
        self.assertEqual(result.receipt.authority_domain, "internal")
        self.assertEqual(result.receipt.authority_reason_code, "SECURITY_INTERNAL_OPERATION_AUTHORIZED")
        self.assertEqual(result.receipt.status, "completed")

    def test_tampered_plan_fingerprint_fails_before_handler(self):
        plan = _plan("network.dns.analyze", "analyze_dns_evidence")
        tampered = replace(plan, plan_fingerprint="sha256:" + "f" * 64)
        request = DNSAnalysisInvocationRequest(
            event_id="dns-v05-2",
            source_type="zeek_json",
            raw_line=json.dumps({"_path": "dns", "query": "example.org", "qtype_name": "A"}),
        )
        with self.assertRaisesRegex(SecurityOperationPlanError, "INVOCATION_PLAN_FINGERPRINT_TAMPERED"):
            SecurityOperationInvoker().invoke(tampered, step_id=tampered.steps[0].step_id, request=request)

    def test_tampered_step_id_fails_integrity_check(self):
        plan = _plan("network.dns.analyze", "analyze_dns_evidence")
        bad_step = replace(plan.steps[0], step_id="step:" + "a" * 24)
        compiler = SecurityOperationPlanCompiler(SecurityCapabilityRegistry())
        fingerprint = compiler._plan_fingerprint(
            request_sha256=plan.request_sha256,
            route_status=plan.route_status,
            status=plan.status,
            steps=(bad_step,),
            registry_fingerprint=plan.registry_fingerprint,
            reason_codes=plan.reason_codes,
        )
        tampered = replace(plan, steps=(bad_step,), plan_fingerprint=fingerprint)
        request = DNSAnalysisInvocationRequest(
            event_id="dns-v05-3",
            source_type="zeek_json",
            raw_line=json.dumps({"_path": "dns", "query": "example.net", "qtype_name": "A"}),
        )
        with self.assertRaisesRegex(SecurityOperationPlanError, "INVOCATION_PLAN_STEP_ID_TAMPERED"):
            SecurityOperationInvoker().invoke(tampered, step_id=bad_step.step_id, request=request)

    def test_unbound_operation_cannot_reach_invocation_runtime(self):
        plan = _plan("network.pcap.read", "read_capture")
        request = CollectorInvocationRequest(
            asset_id="asset-a",
            run_id="run-a",
            observed_at="2026-09-02T00:00:00+00:00",
        )
        with self.assertRaises(SecurityOperationHandlerUnbound):
            SecurityOperationInvoker().invoke(plan, step_id=plan.steps[0].step_id, request=request)

    def test_local_counter_invocation_reauthorizes_inventory_and_dispatcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_path = Path(tmp) / "netdev"
            proc_path.write_text(
                "Inter-| Receive | Transmit\n"
                " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
                " eth0: 100 2 0 0 0 0 0 0 200 3 0 0 0 0 0 0\n",
                encoding="utf-8",
            )
            asset = AssetInventoryRecord(
                asset_id="asset-local",
                role="server",
                management_host="127.0.0.1",
                collector_capabilities=("local_net_read",),
            ).validate()
            engine = MonitoringPolicyEngine(MonitoringPolicy())
            dispatcher = DefaultCollectorDispatcher(engine, proc_net_path=proc_path)
            invoker = SecurityOperationInvoker(
                monitoring_engine=engine,
                dispatcher=dispatcher,
                assets=(asset,),
            )
            plan = _plan("network.flow.observe", "read_local_flow_evidence")
            result = invoker.invoke(
                plan,
                step_id=plan.steps[0].step_id,
                request=CollectorInvocationRequest(
                    asset_id=asset.asset_id,
                    run_id="run-local-v05",
                    observed_at="2026-09-02T00:00:00+00:00",
                ),
            )
            self.assertIsInstance(result.output, CollectorResult)
            self.assertEqual(len(result.output.observations), 8)
            self.assertEqual(result.receipt.authority_reason_code, "SECURITY_MONITORING_AUTHORITY_CONFIRMED")
            self.assertEqual(result.receipt.handler_id, "monitoring.dispatch.local_net_read")

    def test_snmp_invocation_uses_inventory_credential_not_request_credential(self):
        backend = _FakeSnmpBackend()
        secret = SecretReference("secret-ref:snmp-v05").validate()
        asset = AssetInventoryRecord(
            asset_id="asset-snmp",
            role="switch",
            management_host="192.0.2.5",
            collector_capabilities=("snmpv3_read",),
            credential_ref=secret,
        ).validate()
        engine = MonitoringPolicyEngine(MonitoringPolicy())
        dispatcher = DefaultCollectorDispatcher(engine, snmp_backend=backend)
        invoker = SecurityOperationInvoker(
            monitoring_engine=engine,
            dispatcher=dispatcher,
            assets=(asset,),
        )
        plan = _plan("network.interface.observe", "read_interface_counters")
        result = invoker.invoke(
            plan,
            step_id=plan.steps[0].step_id,
            request=CollectorInvocationRequest(
                asset_id=asset.asset_id,
                run_id="run-snmp-v05",
                observed_at="2026-09-02T00:00:00+00:00",
            ),
        )
        self.assertIsInstance(result.output, CollectorResult)
        self.assertEqual(backend.last_call[1], "secret-ref:snmp-v05")
        self.assertEqual(result.receipt.handler_id, "monitoring.dispatch.snmpv3_read")
        self.assertNotIn("credential", CollectorInvocationRequest.__dataclass_fields__)
        self.assertNotIn("target_host", CollectorInvocationRequest.__dataclass_fields__)

    def test_unknown_asset_is_denied_before_dispatch(self):
        asset = AssetInventoryRecord(
            asset_id="asset-known",
            role="server",
            management_host="127.0.0.1",
            collector_capabilities=("local_net_read",),
        ).validate()
        engine = MonitoringPolicyEngine(MonitoringPolicy())
        dispatcher = DefaultCollectorDispatcher(engine)
        invoker = SecurityOperationInvoker(
            monitoring_engine=engine,
            dispatcher=dispatcher,
            assets=(asset,),
        )
        plan = _plan("network.flow.observe", "read_local_flow_evidence")
        with self.assertRaisesRegex(SecurityOperationInvocationDenied, "INVOCATION_ASSET_NOT_IN_TRUSTED_INVENTORY"):
            invoker.invoke(
                plan,
                step_id=plan.steps[0].step_id,
                request=CollectorInvocationRequest(
                    asset_id="asset-unknown",
                    run_id="run-x",
                    observed_at="2026-09-02T00:00:00+00:00",
                ),
            )

    def test_passive_telemetry_uses_preconfigured_path_and_asset_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry = Path(tmp) / "flow.jsonl"
            telemetry.write_text(
                json.dumps(
                    {
                        "flow_type": "netflow",
                        "timestamp": "2026-09-02T00:00:00+00:00",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            adapter = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="flow-source-v05",
                    source_type="flow_json",
                    path=telemetry,
                    enabled=True,
                )
            )
            asset = AssetInventoryRecord(
                asset_id="asset-flow-source",
                role="sensor",
                management_host="127.0.0.1",
                collector_capabilities=("fixed_readonly_adapter",),
            ).validate()
            engine = MonitoringPolicyEngine(MonitoringPolicy())
            invoker = SecurityOperationInvoker(
                monitoring_engine=engine,
                assets=(asset,),
                passive_adapters={"flow-source-v05": adapter},
                passive_source_assets={"flow-source-v05": asset.asset_id},
            )
            plan = _plan("security.telemetry.observe", "read_fixed_telemetry")
            result = invoker.invoke(
                plan,
                step_id=plan.steps[0].step_id,
                request=PassiveTelemetryInvocationRequest(
                    asset_id=asset.asset_id,
                    source_id="flow-source-v05",
                    evaluated_at="2026-09-02T00:00:01+00:00",
                ),
            )
            self.assertIsInstance(result.output, PassiveSensorBatch)
            self.assertEqual(len(result.output.events), 1)
            self.assertNotIn("path", PassiveTelemetryInvocationRequest.__dataclass_fields__)
            self.assertEqual(result.receipt.handler_id, "monitoring.passive_jsonl.read_batch")

    def test_passive_source_cannot_be_rebound_by_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry = Path(tmp) / "flow.jsonl"
            telemetry.write_text("", encoding="utf-8")
            adapter = PassiveJsonlSensorAdapter(
                PassiveSensorConfig(
                    source_id="flow-source-bound",
                    source_type="flow_json",
                    path=telemetry,
                    enabled=True,
                )
            )
            asset_a = AssetInventoryRecord(
                asset_id="asset-a",
                role="sensor",
                management_host="127.0.0.1",
                collector_capabilities=("fixed_readonly_adapter",),
            ).validate()
            asset_b = AssetInventoryRecord(
                asset_id="asset-b",
                role="sensor",
                management_host="127.0.0.2",
                collector_capabilities=("fixed_readonly_adapter",),
            ).validate()
            engine = MonitoringPolicyEngine(MonitoringPolicy())
            invoker = SecurityOperationInvoker(
                monitoring_engine=engine,
                assets=(asset_a, asset_b),
                passive_adapters={"flow-source-bound": adapter},
                passive_source_assets={"flow-source-bound": asset_a.asset_id},
            )
            plan = _plan("security.telemetry.observe", "read_fixed_telemetry")
            with self.assertRaisesRegex(SecurityOperationInvocationDenied, "INVOCATION_PASSIVE_SOURCE_ASSET_MISMATCH"):
                invoker.invoke(
                    plan,
                    step_id=plan.steps[0].step_id,
                    request=PassiveTelemetryInvocationRequest(
                        asset_id=asset_b.asset_id,
                        source_id="flow-source-bound",
                        evaluated_at="2026-09-02T00:00:01+00:00",
                    ),
                )

    def test_local_ai_analyst_is_trusted_dependency_and_remains_advisory(self):
        analyst = LocalAIAnalyst(_NeverCalledClient())
        invoker = SecurityOperationInvoker(analyst=analyst)
        plan = _plan("security.incident_triage.analyze", "triage_findings")
        result = invoker.invoke(
            plan,
            step_id=plan.steps[0].step_id,
            request=AnalystInvocationRequest(report=_report(), enabled=False),
        )
        self.assertEqual(result.output.status, "not_requested")
        self.assertEqual(result.output.model_calls, 0)
        self.assertEqual(result.receipt.authority_domain, "internal")
        self.assertEqual(result.receipt.handler_id, "analysis.local_ai_analyst.analyze")

    def test_handler_request_type_mismatch_fails_closed(self):
        plan = _plan("network.dns.analyze", "analyze_dns_evidence")
        with self.assertRaisesRegex(SecurityOperationInvocationDenied, "INVOCATION_REQUEST_TYPE_MISMATCH"):
            SecurityOperationInvoker().invoke(
                plan,
                step_id=plan.steps[0].step_id,
                request=CollectorInvocationRequest(
                    asset_id="asset-a",
                    run_id="run-a",
                    observed_at="2026-09-02T00:00:00+00:00",
                ),
            )

    def test_monitoring_handler_requires_policy_engine(self):
        asset = AssetInventoryRecord(
            asset_id="asset-local",
            role="server",
            management_host="127.0.0.1",
            collector_capabilities=("local_net_read",),
        ).validate()
        plan = _plan("network.flow.observe", "read_local_flow_evidence")
        invoker = SecurityOperationInvoker(assets=(asset,))
        with self.assertRaisesRegex(SecurityOperationInvocationDenied, "INVOCATION_MONITORING_ENGINE_REQUIRED"):
            invoker.invoke(
                plan,
                step_id=plan.steps[0].step_id,
                request=CollectorInvocationRequest(
                    asset_id=asset.asset_id,
                    run_id="run-a",
                    observed_at="2026-09-02T00:00:00+00:00",
                ),
            )

    def test_dns_raw_evidence_is_hard_bounded(self):
        request = DNSAnalysisInvocationRequest(
            event_id="dns-large",
            source_type="zeek_json",
            raw_line="x" * (256 * 1024 + 1),
        )
        with self.assertRaisesRegex(ValueError, "bounded size"):
            request.validate()

    def test_runtime_fingerprint_is_deterministic_and_opaque(self):
        invoker = SecurityOperationInvoker()
        first = invoker.runtime_fingerprint
        second = invoker.runtime_fingerprint
        self.assertEqual(first, second)
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
