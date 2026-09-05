import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from three_agent.task_contract import TaskContractCompiler
from three_agent.security_monitoring.capability_registry import SecurityCapabilityRegistry
from three_agent.security_monitoring.operation_plan import (
    SecurityOperationPlan,
    SecurityOperationPlanCompiler,
    SecurityOperationStep,
)
from three_agent.security_monitoring.pcap_evidence import (
    BoundedPCAPEvidenceReader,
    PCAPEvidenceDenied,
    PCAPEvidenceError,
    PCAPResource,
    PCAPResourceRegistry,
)
from three_agent.security_monitoring.pcap_task_invocation import (
    PCAPEvidenceInvocationRequest,
    PCAPSecurityOperationBindingRegistry,
    PCAPTaskSecurityOperationInvoker,
)
from three_agent.security_monitoring.security_workflow import SecurityAnalystWorkflow
from three_agent.security_monitoring.workflow_audit import SecurityWorkflowAuditJournal


MAGIC_VARIANTS = (
    (b"\xd4\xc3\xb2\xa1", "<", "little", "microsecond", 111_222),
    (b"\xa1\xb2\xc3\xd4", ">", "big", "microsecond", 111_222),
    (b"\x4d\x3c\xb2\xa1", "<", "little", "nanosecond", 111_222_333),
    (b"\xa1\xb2\x3c\x4d", ">", "big", "nanosecond", 111_222_333),
)


def _pcap_bytes(magic, endian, fraction, payloads=(b"ABC", b"DEF012")):
    data = bytearray(magic)
    data.extend(struct.pack(endian + "HHiIII", 2, 4, 0, 0, 65535, 1))
    for index, payload in enumerate(payloads):
        ts_sec = 1_700_000_000 + index
        data.extend(struct.pack(endian + "IIII", ts_sec, fraction, len(payload), len(payload) + index))
        data.extend(payload)
    return bytes(data)


def _task_contract(*, allow_read=True):
    return TaskContractCompiler().compile(
        task_id="pcap-evidence-task-v07",
        task_type="retrieval" if allow_read else "analysis",
        sensitivity="confidential",
        risk_level="medium",
        allowed_sources=("trusted-pcap-registry",),
        allowed_tools=("read_file",) if allow_read else ("calculator",),
        deterministic_only=allow_read,
    )


def _plan(operation_id):
    registry = SecurityCapabilityRegistry()
    compiler = SecurityOperationPlanCompiler(registry)
    capability, operation = registry.resolve("network.pcap.read", operation_id)
    request_sha256 = "sha256:" + "7" * 64
    step = SecurityOperationStep(
        step_id=compiler._step_id(request_sha256, 1, capability.capability_id, operation.operation_id),
        sequence=1,
        taxonomy_id=capability.taxonomy_id,
        capability_id=capability.capability_id,
        operation_id=operation.operation_id,
        authority_level=capability.authority_level,
        authority_domain=capability.authority_domain,
        backend_capability=operation.backend_capability,
        effect=operation.effect,
        evidence_required=capability.evidence_required,
        preflight_state="authority_required",
    ).validate()
    reasons = ("TEST_PCAP_ROUTE", "DETERMINISTIC_OPERATION_PLAN_COMPILED")
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


class SecurityPCAPTaskReadTests(unittest.TestCase):
    def _registry(self, root, name="capture.pcap", **limits):
        return PCAPResourceRegistry(
            root,
            (
                PCAPResource(
                    resource_ref="evidence/capture-001",
                    relative_path=name,
                    **limits,
                ),
            ),
        )

    def test_all_classic_pcap_magic_variants_are_read_without_raw_payload_output(self):
        for magic, endian, expected_order, expected_resolution, fraction in MAGIC_VARIANTS:
            with self.subTest(magic=magic.hex()), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                payloads = (b"PRIVATE-PACKET-A", b"PRIVATE-PACKET-B")
                capture = _pcap_bytes(magic, endian, fraction, payloads)
                (root / "capture.pcap").write_bytes(capture)
                evidence = BoundedPCAPEvidenceReader(self._registry(root)).read_capture("evidence/capture-001")
                self.assertEqual(evidence.byte_order, expected_order)
                self.assertEqual(evidence.timestamp_resolution, expected_resolution)
                self.assertEqual(evidence.packet_count, 2)
                self.assertEqual(evidence.file_sha256, "sha256:" + hashlib.sha256(capture).hexdigest())
                self.assertEqual(
                    evidence.packets[0].payload_sha256,
                    "sha256:" + hashlib.sha256(payloads[0]).hexdigest(),
                )
                rendered = evidence.to_json()
                self.assertNotIn("PRIVATE-PACKET-A", rendered)
                self.assertNotIn("PRIVATE-PACKET-B", rendered)

    def test_metadata_mode_returns_structure_without_packet_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(_pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4]))
            evidence = BoundedPCAPEvidenceReader(self._registry(root)).read_metadata("evidence/capture-001")
            self.assertEqual(evidence.mode, "metadata")
            self.assertEqual(evidence.packet_count, 2)
            self.assertEqual(evidence.packets, ())
            self.assertGreater(evidence.total_captured_bytes, 0)

    def test_unknown_resource_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "capture.pcap"
            capture.write_bytes(_pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4]))
            registry = self._registry(root)
            reader = BoundedPCAPEvidenceReader(registry)
            with self.assertRaisesRegex(PCAPEvidenceDenied, "PCAP_RESOURCE_NOT_TRUSTED"):
                reader.read_capture("evidence/not-registered")

            target = root / "real.pcap"
            target.write_bytes(capture.read_bytes())
            link = root / "link.pcap"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            link_registry = self._registry(root, name="link.pcap")
            with self.assertRaisesRegex(PCAPEvidenceDenied, "PCAP_RESOURCE_SYMLINK_DENIED"):
                BoundedPCAPEvidenceReader(link_registry).read_capture("evidence/capture-001")

    def test_malformed_truncated_and_bound_exceeded_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "capture.pcap"
            path.write_bytes(b"not-a-pcap" * 4)
            with self.assertRaises(PCAPEvidenceError):
                BoundedPCAPEvidenceReader(self._registry(root)).read_capture("evidence/capture-001")

            valid = _pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4])
            path.write_bytes(valid[:-1])
            with self.assertRaisesRegex(PCAPEvidenceError, "PAYLOAD_TRUNCATED"):
                BoundedPCAPEvidenceReader(self._registry(root)).read_capture("evidence/capture-001")

            path.write_bytes(valid)
            registry = self._registry(
                root,
                max_file_bytes=len(valid) - 1,
                max_packet_bytes=len(valid) - 1,
            )
            with self.assertRaisesRegex(PCAPEvidenceError, "FILE_BOUND_EXCEEDED"):
                BoundedPCAPEvidenceReader(registry).read_capture("evidence/capture-001")

    def test_packet_count_bound_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(
                _pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4], payloads=(b"A", b"B"))
            )
            registry = self._registry(root, max_packets=1)
            with self.assertRaisesRegex(PCAPEvidenceError, "PACKET_COUNT_BOUND_EXCEEDED"):
                BoundedPCAPEvidenceReader(registry).read_capture("evidence/capture-001")

    def test_pcap_profile_binding_coverage_is_eight_of_fifteen(self):
        coverage = PCAPSecurityOperationBindingRegistry().coverage()
        self.assertEqual(coverage.total_operations, 15)
        self.assertEqual(coverage.bound_operations, 8)
        self.assertEqual(coverage.unbound_operations, 7)
        self.assertEqual(coverage.bound_percent, 53.333)
        self.assertNotIn("network.pcap.read#read_capture", coverage.unbound_operation_refs)
        self.assertNotIn("network.pcap.read#read_capture_metadata", coverage.unbound_operation_refs)
        self.assertNotIn("network.flow.analyze#analyze_flow_evidence", coverage.unbound_operation_refs)

    def test_typed_request_contains_resource_id_not_path(self):
        request = PCAPEvidenceInvocationRequest("evidence/capture-001").validate()
        self.assertEqual(request.resource_ref, "evidence/capture-001")
        self.assertNotIn("path", request.__dataclass_fields__)
        self.assertNotIn("target", request.__dataclass_fields__)
        self.assertNotIn("command", request.__dataclass_fields__)

    def test_task_authorized_capture_invocation_uses_trusted_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"SENSITIVE-PCAP-PAYLOAD"
            root.joinpath("capture.pcap").write_bytes(
                _pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4], payloads=(payload,))
            )
            invoker = PCAPTaskSecurityOperationInvoker(
                task_contract=_task_contract(allow_read=True),
                pcap_registry=self._registry(root),
            )
            plan = _plan("read_capture")
            result = invoker.invoke(
                plan,
                step_id=plan.steps[0].step_id,
                request=PCAPEvidenceInvocationRequest("evidence/capture-001"),
            )
            self.assertEqual(result.receipt.authority_domain, "task")
            self.assertEqual(result.receipt.authority_reason_code, "SECURITY_TASK_AUTHORITY_CONFIRMED")
            self.assertEqual(result.output.packet_count, 1)
            self.assertNotIn(payload.decode(), json.dumps(result.receipt.public_dict()))
            self.assertRegex(invoker.runtime_fingerprint, r"^sha256:[0-9a-f]{64}$")

    def test_task_without_read_file_authority_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(_pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4]))
            invoker = PCAPTaskSecurityOperationInvoker(
                task_contract=_task_contract(allow_read=False),
                pcap_registry=self._registry(root),
            )
            plan = _plan("read_capture")
            with self.assertRaisesRegex(PermissionError, "INVOCATION_TASK_CAPABILITY_NOT_ALLOWED"):
                invoker.invoke(
                    plan,
                    step_id=plan.steps[0].step_id,
                    request=PCAPEvidenceInvocationRequest("evidence/capture-001"),
                )

    def test_workflow_executes_bound_pcap_step_and_keeps_flow_analysis_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(_pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4]))
            invoker = PCAPTaskSecurityOperationInvoker(
                task_contract=_task_contract(allow_read=True),
                pcap_registry=self._registry(root),
            )
            journal = SecurityWorkflowAuditJournal(root / "workflow-audit.jsonl")
            workflow = SecurityAnalystWorkflow(invoker=invoker, journal=journal)
            prepared = workflow.prepare("analyze this pcap packet capture")
            self.assertEqual(prepared.session.status, "ready")
            pcap_steps = [step for step in prepared.session.steps if step.capability_id == "network.pcap.read"]
            flow_steps = [step for step in prepared.session.steps if step.capability_id == "network.flow.analyze"]
            self.assertEqual(len(pcap_steps), 1)
            self.assertEqual(pcap_steps[0].state, "awaiting_typed_input")
            self.assertEqual(len(flow_steps), 1)
            self.assertEqual(flow_steps[0].state, "awaiting_typed_input")
            self.assertEqual(flow_steps[0].binding_status, "bound")
            self.assertEqual(flow_steps[0].handler_id, "analysis.flow_evidence.analyze")

            execution = workflow.execute_step(
                prepared,
                step_id=pcap_steps[0].step_id,
                request=PCAPEvidenceInvocationRequest("evidence/capture-001"),
            )
            self.assertEqual(execution.session.status, "ready")
            self.assertEqual(execution.session.step_completion_percent, 50.0)
            self.assertEqual(execution.result.output.packet_count, 2)
            self.assertEqual(journal.records()[-1].event_type, "STEP_COMPLETED")
            rendered_audit = journal.path.read_text(encoding="utf-8")
            self.assertNotIn("capture.pcap", rendered_audit)
            self.assertNotIn(str(root), rendered_audit)

    def test_runtime_fingerprint_changes_with_task_authority_or_resource_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("capture.pcap").write_bytes(_pcap_bytes(*MAGIC_VARIANTS[0][:2], MAGIC_VARIANTS[0][4]))
            first = PCAPTaskSecurityOperationInvoker(
                task_contract=_task_contract(allow_read=True),
                pcap_registry=self._registry(root),
            ).runtime_fingerprint
            other_contract = TaskContractCompiler().compile(
                task_id="different-pcap-task",
                task_type="retrieval",
                sensitivity="confidential",
                risk_level="medium",
                allowed_sources=("trusted-pcap-registry",),
                allowed_tools=("read_file",),
                deterministic_only=True,
            )
            second = PCAPTaskSecurityOperationInvoker(
                task_contract=other_contract,
                pcap_registry=self._registry(root),
            ).runtime_fingerprint
            self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
