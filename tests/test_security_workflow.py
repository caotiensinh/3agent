import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.security_monitoring.operation_invocation import (
    CollectorInvocationRequest,
    DNSAnalysisInvocationRequest,
    SecurityOperationInvoker,
)
from three_agent.security_monitoring.security_workflow import (
    SecurityAnalystWorkflow,
    SecurityWorkflowDenied,
)
from three_agent.security_monitoring.workflow_audit import (
    SecurityWorkflowAuditError,
    SecurityWorkflowAuditJournal,
)


class SecurityAnalystWorkflowTests(unittest.TestCase):
    def _workflow(self, root):
        journal = SecurityWorkflowAuditJournal(Path(root) / "security-workflow-audit.jsonl")
        workflow = SecurityAnalystWorkflow(
            invoker=SecurityOperationInvoker(),
            journal=journal,
        )
        return workflow, journal

    @staticmethod
    def _dns_request(event_id="dns-workflow-1"):
        return DNSAnalysisInvocationRequest(
            event_id=event_id,
            source_type="zeek_json",
            raw_line=json.dumps(
                {
                    "_path": "dns",
                    "query": "example.com",
                    "qtype_name": "A",
                    "rcode_name": "NOERROR",
                    "answers": ["192.0.2.10"],
                }
            ),
        )

    def test_prepare_retains_hash_not_raw_natural_language_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, journal = self._workflow(tmp)
            secret_marker = "internal-secret-marker-12345"
            prepared = workflow.prepare(f"analyze dns evidence {secret_marker}")
            self.assertEqual(prepared.session.status, "ready")
            self.assertEqual(len(prepared.session.steps), 1)
            self.assertRegex(prepared.session.request_sha256, r"^sha256:[0-9a-f]{64}$")
            serialized = json.dumps(prepared.session.public_dict(), sort_keys=True)
            journal_text = journal.path.read_text(encoding="utf-8")
            self.assertNotIn(secret_marker, serialized)
            self.assertNotIn(secret_marker, journal_text)
            self.assertNotIn("analyze dns evidence", journal_text)

    def test_execute_dns_step_writes_requested_and_completed_hash_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, journal = self._workflow(tmp)
            prepared = workflow.prepare("analyze dns evidence")
            step = prepared.session.steps[0]
            execution = workflow.execute_step(
                prepared,
                step_id=step.step_id,
                request=self._dns_request(),
            )
            self.assertEqual(execution.session.status, "completed")
            self.assertEqual(execution.session.step_completion_percent, 100.0)
            self.assertEqual(execution.result.output.query_length, len("example.com"))
            self.assertEqual(execution.session.steps[0].state, "completed")
            self.assertEqual(
                execution.session.steps[0].invocation_id,
                execution.result.receipt.invocation_id,
            )
            records = journal.records()
            self.assertEqual(
                tuple(record.event_type for record in records),
                ("SESSION_PREPARED", "STEP_REQUESTED", "STEP_COMPLETED"),
            )
            verification = journal.verify()
            self.assertTrue(verification.valid)
            self.assertEqual(verification.record_count, 3)
            self.assertEqual(verification.first_record_sha256, records[0].record_sha256)
            self.assertEqual(verification.last_record_sha256, records[-1].record_sha256)

    def test_stale_prepared_session_cannot_replay_completed_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, _ = self._workflow(tmp)
            prepared = workflow.prepare("analyze dns evidence")
            step = prepared.session.steps[0]
            workflow.execute_step(prepared, step_id=step.step_id, request=self._dns_request())
            with self.assertRaisesRegex(
                SecurityWorkflowDenied,
                "WORKFLOW_STEP_ALREADY_COMPLETED_IN_AUDIT",
            ):
                workflow.execute_step(
                    prepared,
                    step_id=step.step_id,
                    request=self._dns_request("dns-workflow-replay"),
                )

    def test_failed_type_mismatch_is_audited_and_retry_after_failure_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, journal = self._workflow(tmp)
            prepared = workflow.prepare("analyze dns evidence")
            step = prepared.session.steps[0]
            wrong_request = CollectorInvocationRequest(
                asset_id="asset-does-not-matter",
                run_id="run-mismatch",
                observed_at="2026-09-02T00:00:00+00:00",
            )
            with self.assertRaisesRegex(PermissionError, "INVOCATION_REQUEST_TYPE_MISMATCH"):
                workflow.execute_step(
                    prepared,
                    step_id=step.step_id,
                    request=wrong_request,
                )
            records = journal.records()
            self.assertEqual(records[-2].event_type, "STEP_REQUESTED")
            self.assertEqual(records[-1].event_type, "STEP_FAILED")
            self.assertEqual(records[-1].reason_codes, ("INVOCATION_REQUEST_TYPE_MISMATCH",))

            execution = workflow.execute_step(
                prepared,
                step_id=step.step_id,
                request=self._dns_request("dns-workflow-retry"),
            )
            self.assertEqual(execution.session.status, "completed")
            self.assertEqual(journal.records()[-1].event_type, "STEP_COMPLETED")

    def test_active_or_offensive_request_is_denied_without_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, journal = self._workflow(tmp)
            prepared = workflow.prepare("run nmap port scan on the subnet")
            self.assertEqual(prepared.routing.status, "denied")
            self.assertEqual(prepared.plan.status, "denied")
            self.assertEqual(prepared.session.status, "denied")
            self.assertEqual(prepared.session.steps, ())
            self.assertEqual(journal.verify().record_count, 1)

    def test_unbound_pcap_route_is_explicitly_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, _ = self._workflow(tmp)
            prepared = workflow.prepare("analyze this pcap packet capture")
            self.assertEqual(prepared.session.status, "blocked")
            self.assertGreaterEqual(len(prepared.session.steps), 1)
            self.assertTrue(all(step.state == "unbound" for step in prepared.session.steps))
            self.assertTrue(
                all(step.binding_reason_code.startswith("UNBOUND_") for step in prepared.session.steps)
            )

    def test_workflow_exposes_no_run_all_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, _ = self._workflow(tmp)
            self.assertFalse(hasattr(workflow, "run_all"))
            self.assertFalse(hasattr(workflow, "execute_all"))

    def test_audit_journal_detects_content_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, journal = self._workflow(tmp)
            workflow.prepare("analyze dns evidence")
            payload = json.loads(journal.path.read_text(encoding="utf-8"))
            payload["reason_codes"] = ["WORKFLOW_TYPED_STEP_COMPLETED"]
            journal.path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SecurityWorkflowAuditError, "record_sha256"):
                journal.verify()

    def test_audit_journal_detects_broken_previous_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, journal = self._workflow(tmp)
            prepared = workflow.prepare("analyze dns evidence")
            workflow.execute_step(
                prepared,
                step_id=prepared.session.steps[0].step_id,
                request=self._dns_request(),
            )
            lines = journal.path.read_text(encoding="utf-8").splitlines()
            second = json.loads(lines[1])
            second["previous_record_sha256"] = "sha256:" + "0" * 64
            # Recompute this record hash so verification must catch the chain relation,
            # not merely the record's own content hash.
            from three_agent.security_monitoring.contracts import sha256_fingerprint

            identity = dict(second)
            identity.pop("record_sha256")
            second["record_sha256"] = sha256_fingerprint(identity)
            lines[1] = json.dumps(second, sort_keys=True, separators=(",", ":"))
            journal.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SecurityWorkflowAuditError, "hash chain"):
                journal.verify()

    def test_completed_session_can_be_carried_forward_without_changing_reviewed_lineage(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, _ = self._workflow(tmp)
            prepared = workflow.prepare("analyze dns evidence")
            execution = workflow.execute_step(
                prepared,
                step_id=prepared.session.steps[0].step_id,
                request=self._dns_request(),
            )
            updated_prepared = replace(prepared, session=execution.session)
            with self.assertRaisesRegex(SecurityWorkflowDenied, "WORKFLOW_SESSION_NOT_EXECUTABLE"):
                workflow.execute_step(
                    updated_prepared,
                    step_id=execution.session.steps[0].step_id,
                    request=self._dns_request("dns-workflow-completed"),
                )

    def test_journal_public_records_expose_no_target_path_or_credential_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow, journal = self._workflow(tmp)
            prepared = workflow.prepare("analyze dns evidence")
            workflow.execute_step(
                prepared,
                step_id=prepared.session.steps[0].step_id,
                request=self._dns_request(),
            )
            rendered = journal.path.read_text(encoding="utf-8")
            for forbidden in (
                "target_host",
                "credential_ref",
                "raw_line",
                "file_path",
                "argv",
                "command",
                "system_prompt",
            ):
                self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
