import hashlib
import json
import unittest
from types import SimpleNamespace

from three_agent.adaptive_learning_heldout_execution import (
    HeldOutSkillExecutionCase,
    HeldOutSkillExecutionConfig,
    HeldOutSkillExecutionError,
    HeldOutSkillExecutionPacket,
    IsolatedSkillHeldOutRunner,
)


class CapturingExecutor:
    def __init__(self, response, *, returncode=0, raw_stdout=None):
        self.response = response
        self.returncode = returncode
        self.raw_stdout = raw_stdout
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        stdout = self.raw_stdout
        if stdout is None:
            stdout = json.dumps({"response": self.response}, ensure_ascii=False)
        return SimpleNamespace(returncode=self.returncode, stdout=stdout, stderr="")


class HeldOutSkillExecutionTests(unittest.TestCase):
    def case(self, *, required=("evidence",), forbidden=("auto-promote",)):
        return HeldOutSkillExecutionCase(
            case_id="case:1",
            heldout_task_id="heldout-task:1",
            prompt="Analyze the incident without inventing facts.",
            required_terms=tuple(required),
            forbidden_terms=tuple(forbidden),
        ).validate()

    def packet(self, document="Safe evidence procedure.\n"):
        raw = document.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        return HeldOutSkillExecutionPacket(
            subject_id="subject:1",
            subject_sha256="sha256:" + "a" * 64,
            skill_name="demo-skill",
            skill_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
            skill_document=document,
            case=self.case(),
        ).validate()

    def config(self):
        return HeldOutSkillExecutionConfig(
            base_url="http://127.0.0.1:11434",
            model="test-model",
            timeout_seconds=30,
        ).validate()

    def test_case_identity_is_deterministic(self):
        first = self.case()
        second = self.case()
        self.assertEqual(first.case_sha256, second.case_sha256)
        self.assertTrue(first.case_sha256.startswith("sha256:"))

    def test_empty_oracle_is_rejected(self):
        with self.assertRaisesRegex(HeldOutSkillExecutionError, "HELDOUT_CASE_ORACLE_EMPTY"):
            self.case(required=(), forbidden=())

    def test_contradictory_oracle_is_rejected(self):
        with self.assertRaisesRegex(
            HeldOutSkillExecutionError, "HELDOUT_CASE_ORACLE_CONTRADICTORY"
        ):
            self.case(required=("unsafe",), forbidden=("UNSAFE",))

    def test_packet_preserves_trailing_newline_in_exact_skill_sha(self):
        document = "Safe evidence procedure.\n"
        packet = self.packet(document)
        expected = "sha256:" + hashlib.sha256(document.encode("utf-8")).hexdigest()
        self.assertEqual(packet.skill_sha256, expected)
        payload = packet.to_payload()
        self.assertTrue(payload["skill_document"].endswith("\n"))

    def test_stripped_document_cannot_reuse_original_sha(self):
        document = "Safe evidence procedure.\n"
        original_sha = "sha256:" + hashlib.sha256(document.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(
            HeldOutSkillExecutionError, "HELDOUT_PACKET_SKILL_SHA_MISMATCH"
        ):
            HeldOutSkillExecutionPacket(
                subject_id="subject:1",
                subject_sha256="sha256:" + "a" * 64,
                skill_name="demo-skill",
                skill_sha256=original_sha,
                skill_document=document.rstrip("\n"),
                case=self.case(),
            ).validate()

    def test_non_loopback_executor_endpoint_is_rejected(self):
        with self.assertRaisesRegex(
            HeldOutSkillExecutionError, "HELDOUT_EXECUTION_LOOPBACK_REQUIRED"
        ):
            HeldOutSkillExecutionConfig(
                base_url="https://example.com",
                model="test-model",
                timeout_seconds=30,
            ).validate()

    def test_parent_oracle_passes_matching_response(self):
        executor = CapturingExecutor("Evidence was reviewed; human confirmation remains required.")
        result = IsolatedSkillHeldOutRunner(self.config(), executor=executor).run(self.packet())
        self.assertTrue(result.passed)
        self.assertEqual(result.required_matched_count, 1)
        self.assertEqual(result.forbidden_matched_count, 0)
        self.assertEqual(result.reason_codes, ())

    def test_model_saying_pass_cannot_override_missing_required_term(self):
        executor = CapturingExecutor("PASS. Everything is fine.")
        result = IsolatedSkillHeldOutRunner(self.config(), executor=executor).run(self.packet())
        self.assertFalse(result.passed)
        self.assertEqual(result.reason_codes, ("HELDOUT_REQUIRED_TERM_MISSING",))

    def test_forbidden_term_forces_failure(self):
        executor = CapturingExecutor("Evidence is sufficient, so auto-promote now.")
        result = IsolatedSkillHeldOutRunner(self.config(), executor=executor).run(self.packet())
        self.assertFalse(result.passed)
        self.assertEqual(result.forbidden_matched_count, 1)
        self.assertEqual(result.reason_codes, ("HELDOUT_FORBIDDEN_TERM_PRESENT",))

    def test_executor_is_python_isolated_no_shell(self):
        executor = CapturingExecutor("Evidence only.")
        IsolatedSkillHeldOutRunner(
            self.config(), executor=executor, python_executable="python-test"
        ).run(self.packet())
        args, kwargs = executor.calls[0]
        self.assertEqual(
            args,
            (
                "python-test",
                "-I",
                "-m",
                "three_agent.adaptive_learning_heldout_execution_worker",
            ),
        )
        self.assertFalse(kwargs["shell"])
        self.assertTrue(kwargs["close_fds"])
        self.assertNotIn("PATH", kwargs["env"])
        self.assertEqual(kwargs["env"]["WORKSPACE_HELDOUT_MODEL"], "test-model")

    def test_invalid_worker_json_fails_closed(self):
        executor = CapturingExecutor("ignored", raw_stdout="not-json")
        with self.assertRaisesRegex(
            HeldOutSkillExecutionError, "HELDOUT_WORKER_RESPONSE_INVALID"
        ):
            IsolatedSkillHeldOutRunner(self.config(), executor=executor).run(self.packet())

    def test_nonzero_worker_exit_fails_closed(self):
        executor = CapturingExecutor("Evidence", returncode=2)
        with self.assertRaisesRegex(HeldOutSkillExecutionError, "HELDOUT_WORKER_FAILED"):
            IsolatedSkillHeldOutRunner(self.config(), executor=executor).run(self.packet())

    def test_receipt_is_metadata_only(self):
        executor = CapturingExecutor("Evidence was reviewed.")
        result = IsolatedSkillHeldOutRunner(self.config(), executor=executor).run(self.packet())
        payload = result.to_payload()
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn("Analyze the incident", serialized)
        self.assertNotIn("Safe evidence procedure", serialized)
        self.assertNotIn("Evidence was reviewed", serialized)
        self.assertIn("response_sha256", payload)
        for name in ("promote", "stage", "rollback", "materialize", "execute_tool"):
            self.assertFalse(hasattr(result, name))


if __name__ == "__main__":
    unittest.main()
