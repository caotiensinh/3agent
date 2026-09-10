from __future__ import annotations

import unittest

from three_agent.privacy import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_DENY_RAW_DERIVE_ABSTRACT_ALLOW,
    ACTION_SANITIZE_WARN_ALLOW,
    ACTION_TOKENIZE_GENERALIZE_WARN_ALLOW,
    SENSITIVITY_CONFIDENTIAL,
    SENSITIVITY_INTERNAL,
    SENSITIVITY_PUBLIC,
    SENSITIVITY_RESTRICTED,
    apply_internet_egress_policy,
    assess_public_egress_text,
    sanitize_research_query,
)
from three_agent.public_query_compiler import (
    compile_public_search_queries,
    compile_public_search_query,
)
from three_agent.task_contract import TaskContractCompiler, TaskContractError


class InternetEgressPolicyTests(unittest.TestCase):
    def test_public_query_is_allowed_without_warning(self):
        decision = apply_internet_egress_policy("NVIDIA RTX 5090 Ollama support")
        self.assertEqual(decision.sensitivity, SENSITIVITY_PUBLIC)
        self.assertEqual(decision.action, ACTION_ALLOW)
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.warning_required)

    def test_internal_query_is_sanitized_warned_and_allowed(self):
        decision = apply_internet_egress_policy(
            "server 192.168.11.190 Ollama connection refused Ubuntu 24.04"
        )
        self.assertEqual(decision.sensitivity, SENSITIVITY_INTERNAL)
        self.assertEqual(decision.action, ACTION_SANITIZE_WARN_ALLOW)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.warning_required)
        self.assertNotIn("192.168.11.190", decision.query)
        self.assertTrue(assess_public_egress_text(decision.query).allowed)

    def test_confidential_query_is_generalized_warned_and_allowed(self):
        decision = apply_internet_egress_policy(
            "社外秘 camera design benchmark RTSP reconnect behavior"
        )
        self.assertEqual(decision.sensitivity, SENSITIVITY_CONFIDENTIAL)
        self.assertEqual(decision.action, ACTION_TOKENIZE_GENERALIZE_WARN_ALLOW)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.warning_required)
        self.assertNotIn("社外秘", decision.query)
        self.assertTrue(assess_public_egress_text(decision.query).allowed)

    def test_restricted_raw_credential_never_leaves_but_safe_research_continues(self):
        raw = "password=TopSecret-12345 Ollama authentication connection refused Ubuntu"
        decision = apply_internet_egress_policy(raw)
        self.assertEqual(decision.sensitivity, SENSITIVITY_RESTRICTED)
        self.assertEqual(decision.action, ACTION_DENY_RAW_DERIVE_ABSTRACT_ALLOW)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.warning_required)
        self.assertNotEqual(decision.query, raw)
        self.assertNotIn("TopSecret", decision.query)
        self.assertTrue(assess_public_egress_text(decision.query).allowed)

    def test_restricted_only_secret_fails_closed(self):
        decision = apply_internet_egress_policy("password=TopSecret-12345")
        self.assertEqual(decision.sensitivity, SENSITIVITY_RESTRICTED)
        self.assertEqual(decision.action, ACTION_BLOCK)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.query, "")

    def test_runtime_sanitizer_uses_same_policy_before_gateway(self):
        query = sanitize_research_query("dev@example.com MediaMTX RTSP reconnect")
        self.assertNotIn("dev@example.com", query)
        self.assertIn("MediaMTX", query)
        self.assertTrue(assess_public_egress_text(query).allowed)

    def test_compiler_diagnostics_never_echo_raw_secret(self):
        raw = "api_key=sk-abcdefghijklmnopqrstuvwxyz123456 camera firmware issue"
        result = compile_public_search_query(raw)
        self.assertTrue(result.allowed)
        self.assertEqual(result.sensitivity, SENSITIVITY_RESTRICTED)
        self.assertTrue(result.warning_required)
        self.assertNotIn("sk-", result.query)
        queries, diagnostics = compile_public_search_queries([raw])
        self.assertEqual(queries, ["camera firmware issue"])
        joined = " ".join(diagnostics)
        self.assertIn("sensitivity=RESTRICTED", joined)
        self.assertNotIn("sk-", joined)

    def test_internal_confidential_and_restricted_tasks_may_use_only_allowlisted_web_gateway(self):
        for sensitivity in ("internal", "confidential", "restricted"):
            contract = TaskContractCompiler().compile(
                task_id=f"TASK-{sensitivity}",
                task_type="analysis",
                sensitivity=sensitivity,
                public_web=True,
            )
            self.assertEqual(contract.network_scope, "allowlisted_egress")
            self.assertIn("web_gateway", contract.allowed_tools)
            self.assertIn(
                f"SANITIZED_{sensitivity.upper()}_ALLOWLISTED_EGRESS",
                contract.policy_reason_codes,
            )

    def test_legacy_secret_task_remains_network_denied(self):
        with self.assertRaises(TaskContractError):
            TaskContractCompiler().compile(
                task_id="TASK-secret",
                task_type="sensitive_query",
                sensitivity="secret",
                public_web=True,
            )


if __name__ == "__main__":
    unittest.main()
