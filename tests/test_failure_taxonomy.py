import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.capability_authority import CapabilityAuthorityDenied
from three_agent.execution_budget import ExecutionBudgetExceeded
from three_agent.failure_taxonomy import (
    DEFAULT_FAILURE_TAXONOMY,
    FAILURE_DECISION_SCHEMA,
    FAILURE_TAXONOMY_SCHEMA,
    classify_failure,
)
from three_agent.inference_scope import inference_scope
from three_agent.llm import LocalLLMError
from three_agent.metered_runtime import MeteredAdaptiveOllamaClient
from three_agent.model_authority import TaskModelAuthority
from three_agent.resource_budget import ResourceAdmissionError
from three_agent.resource_events import ResourceEventRecorder
from three_agent.task_contract import TaskContractCompiler


class FakeModel:
    def __init__(self, model, outcomes):
        self.config = SimpleNamespace(model=model)
        self.outcomes = list(outcomes)
        self.calls = 0

    def generate(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def generate_json(self, *args, **kwargs):
        return self.generate(*args, **kwargs)

    def unload(self):
        return None


class DenyRecoveryTaxonomy:
    def __init__(self):
        self.calls = []

    def require_operation(self, reason_code, operation):
        self.calls.append((reason_code, operation))
        raise RuntimeError("RECOVERY_POLICY_DENIED_FOR_TEST")


class FailureTaxonomyTests(unittest.TestCase):
    def test_registry_is_versioned_and_unknown_fails_closed(self):
        payload = DEFAULT_FAILURE_TAXONOMY.registry_payload()
        self.assertEqual(payload["schema_version"], FAILURE_TAXONOMY_SCHEMA)
        self.assertEqual(payload["unknown_failure_policy"], "hard_stop")
        self.assertFalse(payload["raw_content_required"])

        decision = classify_failure(RuntimeError("PRIVATE_FAILURE_MESSAGE"))
        self.assertEqual(decision.code, "UNKNOWN_FAILURE")
        self.assertTrue(decision.terminal)
        self.assertFalse(decision.retryable)
        raw = json.dumps(decision.to_dict(), sort_keys=True)
        self.assertEqual(decision.to_dict()["schema_version"], FAILURE_DECISION_SCHEMA)
        self.assertNotIn("PRIVATE_FAILURE_MESSAGE", raw)

    def test_security_and_budget_denials_are_terminal(self):
        capability = classify_failure(CapabilityAuthorityDenied("CAPABILITY_NOT_ALLOWED"))
        self.assertEqual(capability.code, "CAPABILITY_DENIED")
        self.assertEqual(capability.recovery_action, "hard_stop")
        self.assertFalse(capability.permits("retry_model"))

        budget = classify_failure(ExecutionBudgetExceeded("TASK_TOOL_CALL_BUDGET_EXHAUSTED"))
        self.assertEqual(budget.code, "BUDGET_EXHAUSTED")
        self.assertTrue(budget.terminal)
        self.assertFalse(budget.retryable)

    def test_evidence_missing_requires_collection_not_model_retry(self):
        decision = classify_failure(reason_code="DETERMINISTIC_RETRIEVAL_EVIDENCE_MISSING")
        self.assertEqual(decision.code, "EVIDENCE_MISSING")
        self.assertEqual(decision.recovery_action, "collect_evidence")
        self.assertTrue(decision.permits("collect_evidence"))
        self.assertFalse(decision.permits("retry_model"))
        with self.assertRaisesRegex(RuntimeError, "FAILURE_RECOVERY_NOT_AUTHORIZED"):
            DEFAULT_FAILURE_TAXONOMY.require_operation(
                "DETERMINISTIC_RETRIEVAL_EVIDENCE_MISSING", "retry_model"
            )

    def test_model_and_resource_failures_have_bounded_recovery_only(self):
        model = classify_failure(LocalLLMError("PRIVATE_MODEL_DETAIL"))
        self.assertEqual(model.code, "MODEL_FAILURE")
        self.assertTrue(model.permits("retry_model"))
        self.assertTrue(model.permits("escalate_model"))
        self.assertFalse(model.permits("collect_evidence"))
        self.assertFalse(model.to_dict()["authority_may_expand"])

        resource = classify_failure(ResourceAdmissionError("busy"))
        self.assertEqual(resource.code, "RESOURCE_ADMISSION")
        self.assertTrue(resource.permits("fallback_worker"))
        self.assertTrue(resource.permits("fallback_model"))
        self.assertFalse(resource.permits("escalate_model"))

    def test_compact_runtime_reason_codes_are_classified_without_raw_messages(self):
        decision = classify_failure(RuntimeError("REQUIRED_VALIDATOR_NOT_PASSED"))
        self.assertEqual(decision.code, "VALIDATION_FAILED")
        self.assertEqual(decision.observed_reason_code, "REQUIRED_VALIDATOR_NOT_PASSED")
        self.assertEqual(decision.exception_type, "RuntimeError")

    def test_router_consults_taxonomy_before_fallback_side_effects_or_telemetry(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-FAILURE-ROUTER",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        authority = TaskModelAuthority.from_contract(contract)
        primary = FakeModel("primary", [LocalLLMError("PRIVATE_PRIMARY_FAILURE")])
        deep = FakeModel("deep", ["MUST_NOT_RUN"])
        denied = DenyRecoveryTaxonomy()

        with tempfile.TemporaryDirectory() as tmp:
            events = Path(tmp) / "resource.jsonl"
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                role="research",
                resource_events=ResourceEventRecorder(events),
                primary_tier="specialist",
                deep_tier="strong",
            )
            with patch("three_agent.metered_runtime.DEFAULT_FAILURE_TAXONOMY", denied):
                with inference_scope(
                    contract.task_id,
                    agent_id="research",
                    stage="research",
                    model_authority=authority,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "RECOVERY_POLICY_DENIED_FOR_TEST"
                    ):
                        client.generate("system", "short")

            self.assertEqual(denied.calls, [("LOCAL_LLM_ERROR", "escalate_model")])
            self.assertEqual(primary.calls, 1)
            self.assertEqual(deep.calls, 0)
            self.assertFalse(events.exists())


if __name__ == "__main__":
    unittest.main()
