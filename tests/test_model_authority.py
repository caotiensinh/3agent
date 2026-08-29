import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from three_agent.artifacts import ArtifactManager
from three_agent.inference_scope import current_model_authority, inference_scope
from three_agent.llm import LocalLLMError
from three_agent.metered_runtime import MeteredAdaptiveOllamaClient
from three_agent.model_authority import ModelAuthorityDenied, TaskModelAuthority
from three_agent.resource_events import ResourceEventRecorder
from three_agent.runtime_validation import RuntimeValidatorBridge
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class CapturingModel:
    def __init__(self, model, outcomes):
        self.config = SimpleNamespace(model=model)
        self.outcomes = list(outcomes)
        self.calls = 0
        self.authority_fingerprints = []

    def generate(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        authority = current_model_authority()
        self.authority_fingerprints.append(
            authority.fingerprint if authority is not None else None
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def generate_json(self, *args, **kwargs):
        return self.generate(*args, **kwargs)

    def unload(self):
        return None


class ModelAuthorityTests(unittest.TestCase):
    @staticmethod
    def _analysis_contract(task_id="TASK-AUTH-1"):
        return TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )

    @staticmethod
    def _restricted_to_specialist(contract):
        return replace(
            contract,
            model_policy=replace(
                contract.model_policy,
                max_tier="specialist",
                escalation_allowed=False,
            ),
        ).validate()

    def test_authority_metadata_is_compact_and_fingerprint_covers_capabilities(self):
        contract = self._analysis_contract()
        authority = TaskModelAuthority.from_contract(contract)
        metadata = authority.metadata()
        self.assertEqual(metadata["authority_fingerprint"], authority.fingerprint)
        self.assertTrue(authority.fingerprint.startswith("sha256:"))
        self.assertNotIn("allowed_sources", metadata)
        self.assertNotIn("allowed_tools", metadata)
        self.assertNotIn("write_scope", metadata)
        self.assertNotIn("network_scope", metadata)

        changed_source = replace(contract, allowed_sources=("source-A",)).validate()
        changed_write = replace(contract, write_scope=("staging/path",)).validate()
        self.assertNotEqual(
            authority.fingerprint,
            TaskModelAuthority.from_contract(changed_source).fingerprint,
        )
        self.assertNotEqual(
            authority.fingerprint,
            TaskModelAuthority.from_contract(changed_write).fingerprint,
        )

    def test_scope_rejects_authority_for_another_task(self):
        authority = TaskModelAuthority.from_contract(self._analysis_contract("TASK-A"))
        with self.assertRaisesRegex(ValueError, "does not match inference scope"):
            with inference_scope(
                "TASK-B",
                agent_id="research",
                stage="research",
                model_authority=authority,
            ):
                pass

    def test_planned_deep_selection_above_contract_max_stays_on_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract = self._restricted_to_specialist(self._analysis_contract())
            authority = TaskModelAuthority.from_contract(contract)
            events = Path(tmp) / "resource.jsonl"
            primary = CapturingModel("primary", ["primary-ok"])
            deep = CapturingModel("deep", ["MUST_NOT_RUN"])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                deep_prompt_chars=2000,
                role="research",
                resource_events=ResourceEventRecorder(events),
                primary_tier="specialist",
                deep_tier="strong",
            )
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=authority,
            ):
                result = client.generate("system", "x" * 2200)
            self.assertEqual(result, "primary-ok")
            self.assertEqual(primary.calls, 1)
            self.assertEqual(deep.calls, 0)
            self.assertFalse(events.exists())

    def test_failure_driven_forbidden_escalation_fails_before_deep_call_or_telemetry(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract = self._restricted_to_specialist(self._analysis_contract())
            authority = TaskModelAuthority.from_contract(contract)
            events = Path(tmp) / "resource.jsonl"
            primary = CapturingModel("primary", [LocalLLMError("PRIVATE_FAILURE")])
            deep = CapturingModel("deep", ["MUST_NOT_RUN"])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                role="research",
                resource_events=ResourceEventRecorder(events),
                primary_tier="specialist",
                deep_tier="strong",
            )
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=authority,
            ):
                with self.assertRaisesRegex(
                    ModelAuthorityDenied, "MODEL_TIER_EXCEEDS_CONTRACT_MAX"
                ):
                    client.generate("system", "short")
            self.assertEqual(primary.calls, 1)
            self.assertEqual(deep.calls, 0)
            self.assertFalse(events.exists())

    def test_allowed_escalation_preserves_identical_authority_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract = self._analysis_contract()
            authority = TaskModelAuthority.from_contract(contract)
            events = Path(tmp) / "resource.jsonl"
            primary = CapturingModel("primary", [LocalLLMError("primary failed")])
            deep = CapturingModel("deep", ["deep-ok"])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                role="research",
                resource_events=ResourceEventRecorder(events),
                primary_tier="specialist",
                deep_tier="strong",
            )
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=authority,
            ):
                self.assertEqual(client.generate("system", "short"), "deep-ok")
            self.assertEqual(primary.authority_fingerprints, [authority.fingerprint])
            self.assertEqual(deep.authority_fingerprints, [authority.fingerprint])
            self.assertEqual(authority.allowed_tools, contract.allowed_tools)
            self.assertEqual(authority.allowed_sources, contract.allowed_sources)
            self.assertEqual(authority.write_scope, contract.write_scope)
            self.assertEqual(authority.network_scope, contract.network_scope)
            rows = [
                json.loads(line)
                for line in events.read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(
                [row["event_type"] for row in rows],
                ["model_retry", "model_escalation"],
            )

    def test_no_llm_contract_blocks_accidental_model_call_before_primary(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-NO-LLM",
            task_type="retrieval",
            sensitivity="internal",
            deterministic_only=True,
        )
        authority = TaskModelAuthority.from_contract(contract)
        primary = CapturingModel("primary", ["MUST_NOT_RUN"])
        deep = CapturingModel("deep", ["MUST_NOT_RUN"])
        with tempfile.TemporaryDirectory() as tmp:
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                role="research",
                resource_events=ResourceEventRecorder(Path(tmp) / "resource.jsonl"),
                primary_tier="specialist",
                deep_tier="strong",
            )
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=authority,
            ):
                with self.assertRaisesRegex(
                    ModelAuthorityDenied, "MODEL_TIER_EXCEEDS_CONTRACT_MAX"
                ):
                    client.generate("system", "short")
        self.assertEqual(primary.calls, 0)
        self.assertEqual(deep.calls, 0)

    def test_runtime_bridge_binds_authority_without_raw_request_in_ledger_or_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            task = store.create_task("authority", "PRIVATE_AUTHORITY_REQUEST_MARKER")
            bridge = RuntimeValidatorBridge(
                store,
                ArtifactManager(root / "artifacts"),
                confidentiality_mode="development-test",
                public_web=False,
            )
            attempt = bridge.begin(task.task_id)
            self.assertIsNotNone(attempt.model_authority)
            fingerprint = attempt.model_authority.fingerprint
            self.assertTrue(fingerprint.startswith("sha256:"))

            ledger_text = json.dumps(
                bridge.ledger.export_results(task.task_id), ensure_ascii=False
            )
            activities = store.activities_for_date(task.created_at[:10])
            activity_text = "\n".join(str(row["details"]) for row in activities)
            self.assertIn(fingerprint, ledger_text)
            self.assertIn(fingerprint, activity_text)
            self.assertNotIn("PRIVATE_AUTHORITY_REQUEST_MARKER", ledger_text)
            self.assertNotIn("PRIVATE_AUTHORITY_REQUEST_MARKER", activity_text)


if __name__ == "__main__":
    unittest.main()
