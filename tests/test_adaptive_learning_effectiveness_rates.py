from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_effectiveness import (
    EFFECTIVENESS_RATE_SCHEMA,
    DeterministicLearningEffectivenessAnalyzer,
    KnowledgeEffectivenessSignal,
    NormalizedEffectivenessRate,
    record_learning_reuse,
)
from three_agent.adaptive_learning_retrieval import LearningContext, LearningContextItem
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class LearningEffectivenessRateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = TaskStore(self.root / "tasks.db")
        self.store.initialize()
        self.compiler = TaskContractCompiler()
        self.ledger = ValidatorLedger(self.store)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def task(self) -> tuple[str, tuple[str, ...]]:
        task = self.store.create_task("Phase4H rates", "PRIVATE-RATE-REQUEST")
        contract = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="confidential",
            risk_level="low",
        )
        self.ledger.bind_contract(contract)
        return task.task_id, tuple(contract.validators)

    @staticmethod
    def item(name: str) -> LearningContextItem:
        return LearningContextItem(
            item_id=f"knowledge:{name}",
            knowledge_sha256=sha(f"knowledge:{name}"),
            level="approved",
            domain="analyst",
            kind="skill",
            title=f"Title {name}",
            content=f"PRIVATE-SKILL-BODY-{name}",
            scope="local analysis",
            sensitivity="confidential",
            risk_level="medium",
            execution_mode="analysis_only",
        ).validate()

    @staticmethod
    def context(*items: LearningContextItem, query: str) -> LearningContext:
        return LearningContext(
            query_sha256=sha(f"query:{query}"),
            domain="analyst",
            task_sensitivity="confidential",
            items=tuple(items),
        ).validate()

    def validator_results(self, task_id: str, validators: tuple[str, ...], *, failed_index: int | None) -> None:
        for index, validator in enumerate(validators):
            status = "failed" if failed_index == index else "passed"
            self.ledger.record(
                task_id,
                validator,
                status=status,
                reason_code=f"RATE_{validator.upper()}_{status.upper()}",
                evidence_refs=(sha(f"{task_id}:{validator}:{status}"),),
                validator_version="rate-test/v1",
                attempt=1,
            )

    def signal(self, item: LearningContextItem):
        snapshot = DeterministicLearningEffectivenessAnalyzer(self.store).snapshot()
        matches = [signal for signal in snapshot.signals if signal.knowledge_sha256 == item.knowledge_sha256]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_normalized_rate_uses_exact_ratio_and_integer_basis_points(self):
        self.assertEqual(
            NormalizedEffectivenessRate.from_counts(1, 3).to_payload(),
            {"numerator": 1, "denominator": 3, "basis_points": 3333},
        )
        self.assertEqual(
            NormalizedEffectivenessRate.from_counts(2, 3).to_payload(),
            {"numerator": 2, "denominator": 3, "basis_points": 6667},
        )
        self.assertEqual(
            NormalizedEffectivenessRate.from_counts(0, 0).to_payload(),
            {"numerator": 0, "denominator": 0, "basis_points": None},
        )

    def test_final_outcome_and_resolved_validator_denominators_are_separate(self):
        item = self.item("mixed-rates")

        success_task, success_validators = self.task()
        record_learning_reuse(self.store, success_task, self.context(item, query="success"))
        self.validator_results(success_task, success_validators, failed_index=None)
        self.store.set_status(success_task, TaskStatus.DONE)

        failed_task, failed_validators = self.task()
        record_learning_reuse(self.store, failed_task, self.context(item, query="failed"))
        self.validator_results(failed_task, failed_validators, failed_index=0)
        self.store.set_status(failed_task, TaskStatus.FAILED)

        unverified_task, unverified_validators = self.task()
        record_learning_reuse(self.store, unverified_task, self.context(item, query="unverified"))
        self.validator_results(unverified_task, unverified_validators, failed_index=0)
        self.store.set_status(unverified_task, TaskStatus.DONE)

        waiting_task, _waiting_validators = self.task()
        record_learning_reuse(self.store, waiting_task, self.context(item, query="waiting"))
        self.store.set_status(waiting_task, TaskStatus.WAITING_HUMAN)

        pending_task, _pending_validators = self.task()
        record_learning_reuse(self.store, pending_task, self.context(item, query="pending"))

        signal = self.signal(item)
        projection = signal.rate_projection()
        payload = projection.to_payload()

        self.assertEqual(payload["schema_version"], EFFECTIVENESS_RATE_SCHEMA)
        self.assertEqual(projection.finalized_task_observations, 3)
        self.assertEqual(projection.verified_success_rate.to_payload(), {
            "numerator": 1,
            "denominator": 3,
            "basis_points": 3333,
        })
        self.assertEqual(projection.failure_rate.to_payload(), {
            "numerator": 1,
            "denominator": 3,
            "basis_points": 3333,
        })

        expected_resolved = len(success_validators) + len(failed_validators) + len(unverified_validators)
        expected_passed = (
            len(success_validators)
            + max(0, len(failed_validators) - 1)
            + max(0, len(unverified_validators) - 1)
        )
        self.assertEqual(projection.resolved_validator_observations, expected_resolved)
        self.assertEqual(projection.validator_pass_rate.numerator, expected_passed)
        self.assertEqual(projection.validator_pass_rate.denominator, expected_resolved)
        expected_bps = (expected_passed * 10_000 + expected_resolved // 2) // expected_resolved
        self.assertEqual(projection.validator_pass_rate.basis_points, expected_bps)

        # Waiting and pending tasks remain visible in raw observational counts but
        # do not turn into final failures or unresolved validator failures.
        self.assertEqual(signal.waiting_human_after_reuse, 1)
        self.assertEqual(signal.pending_after_reuse, 1)
        self.assertEqual(projection.finalized_task_observations, 3)
        self.assertEqual(projection.resolved_validator_observations, expected_resolved)

    def test_missing_validator_results_produce_unavailable_not_zero_percent(self):
        item = self.item("unresolved-only")
        task_id, _validators = self.task()
        record_learning_reuse(self.store, task_id, self.context(item, query="pending"))

        projection = self.signal(item).rate_projection()
        self.assertEqual(projection.finalized_task_observations, 0)
        self.assertIsNone(projection.verified_success_rate.basis_points)
        self.assertIsNone(projection.failure_rate.basis_points)
        self.assertEqual(projection.resolved_validator_observations, 0)
        self.assertIsNone(projection.validator_pass_rate.basis_points)

    def test_confounded_task_has_overall_rates_but_no_isolated_denominator(self):
        one = self.item("confounded-one")
        two = self.item("confounded-two")
        task_id, validators = self.task()
        record_learning_reuse(self.store, task_id, self.context(one, two, query="confounded"))
        self.validator_results(task_id, validators, failed_index=None)
        self.store.set_status(task_id, TaskStatus.DONE)

        snapshot = DeterministicLearningEffectivenessAnalyzer(self.store).snapshot()
        self.assertEqual(len(snapshot.rate_projections()), 2)
        for projection in snapshot.rate_projections():
            self.assertEqual(projection.verified_success_rate.basis_points, 10_000)
            self.assertEqual(projection.validator_pass_rate.basis_points, 10_000)
            self.assertEqual(projection.isolated_finalized_task_observations, 0)
            self.assertIsNone(projection.isolated_verified_success_rate.basis_points)
            self.assertIsNone(projection.isolated_failure_rate.basis_points)
            self.assertEqual(projection.isolated_resolved_validator_observations, 0)
            self.assertIsNone(projection.isolated_validator_pass_rate.basis_points)

    def test_v1_snapshot_payload_and_hash_ignore_new_projection_counters(self):
        base = dict(
            item_id="knowledge:compat",
            knowledge_sha256=sha("knowledge:compat"),
            domain="analyst",
            unique_task_observations=2,
            unique_reuse_receipts=2,
            isolated_task_observations=2,
            confounded_task_observations=0,
            verified_success_after_reuse=1,
            failed_after_reuse=1,
            waiting_human_after_reuse=0,
            pending_after_reuse=0,
            done_unverified_after_reuse=0,
            isolated_verified_success=1,
            isolated_failed=1,
            isolated_waiting_human=0,
            isolated_done_unverified=0,
            advisory_signal="INSUFFICIENT_EVIDENCE",
        )
        old_shape = KnowledgeEffectivenessSignal(**base)
        enriched = KnowledgeEffectivenessSignal(
            **base,
            validator_resolved_after_reuse=7,
            validator_passed_after_reuse=5,
            isolated_validator_resolved=7,
            isolated_validator_passed=5,
        )
        self.assertEqual(old_shape.to_payload(), enriched.to_payload())
        serialized = json.dumps(enriched.to_payload(), sort_keys=True)
        self.assertNotIn("validator_resolved_after_reuse", serialized)
        self.assertNotIn("normalized_rates", serialized)
        self.assertEqual(enriched.rate_projection().validator_pass_rate.numerator, 5)
        self.assertEqual(enriched.rate_projection().validator_pass_rate.denominator, 7)


if __name__ == "__main__":
    unittest.main()
