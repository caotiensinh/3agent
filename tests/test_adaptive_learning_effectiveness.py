from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_effectiveness import (
    DeterministicLearningEffectivenessAnalyzer,
    LearningEffectivenessError,
    LearningReuseReceipt,
    OUTCOME_DONE_UNVERIFIED,
    SIGNAL_DOMAIN_REVIEW,
    SIGNAL_INSUFFICIENT,
    SIGNAL_REVIEW,
    SIGNAL_SUPPORT,
    record_learning_reuse,
)
from three_agent.adaptive_learning_retrieval import LearningContext, LearningContextItem
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class LearningEffectivenessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = TaskStore(self.root / "tasks.db")
        self.store.initialize()
        self.compiler = TaskContractCompiler()
        self.ledger = ValidatorLedger(self.store)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def task(self, *, sensitivity: str = "confidential") -> str:
        task = self.store.create_task("Phase4H", "local verified task")
        contract = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity=sensitivity,
            risk_level="low",
        )
        self.ledger.bind_contract(contract)
        return task.task_id

    def verify(self, task_id: str) -> None:
        contract = self.store.task_contract_for_task(task_id)
        assert isinstance(contract, dict)
        for index, validator in enumerate(contract["validators"], start=1):
            self.ledger.record(
                task_id,
                validator,
                status="passed",
                reason_code=f"PHASE4H_{validator.upper()}_PASS",
                evidence_refs=(sha(f"{task_id}:{validator}"),),
                validator_version="phase4h-test/v1",
                attempt=index,
            )
        self.store.set_status(task_id, TaskStatus.DONE)

    @staticmethod
    def item(name: str, *, domain: str = "analyst") -> LearningContextItem:
        return LearningContextItem(
            item_id=f"knowledge:{name}",
            knowledge_sha256=sha(f"knowledge:{name}"),
            level="approved",
            domain=domain,
            kind="skill",
            title=f"Title {name}",
            content=f"Reusable verified procedure {name}",
            scope="local analysis",
            sensitivity="confidential",
            risk_level="medium",
            execution_mode="analysis_only",
        ).validate()

    @classmethod
    def context(
        cls,
        *items: LearningContextItem,
        domain: str = "analyst",
        query: str = "default",
    ) -> LearningContext:
        return LearningContext(
            query_sha256=sha(f"query:{query}"),
            domain=domain,
            task_sensitivity="confidential",
            items=tuple(items),
        ).validate()

    def signal(self, item: LearningContextItem):
        snapshot = DeterministicLearningEffectivenessAnalyzer(self.store).snapshot()
        matches = [s for s in snapshot.signals if s.knowledge_sha256 == item.knowledge_sha256]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_reuse_receipt_is_deterministic_metadata_only_and_task_bound(self):
        task_id = self.task()
        item = self.item("one")
        context = self.context(item)
        first = LearningReuseReceipt.create(task_id, context)
        second = LearningReuseReceipt.create(task_id, context)
        self.assertEqual(first, second)
        self.assertEqual(first.receipt_id, second.receipt_id)

        payload = first.to_payload()
        serialized = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["task_id"], task_id)
        self.assertEqual(payload["items"][0]["knowledge_sha256"], item.knowledge_sha256)
        for forbidden in (
            item.content,
            "local verified task",
            "/var/lib/workspace",
            "password=secret",
            "model_output",
            "evidence_bytes",
            "raw_request",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_record_reuse_requires_exact_bound_task_sensitivity(self):
        task_id = self.task(sensitivity="internal")
        item = self.item("one")
        context = self.context(item)
        with self.assertRaisesRegex(LearningEffectivenessError, "sensitivity mismatch"):
            record_learning_reuse(self.store, task_id, context)

    def test_duplicate_receipts_and_multiple_queries_do_not_inflate_task_observation(self):
        task_id = self.task()
        item = self.item("dedupe")
        first = self.context(item, query="one")
        second = self.context(item, query="two")
        record_learning_reuse(self.store, task_id, first)
        record_learning_reuse(self.store, task_id, first)
        record_learning_reuse(self.store, task_id, second)
        self.verify(task_id)

        signal = self.signal(item)
        self.assertEqual(signal.unique_task_observations, 1)
        self.assertEqual(signal.unique_reuse_receipts, 2)
        self.assertEqual(signal.verified_success_after_reuse, 1)
        self.assertEqual(signal.isolated_verified_success, 1)

    def test_done_without_fresh_validator_verification_is_not_success(self):
        task_id = self.task()
        item = self.item("unverified")
        record_learning_reuse(self.store, task_id, self.context(item))
        self.store.set_status(task_id, TaskStatus.DONE)

        signal = self.signal(item)
        self.assertEqual(signal.verified_success_after_reuse, 0)
        self.assertEqual(signal.done_unverified_after_reuse, 1)
        self.assertEqual(signal.isolated_done_unverified, 1)
        self.assertEqual(signal.advisory_signal, SIGNAL_INSUFFICIENT)

    def test_three_isolated_verified_successes_emit_support_not_promotion(self):
        item = self.item("support")
        for index in range(3):
            task_id = self.task()
            record_learning_reuse(
                self.store,
                task_id,
                self.context(item, query=f"support-{index}"),
            )
            self.verify(task_id)

        signal = self.signal(item)
        self.assertEqual(signal.isolated_verified_success, 3)
        self.assertEqual(signal.advisory_signal, SIGNAL_SUPPORT)
        self.assertEqual(signal.interpretation, "observational_non_causal")
        analyzer = DeterministicLearningEffectivenessAnalyzer(self.store)
        for forbidden in (
            "promote",
            "archive",
            "rollback",
            "delete",
            "remediate",
            "rotate_key",
            "stage",
        ):
            self.assertFalse(hasattr(analyzer, forbidden), forbidden)

    def test_multi_item_task_is_confounded_for_every_item(self):
        task_id = self.task()
        one = self.item("confounded-one")
        two = self.item("confounded-two")
        record_learning_reuse(self.store, task_id, self.context(one, two))
        self.verify(task_id)

        snapshot = DeterministicLearningEffectivenessAnalyzer(self.store).snapshot()
        self.assertEqual(len(snapshot.signals), 2)
        for signal in snapshot.signals:
            self.assertEqual(signal.unique_task_observations, 1)
            self.assertEqual(signal.confounded_task_observations, 1)
            self.assertEqual(signal.isolated_task_observations, 0)
            self.assertEqual(signal.isolated_verified_success, 0)
            self.assertEqual(signal.advisory_signal, SIGNAL_INSUFFICIENT)

    def test_any_other_knowledge_seen_in_same_task_keeps_observation_confounded(self):
        task_id = self.task()
        one = self.item("mixed-one")
        two = self.item("mixed-two")
        record_learning_reuse(self.store, task_id, self.context(one, query="solo-first"))
        record_learning_reuse(self.store, task_id, self.context(one, two, query="later-multi"))
        self.verify(task_id)

        one_signal = self.signal(one)
        self.assertEqual(one_signal.confounded_task_observations, 1)
        self.assertEqual(one_signal.isolated_task_observations, 0)
        self.assertEqual(one_signal.isolated_verified_success, 0)

    def test_network_security_review_threshold_is_stricter(self):
        network_item = self.item("network-adverse", domain="network")
        task_id = self.task()
        record_learning_reuse(
            self.store,
            task_id,
            self.context(network_item, domain="network"),
        )
        self.store.set_status(task_id, TaskStatus.FAILED)
        self.assertEqual(self.signal(network_item).advisory_signal, SIGNAL_DOMAIN_REVIEW)

        analyst_item = self.item("analyst-adverse")
        first = self.task()
        record_learning_reuse(self.store, first, self.context(analyst_item, query="a1"))
        self.store.set_status(first, TaskStatus.FAILED)
        self.assertEqual(self.signal(analyst_item).advisory_signal, SIGNAL_INSUFFICIENT)

        second = self.task()
        record_learning_reuse(self.store, second, self.context(analyst_item, query="a2"))
        self.store.set_status(second, TaskStatus.FAILED)
        self.assertEqual(self.signal(analyst_item).advisory_signal, SIGNAL_REVIEW)

    def test_waiting_and_pending_remain_distinct_non_final_observations(self):
        item = self.item("nonfinal")
        waiting = self.task()
        record_learning_reuse(self.store, waiting, self.context(item, query="waiting"))
        self.store.set_status(waiting, TaskStatus.WAITING_HUMAN)

        pending = self.task()
        record_learning_reuse(self.store, pending, self.context(item, query="pending"))

        signal = self.signal(item)
        self.assertEqual(signal.waiting_human_after_reuse, 1)
        self.assertEqual(signal.pending_after_reuse, 1)
        self.assertEqual(signal.verified_success_after_reuse, 0)

    def test_tampered_receipt_fails_closed_instead_of_skewing_metrics(self):
        task_id = self.task()
        item = self.item("tamper")
        receipt = LearningReuseReceipt.create(task_id, self.context(item))
        payload = receipt.to_payload()
        payload["query_sha256"] = sha("tampered-query")
        self.store.record_activity(
            task_id,
            "learning_effectiveness",
            "learning_reuse_observed",
            "ok",
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )
        with self.assertRaisesRegex(LearningEffectivenessError, "REUSE_RECEIPT_INVALID"):
            DeterministicLearningEffectivenessAnalyzer(self.store).snapshot()

    def test_snapshot_is_deterministic_and_metadata_only(self):
        task_id = self.task()
        item = self.item("snapshot")
        record_learning_reuse(self.store, task_id, self.context(item))
        self.verify(task_id)
        analyzer = DeterministicLearningEffectivenessAnalyzer(self.store)
        first = analyzer.snapshot().to_payload()
        second = analyzer.snapshot().to_payload()
        self.assertEqual(first, second)
        self.assertRegex(first["snapshot_sha256"], r"^sha256:[0-9a-f]{64}$")
        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn(item.content, serialized)
        self.assertNotIn("local verified task", serialized)
        self.assertNotIn("evidence_refs", serialized)


if __name__ == "__main__":
    unittest.main()
