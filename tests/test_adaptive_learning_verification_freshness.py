from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_effectiveness import record_learning_reuse
from three_agent.adaptive_learning_retrieval import LearningContext, LearningContextItem
from three_agent.adaptive_learning_verification_freshness import (
    VERIFICATION_FRESHNESS_SCHEMA,
    DeterministicLearningVerificationFreshnessProjector,
    LearningVerificationFreshnessError,
)
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class LearningVerificationFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = TaskStore(self.root / "tasks.db")
        self.store.initialize()
        self.compiler = TaskContractCompiler()
        self.ledger = ValidatorLedger(self.store)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def task(self, name: str) -> tuple[str, tuple[str, ...]]:
        task = self.store.create_task(f"Freshness {name}", f"PRIVATE-REQUEST-{name}")
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
            title=f"Freshness {name}",
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

    def make_verified(self, task_id: str, validators: tuple[str, ...], *, verified_at: str) -> None:
        for index, validator in enumerate(validators, start=1):
            self.ledger.record(
                task_id,
                validator,
                status="passed",
                reason_code=f"FRESHNESS_{validator.upper()}_PASS",
                evidence_refs=(sha(f"{task_id}:{validator}"),),
                validator_version="freshness-test/v1",
                attempt=index,
            )
        self.store.set_status(task_id, TaskStatus.DONE)
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET updated_at=? WHERE task_id=?", (verified_at, task_id))
            conn.execute(
                "UPDATE validator_results SET timestamp=? WHERE task_id=?",
                (verified_at, task_id),
            )

    def projection(self, item: LearningContextItem):
        snapshot = DeterministicLearningVerificationFreshnessProjector(self.store).snapshot()
        matches = [
            projection
            for projection in snapshot.projections
            if projection.knowledge_sha256 == item.knowledge_sha256
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_verified_task_projects_canonical_utc_last_verified_timestamp(self):
        item = self.item("one")
        task_id, validators = self.task("one")
        record_learning_reuse(self.store, task_id, self.context(item, query="one"))
        self.make_verified(task_id, validators, verified_at="2030-01-02T12:34:56+09:00")

        projection = self.projection(item)

        self.assertEqual(projection.schema_version, VERIFICATION_FRESHNESS_SCHEMA)
        self.assertEqual(projection.verified_task_observations, 1)
        self.assertEqual(projection.isolated_verified_task_observations, 1)
        self.assertEqual(projection.last_verified_at, "2030-01-02T03:34:56Z")
        self.assertEqual(projection.last_isolated_verified_at, "2030-01-02T03:34:56Z")
        self.assertRegex(projection.projection_sha256, r"^sha256:[0-9a-f]{64}$")

    def test_latest_verified_task_wins_without_counting_duplicate_reuse_receipts(self):
        item = self.item("latest")
        first, first_validators = self.task("first")
        context = self.context(item, query="first")
        record_learning_reuse(self.store, first, context)
        record_learning_reuse(self.store, first, context)
        self.make_verified(first, first_validators, verified_at="2030-01-01T00:00:00Z")

        second, second_validators = self.task("second")
        record_learning_reuse(self.store, second, self.context(item, query="second"))
        self.make_verified(second, second_validators, verified_at="2030-02-01T00:00:00Z")

        projection = self.projection(item)
        self.assertEqual(projection.verified_task_observations, 2)
        self.assertEqual(projection.isolated_verified_task_observations, 2)
        self.assertEqual(projection.last_verified_at, "2030-02-01T00:00:00Z")
        self.assertEqual(projection.last_isolated_verified_at, "2030-02-01T00:00:00Z")

    def test_confounded_verified_task_updates_overall_but_not_isolated_freshness(self):
        first = self.item("confounded-one")
        second = self.item("confounded-two")
        task_id, validators = self.task("confounded")
        record_learning_reuse(
            self.store,
            task_id,
            self.context(first, second, query="confounded"),
        )
        self.make_verified(task_id, validators, verified_at="2030-03-01T00:00:00Z")

        snapshot = DeterministicLearningVerificationFreshnessProjector(self.store).snapshot()
        self.assertEqual(len(snapshot.projections), 2)
        for projection in snapshot.projections:
            self.assertEqual(projection.verified_task_observations, 1)
            self.assertEqual(projection.last_verified_at, "2030-03-01T00:00:00Z")
            self.assertEqual(projection.isolated_verified_task_observations, 0)
            self.assertIsNone(projection.last_isolated_verified_at)

    def test_failed_pending_and_done_unverified_never_create_verified_timestamp(self):
        item = self.item("nonverified")

        failed, _ = self.task("failed")
        record_learning_reuse(self.store, failed, self.context(item, query="failed"))
        self.store.set_status(failed, TaskStatus.FAILED)

        pending, _ = self.task("pending")
        record_learning_reuse(self.store, pending, self.context(item, query="pending"))

        unverified, _ = self.task("unverified")
        record_learning_reuse(self.store, unverified, self.context(item, query="unverified"))
        self.store.set_status(unverified, TaskStatus.DONE)

        projection = self.projection(item)
        self.assertEqual(projection.verified_task_observations, 0)
        self.assertEqual(projection.isolated_verified_task_observations, 0)
        self.assertIsNone(projection.last_verified_at)
        self.assertIsNone(projection.last_isolated_verified_at)

    def test_verified_chronology_before_reuse_fails_closed(self):
        item = self.item("chronology")
        task_id, validators = self.task("chronology")
        record_learning_reuse(self.store, task_id, self.context(item, query="chronology"))
        self.make_verified(task_id, validators, verified_at="2020-01-01T00:00:00Z")

        with self.assertRaisesRegex(
            LearningVerificationFreshnessError,
            "VERIFICATION_FRESHNESS_VERIFICATION_PRECEDES_REUSE",
        ):
            DeterministicLearningVerificationFreshnessProjector(self.store).snapshot()

    def test_projection_is_deterministic_metadata_only_and_has_no_mutation_surface(self):
        item = self.item("privacy")
        task_id, validators = self.task("privacy")
        record_learning_reuse(self.store, task_id, self.context(item, query="privacy"))
        self.make_verified(task_id, validators, verified_at="2030-04-01T00:00:00Z")
        projector = DeterministicLearningVerificationFreshnessProjector(self.store)

        first = projector.snapshot().to_payload()
        second = projector.snapshot().to_payload()
        self.assertEqual(first, second)
        serialized = json.dumps(first, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(item.content, serialized)
        self.assertNotIn("PRIVATE-REQUEST-privacy", serialized)
        self.assertNotIn(task_id, serialized)
        self.assertNotIn("evidence_refs", serialized)
        self.assertRegex(first["snapshot_sha256"], r"^sha256:[0-9a-f]{64}$")
        for forbidden in (
            "promote",
            "stage",
            "archive",
            "rollback",
            "materialize",
            "execute",
            "invoke",
        ):
            self.assertFalse(hasattr(projector, forbidden), forbidden)


if __name__ == "__main__":
    unittest.main()
