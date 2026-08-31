from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.adaptive_learning_admission import VerifiedLearningSourceEnvelope
from three_agent.adaptive_learning_scheduler import (
    AdaptiveLearningScheduler,
    AdaptiveLearningSchedulerConfig,
    LearningSchedulerError,
    LearningSourceHandle,
    LocalLearningSourceProvider,
    ScheduledTaskDomain,
)
from three_agent.artifacts import ArtifactManager
from three_agent.models import TaskStatus
from three_agent.store import TaskStore


EVIDENCE = b"Verified passive observations with read-only correlation."
EVIDENCE_SHA = "sha256:" + hashlib.sha256(EVIDENCE).hexdigest()


def envelope(task_id: str, *, sensitivity: str = "confidential"):
    suffix = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
    return VerifiedLearningSourceEnvelope(
        admission_id="admission:" + suffix,
        task_id=task_id,
        task_type="analysis",
        outcome="verified_success",
        sensitivity=sensitivity,
        risk_level="low",
        contract_sha256="sha256:" + "c" * 64,
        manifest_sha256="sha256:" + "d" * 64,
        validator_provenance_sha256="sha256:" + "e" * 64,
        provenance_sha256="sha256:" + "f" * 64,
        evidence_hashes=(EVIDENCE_SHA,),
        required_validators=("policy", "evidence"),
        capability_grants=(),
    )


class FakeAdmission:
    def __init__(self, *, secret_tasks=()):
        self.calls = []
        self.secret_tasks = set(secret_tasks)

    def admit(self, task_id, manifest_path):
        self.calls.append((task_id, manifest_path))
        return envelope(
            task_id,
            sensitivity="secret" if task_id in self.secret_tasks else "confidential",
        )


class FakeReceiptStore:
    def __init__(self, records=None):
        self.records = dict(records or {})
        self.calls = []

    def read(self, admission_id, domain):
        self.calls.append((admission_id, domain))
        return self.records.get((admission_id, domain))


class FakeReflection:
    def __init__(self, results=None, records=None):
        self.results = dict(results or {})
        self.receipt_store = FakeReceiptStore(records)
        self.calls = []

    def reflect_and_stage(self, source, binding, evidence):
        self.calls.append((source, binding, evidence))
        result = self.results.get(source.task_id, "STAGED")
        if isinstance(result, Exception):
            raise result
        return SimpleNamespace(
            result=result,
            candidate_id=("candidate:" + "a" * 64 if result == "STAGED" else None),
            candidate_sha256=("sha256:" + "b" * 64 if result == "STAGED" else None),
        )


class FakeProvider:
    def __init__(self, task_ids, *, evidence_failures=()):
        self.task_ids = tuple(task_ids)
        self.evidence_failures = set(evidence_failures)
        self.discover_calls = []
        self.manifest_calls = []
        self.evidence_calls = []

    def discover_done(self, configured_task_ids, *, limit):
        self.discover_calls.append((configured_task_ids, limit))
        allowed = set(configured_task_ids)
        return tuple(
            LearningSourceHandle(task_id, f"registered:{task_id}")
            for task_id in self.task_ids
            if task_id in allowed
        )[:limit]

    def manifest_path(self, handle):
        self.manifest_calls.append(handle.task_id)
        return Path(f"/trusted/{handle.task_id}.json")

    def load_evidence(self, task_id, evidence_hashes):
        self.evidence_calls.append((task_id, evidence_hashes))
        if task_id in self.evidence_failures:
            raise LearningSchedulerError("SCHEDULER_EVIDENCE_NOT_RESOLVED")
        return {EVIDENCE_SHA: EVIDENCE}


class Exploding:
    def __getattr__(self, name):
        raise AssertionError(f"disabled scheduler touched {name}")


class IncrementingClock:
    def __init__(self, step):
        self.value = -step
        self.step = step

    def __call__(self):
        self.value += self.step
        return self.value


def config(*task_domains, enabled=True, max_items=4, max_scan_items=16, max_wall=300):
    return AdaptiveLearningSchedulerConfig(
        enabled=enabled,
        max_items=max_items,
        max_scan_items=max_scan_items,
        max_wall_time_seconds=max_wall,
        task_domains=tuple(ScheduledTaskDomain(task_id, domain) for task_id, domain in task_domains),
    )


class SchedulerConfigurationTests(unittest.TestCase):
    def test_disabled_run_touches_no_admission_provider_or_reflection(self):
        scheduler = AdaptiveLearningScheduler(
            config(enabled=False),
            Exploding(),
            Exploding(),
            Exploding(),
            clock=lambda: 10.0,
        )
        receipt = scheduler.run_once()
        self.assertFalse(receipt.enabled)
        self.assertEqual(receipt.attempted, 0)
        self.assertEqual(receipt.stop_reason, "DISABLED")
        self.assertEqual(receipt.outcomes, ())

    def test_config_requires_bounded_canonical_explicit_domain_bindings(self):
        with self.assertRaisesRegex(LearningSchedulerError, "DOMAIN_INVALID"):
            config(("TASK-A", "unknown")).validate()
        with self.assertRaisesRegex(LearningSchedulerError, "DOMAIN_BINDING_NOT_CANONICAL"):
            config(("TASK-A", "Network")).validate()
        with self.assertRaisesRegex(LearningSchedulerError, "DOMAIN_DUPLICATE"):
            config(("TASK-A", "network"), ("TASK-A", "security")).validate()
        with self.assertRaisesRegex(LearningSchedulerError, "SCAN_LIMIT_BELOW_ITEM_LIMIT"):
            config(("TASK-A", "network"), max_items=4, max_scan_items=2).validate()


class LocalSourceProviderTests(unittest.TestCase):
    def _fixture(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        store = TaskStore(root / "tasks.db")
        store.initialize()
        artifacts = ArtifactManager(root / "artifacts")
        task = store.create_task("test", "request")
        store.set_status(task.task_id, TaskStatus.DONE)

        manifest = artifacts.root / "workflow_runs" / "2026-09-01" / f"{task.task_id}.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"task_id": task.task_id}) + "\n", encoding="utf-8")
        store.record_artifact(
            task.task_id,
            "workflow",
            "workflow_manifest_json",
            str(manifest),
        )

        handoff = artifacts.root / "research" / "2026-09-01" / f"{task.task_id}_handoff.json"
        handoff.parent.mkdir(parents=True, exist_ok=True)
        handoff.write_bytes(EVIDENCE)
        store.record_artifact(
            task.task_id,
            "research",
            "research_handoff_json",
            str(handoff),
        )
        return temp, store, artifacts, task, manifest, handoff

    def test_discovers_only_configured_done_task_and_resolves_registered_digest(self):
        temp, store, artifacts, task, manifest, _ = self._fixture()
        self.addCleanup(temp.cleanup)
        other = store.create_task("other", "request")
        store.record_artifact(
            other.task_id,
            "workflow",
            "workflow_manifest_json",
            str(manifest),
        )
        provider = LocalLearningSourceProvider(store, artifacts)
        handles = provider.discover_done((task.task_id, other.task_id), limit=4)
        self.assertEqual([item.task_id for item in handles], [task.task_id])
        self.assertEqual(provider.manifest_path(handles[0]), manifest.resolve())
        self.assertEqual(
            provider.load_evidence(task.task_id, (EVIDENCE_SHA,)),
            {EVIDENCE_SHA: EVIDENCE},
        )

    def test_registered_manifest_outside_artifact_root_fails_closed(self):
        temp, store, artifacts, task, _, _ = self._fixture()
        self.addCleanup(temp.cleanup)
        outside = Path(temp.name) / "outside.json"
        outside.write_text("{}\n", encoding="utf-8")
        store.record_artifact(
            task.task_id,
            "workflow",
            "workflow_manifest_json",
            str(outside),
        )
        handle = LocalLearningSourceProvider(store, artifacts).discover_done(
            (task.task_id,), limit=1
        )[0]
        with self.assertRaisesRegex(LearningSchedulerError, "OUTSIDE_ARTIFACT_ROOT"):
            LocalLearningSourceProvider(store, artifacts).manifest_path(handle)

    def test_evidence_must_match_registered_handoff_bytes_exactly(self):
        temp, store, artifacts, task, _, handoff = self._fixture()
        self.addCleanup(temp.cleanup)
        handoff.write_bytes(b"tampered")
        with self.assertRaisesRegex(LearningSchedulerError, "EVIDENCE_NOT_RESOLVED"):
            LocalLearningSourceProvider(store, artifacts).load_evidence(
                task.task_id, (EVIDENCE_SHA,)
            )


class SchedulerTickTests(unittest.TestCase):
    def test_tick_is_bounded_and_preserves_prebound_domain(self):
        tasks = ("TASK-A", "TASK-B", "TASK-C")
        provider = FakeProvider(tasks)
        reflection = FakeReflection(
            {"TASK-A": "STAGED", "TASK-B": "NO_LEARNING_VALUE", "TASK-C": "STAGED"}
        )
        scheduler = AdaptiveLearningScheduler(
            config(
                ("TASK-A", "network"),
                ("TASK-B", "security"),
                ("TASK-C", "analyst"),
                max_items=2,
            ),
            FakeAdmission(),
            reflection,
            provider,
            clock=lambda: 1.0,
        )
        receipt = scheduler.run_once()
        self.assertEqual(receipt.attempted, 2)
        self.assertEqual(receipt.staged, 1)
        self.assertEqual(receipt.no_learning_value, 1)
        self.assertEqual(receipt.stop_reason, "MAX_ITEMS")
        self.assertEqual(
            [call[1].domain for call in reflection.calls],
            ["network", "security"],
        )
        self.assertEqual(len(reflection.calls), 2)

    def test_completed_and_claimed_receipts_suppress_evidence_and_model_work(self):
        first = envelope("TASK-A")
        second = envelope("TASK-B")
        records = {
            (first.admission_id, "network"): SimpleNamespace(
                status="completed", candidate_sha256="sha256:" + "9" * 64
            ),
            (second.admission_id, "security"): SimpleNamespace(
                status="claimed", candidate_sha256=None
            ),
        }
        provider = FakeProvider(("TASK-A", "TASK-B"))
        reflection = FakeReflection(records=records)
        receipt = AdaptiveLearningScheduler(
            config(("TASK-A", "network"), ("TASK-B", "security")),
            FakeAdmission(),
            reflection,
            provider,
            clock=lambda: 1.0,
        ).run_once()
        self.assertEqual([item.result for item in receipt.outcomes], ["SKIPPED", "RECOVERY_REQUIRED"])
        self.assertEqual(provider.evidence_calls, [])
        self.assertEqual(reflection.calls, [])
        self.assertEqual(receipt.skipped, 1)
        self.assertEqual(receipt.recovery_required, 1)

    def test_source_failure_is_metadata_only_and_does_not_block_next_source(self):
        provider = FakeProvider(("TASK-A", "TASK-B"), evidence_failures=("TASK-A",))
        reflection = FakeReflection({"TASK-B": "STAGED"})
        receipt = AdaptiveLearningScheduler(
            config(("TASK-A", "network"), ("TASK-B", "analyst")),
            FakeAdmission(),
            reflection,
            provider,
            clock=lambda: 1.0,
        ).run_once()
        self.assertEqual(receipt.outcomes[0].result, "REJECTED")
        self.assertEqual(receipt.outcomes[0].reason_code, "SCHEDULER_EVIDENCE_NOT_RESOLVED")
        self.assertEqual(receipt.outcomes[1].result, "STAGED")
        rendered = json.dumps(receipt.to_payload(), sort_keys=True)
        self.assertNotIn(EVIDENCE.decode("utf-8"), rendered)
        self.assertNotIn("/trusted/", rendered)
        self.assertEqual(len(reflection.calls), 1)

    def test_secret_source_fails_before_evidence_or_model_invocation(self):
        provider = FakeProvider(("TASK-A",))
        reflection = FakeReflection()
        receipt = AdaptiveLearningScheduler(
            config(("TASK-A", "security")),
            FakeAdmission(secret_tasks=("TASK-A",)),
            reflection,
            provider,
            clock=lambda: 1.0,
        ).run_once()
        self.assertEqual(receipt.outcomes[0].result, "REJECTED")
        self.assertEqual(receipt.outcomes[0].reason_code, "REFLECTION_SECRET_NOT_SUPPORTED")
        self.assertEqual(provider.evidence_calls, [])
        self.assertEqual(reflection.calls, [])

    def test_wall_time_stops_starting_new_items(self):
        provider = FakeProvider(("TASK-A",))
        receipt = AdaptiveLearningScheduler(
            config(("TASK-A", "analyst"), max_wall=1),
            FakeAdmission(),
            FakeReflection(),
            provider,
            clock=IncrementingClock(2.0),
        ).run_once()
        self.assertEqual(receipt.attempted, 0)
        self.assertEqual(receipt.stop_reason, "WALL_TIME")

    def test_scheduler_exposes_no_promotion_or_operator_mutation_methods(self):
        scheduler = AdaptiveLearningScheduler(
            config(("TASK-A", "analyst")),
            FakeAdmission(),
            FakeReflection(),
            FakeProvider(("TASK-A",)),
        )
        for name in ("promote", "archive", "rollback", "rotate_key", "deploy", "remediate"):
            self.assertFalse(hasattr(scheduler, name))


if __name__ == "__main__":
    unittest.main()
