from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from three_agent.runtime_writer_lease import (
    RuntimeWriterLease,
    RuntimeWriterLeaseError,
    RuntimeWriterLeaseRepository,
)
from three_agent.store import TaskStore


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class RuntimeWriterLeaseRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "workspace.sqlite3"
        self.store = TaskStore(self.db)
        self.store.initialize()
        self.task = self.store.create_task("writer lease", "fence stale runtime writers")
        self.plan = _sha("plan")
        self.repo = RuntimeWriterLeaseRepository(self.store)
        self.repo.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_claim_is_generation_one_and_current(self):
        lease = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        self.assertEqual(lease.generation, 1)
        self.assertEqual(lease.status, "ACTIVE")
        self.assertEqual(self.repo.current(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
        ), lease)
        self.assertEqual(self.repo.require_current(lease), lease)
        self.assertTrue(self.repo.verify_event_chain(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
        ))

    def test_same_active_run_claim_is_idempotent(self):
        first = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        second = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:05:00Z",
        )
        self.assertEqual(second, first)
        with self.store.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM runtime_writer_lease_events"
            ).fetchone()["n"]
        self.assertEqual(count, 1)

    def test_new_run_increments_generation_and_fences_old_writer(self):
        first = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        second = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-B",
            issued_at="2026-09-09T13:01:00Z",
        )
        self.assertEqual(second.generation, 2)
        self.assertEqual(self.repo.require_current(second), second)
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
            self.repo.require_current(first)

    def test_enforcement_can_share_callers_write_transaction(self):
        lease = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = self.repo.require_current_in_transaction(conn, lease)
            self.assertEqual(current, lease)
            conn.execute("ROLLBACK")

    def test_release_is_idempotent_and_blocks_further_writes(self):
        lease = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        released = self.repo.release(lease, released_at="2026-09-09T13:02:00Z")
        replayed = self.repo.release(lease, released_at="2026-09-09T13:03:00Z")
        self.assertEqual(replayed, released)
        self.assertEqual(released.status, "RELEASED")
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_NOT_ACTIVE"):
            self.repo.require_current(lease)
        self.assertTrue(self.repo.verify_event_chain(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
        ))

    def test_released_generation_can_be_superseded_but_never_reactivated(self):
        first = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        self.repo.release(first, released_at="2026-09-09T13:01:00Z")
        second = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:02:00Z",
        )
        self.assertEqual(second.generation, 2)
        self.assertNotEqual(second.fingerprint, first.fingerprint)
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
            self.repo.require_current(first)

    def test_stale_writer_cannot_release_new_owner(self):
        first = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        second = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-B",
            issued_at="2026-09-09T13:01:00Z",
        )
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
            self.repo.release(first, released_at="2026-09-09T13:02:00Z")
        self.assertEqual(self.repo.require_current(second), second)

    def test_lease_row_tamper_is_detected(self):
        self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        with self.store.connect() as conn:
            conn.execute(
                """
                UPDATE runtime_writer_leases
                SET lease_json = '{}'
                WHERE task_id = ? AND plan_fingerprint = ?
                """,
                (self.task.task_id, self.plan),
            )
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_DIGEST_MISMATCH"):
            self.repo.current(
                task_id=self.task.task_id,
                plan_fingerprint=self.plan,
            )

    def test_event_chain_tamper_is_detected(self):
        self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            issued_at="2026-09-09T13:00:00Z",
        )
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE runtime_writer_lease_events SET event_type='TAMPERED' WHERE sequence=1"
            )
        self.assertFalse(self.repo.verify_event_chain(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
        ))

    def test_invalid_or_missing_scope_fails_closed(self):
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "INVALID_PLAN_FINGERPRINT"):
            self.repo.claim(
                task_id=self.task.task_id,
                plan_fingerprint="not-a-digest",
                run_id="RUN-A",
            )
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_TASK_NOT_FOUND"):
            self.repo.claim(
                task_id="TASK-DOES-NOT-EXIST",
                plan_fingerprint=self.plan,
                run_id="RUN-A",
                issued_at="2026-09-09T13:00:00Z",
            )

    def test_runtime_writer_lease_is_immutable_and_canonical(self):
        lease = RuntimeWriterLease(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-A",
            generation=1,
            issued_at="2026-09-09T13:00:00Z",
        ).validate()
        self.assertEqual(lease.canonical_dict()["generation"], 1)
        self.assertRegex(lease.fingerprint, r"^sha256:[0-9a-f]{64}$")
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "INVALID_WRITER_GENERATION"):
            RuntimeWriterLease(
                task_id=self.task.task_id,
                plan_fingerprint=self.plan,
                run_id="RUN-A",
                generation=0,
                issued_at="2026-09-09T13:00:00Z",
            ).validate()


if __name__ == "__main__":
    unittest.main()
