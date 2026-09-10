from __future__ import annotations

import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from three_agent.runtime_writer_lease import (
    RuntimeWriterLeaseError,
    RuntimeWriterLeaseRepository,
)
from three_agent.store import TaskStore


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class RuntimeWriterLeaseE2ETests(unittest.TestCase):
    """Cross-component acceptance tests for durable writer fencing.

    These tests intentionally exercise TaskStore + SQLite transactions + the
    runtime-writer lease repository together. They verify durable outcomes, not
    only return values from the lease primitive.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "workspace.sqlite3"
        self.store = TaskStore(self.db)
        self.store.initialize()
        self.task = self.store.create_task(
            "runtime writer E2E",
            "prove that only the current runtime generation can commit durable writes",
        )
        self.plan = _sha("runtime-writer-e2e-plan")
        self.repo = RuntimeWriterLeaseRepository(self.store)
        self.repo.initialize()
        with self.store.connect() as conn:
            conn.execute(
                """
                CREATE TABLE e2e_protected_writes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    writer TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def tearDown(self):
        self.tmp.cleanup()

    def _claim(self, run_id: str, minute: int):
        return self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id=run_id,
            issued_at=f"2026-09-09T13:{minute:02d}:00Z",
        )

    def _persist_with_lease(self, repo, lease, payload: str) -> None:
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                repo.require_current_in_transaction(conn, lease)
                conn.execute(
                    "INSERT INTO e2e_protected_writes(writer, payload) VALUES(?, ?)",
                    (lease.run_id, payload),
                )
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def _writes(self):
        with self.store.connect() as conn:
            return conn.execute(
                "SELECT writer, payload FROM e2e_protected_writes ORDER BY id"
            ).fetchall()

    def test_current_writer_can_commit_protected_write(self):
        lease = self._claim("RUN-A", 0)

        self._persist_with_lease(self.repo, lease, "accepted")

        rows = self._writes()
        self.assertEqual([(row["writer"], row["payload"]) for row in rows], [("RUN-A", "accepted")])

    def test_superseded_writer_is_rejected_before_durable_mutation(self):
        stale = self._claim("RUN-A", 0)
        current = self._claim("RUN-B", 1)

        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
            self._persist_with_lease(self.repo, stale, "must-never-commit")
        self._persist_with_lease(self.repo, current, "current-writer")

        rows = self._writes()
        self.assertEqual([(row["writer"], row["payload"]) for row in rows], [("RUN-B", "current-writer")])

    def test_restart_preserves_generation_authority_and_fences_pre_restart_writer(self):
        before_restart = self._claim("RUN-A", 0)

        restarted_store = TaskStore(self.db)
        restarted_store.initialize()
        restarted_repo = RuntimeWriterLeaseRepository(restarted_store)
        restarted_repo.initialize()
        after_restart = restarted_repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-B",
            issued_at="2026-09-09T13:01:00Z",
        )

        self.assertEqual(after_restart.generation, before_restart.generation + 1)
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
            self._persist_with_lease(self.repo, before_restart, "pre-restart-stale")
        self._persist_with_lease(restarted_repo, after_restart, "post-restart-current")

        rows = self._writes()
        self.assertEqual([(row["writer"], row["payload"]) for row in rows], [("RUN-B", "post-restart-current")])

    def test_missing_authority_record_fails_closed_without_partial_commit(self):
        lease = self._claim("RUN-A", 0)
        with self.store.connect() as conn:
            conn.execute(
                "DELETE FROM runtime_writer_leases WHERE task_id=? AND plan_fingerprint=?",
                (self.task.task_id, self.plan),
            )

        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_NOT_FOUND"):
            self._persist_with_lease(self.repo, lease, "must-never-commit")

        self.assertEqual(len(self._writes()), 0)

    def test_tampered_authority_record_fails_closed_without_partial_commit(self):
        lease = self._claim("RUN-A", 0)
        with self.store.connect() as conn:
            conn.execute(
                """
                UPDATE runtime_writer_leases
                SET lease_json='{}'
                WHERE task_id=? AND plan_fingerprint=?
                """,
                (self.task.task_id, self.plan),
            )

        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_DIGEST_MISMATCH"):
            self._persist_with_lease(self.repo, lease, "must-never-commit")

        self.assertEqual(len(self._writes()), 0)

    def test_multiple_contenders_converge_to_one_current_generation(self):
        def claim(index: int):
            local_store = TaskStore(self.db)
            local_repo = RuntimeWriterLeaseRepository(local_store)
            local_repo.initialize()
            return local_repo.claim(
                task_id=self.task.task_id,
                plan_fingerprint=self.plan,
                run_id=f"RUN-{index}",
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            leases = list(executor.map(claim, range(4)))

        generations = sorted(lease.generation for lease in leases)
        self.assertEqual(generations, [1, 2, 3, 4])

        current = self.repo.current(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
        )
        self.assertIsNotNone(current)
        self.assertEqual(current.generation, 4)

        for lease in leases:
            if lease.fingerprint == current.fingerprint:
                self._persist_with_lease(self.repo, lease, "winner")
            else:
                with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
                    self._persist_with_lease(self.repo, lease, "loser-must-never-commit")

        rows = self._writes()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["writer"], current.run_id)
        self.assertEqual(rows[0]["payload"], "winner")
        self.assertTrue(
            self.repo.verify_event_chain(
                task_id=self.task.task_id,
                plan_fingerprint=self.plan,
            )
        )


if __name__ == "__main__":
    unittest.main()
