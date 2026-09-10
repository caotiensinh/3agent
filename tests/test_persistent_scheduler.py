from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from three_agent.persistent_scheduler import (
    PersistentSchedulerError,
    PersistentWallClockScheduler,
)
from three_agent.store import TaskStore


class PersistentWallClockSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.db")
        self.store.initialize()
        self.task = self.store.create_task("scheduled test", "bounded scheduled task")
        self.store.bind_task_contract(
            self.task.task_id,
            {
                "schema_version": "workspace-task-contract/v1",
                "task_id": self.task.task_id,
                "test_fixture": True,
            },
        )
        self.scheduler = PersistentWallClockScheduler(self.store)
        self.scheduler.initialize()
        self.t0 = datetime(2026, 9, 9, 0, 7, tzinfo=timezone.utc)

    def tearDown(self):
        self.tmp.cleanup()

    def test_interval_claim_persists_across_restart_and_coalesces(self):
        schedule = self.scheduler.register_interval(
            "sched:interval",
            self.task.task_id,
            60,
            start_at=self.t0,
            now=self.t0,
        )
        self.assertEqual(schedule.next_run_at, self.t0.isoformat())

        restarted = PersistentWallClockScheduler(self.store)
        restarted.initialize()
        claims = restarted.claim_due(now=self.t0, lease_seconds=60)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0].schedule_id, "sched:interval")
        self.assertEqual(claims[0].scheduled_for, self.t0.isoformat())

        # The claimed occurrence is durably advanced; a duplicate tick cannot
        # claim the same occurrence again.
        self.assertEqual(restarted.claim_due(now=self.t0, lease_seconds=60), ())
        advanced = restarted.get("sched:interval")
        self.assertEqual(
            advanced.next_run_at,
            (self.t0 + timedelta(seconds=60)).isoformat(),
        )

    def test_cron_uses_standard_five_field_matching(self):
        schedule = self.scheduler.register_cron(
            "sched:cron",
            self.task.task_id,
            "*/15 * * * *",
            timezone_name="UTC",
            now=self.t0,
        )
        self.assertEqual(
            schedule.next_run_at,
            datetime(2026, 9, 9, 0, 15, tzinfo=timezone.utc).isoformat(),
        )

        with self.assertRaisesRegex(
            PersistentSchedulerError,
            "CRON_EXPRESSION_REQUIRES_FIVE_FIELDS",
        ):
            self.scheduler.register_cron(
                "sched:bad-cron",
                self.task.task_id,
                "* * * *",
                now=self.t0,
            )

    def test_missing_bound_contract_auto_disables_due_schedule(self):
        self.scheduler.register_interval(
            "sched:contract",
            self.task.task_id,
            60,
            start_at=self.t0,
            now=self.t0,
        )
        with self.store.connect() as conn:
            conn.execute("DELETE FROM task_contracts WHERE task_id=?", (self.task.task_id,))

        self.assertEqual(self.scheduler.claim_due(now=self.t0), ())
        schedule = self.scheduler.get("sched:contract")
        self.assertFalse(schedule.enabled)
        self.assertEqual(schedule.last_error, "SCHEDULE_TASK_CONTRACT_REQUIRED")

    def test_expired_claim_requires_reconciliation_before_next_occurrence(self):
        self.scheduler.register_interval(
            "sched:recovery",
            self.task.task_id,
            60,
            start_at=self.t0,
            now=self.t0,
        )
        first = self.scheduler.claim_due(now=self.t0, lease_seconds=60)
        self.assertEqual(len(first), 1)

        recovery_time = self.t0 + timedelta(seconds=61)
        recovery = self.scheduler.mark_expired_claims_recovery_required(now=recovery_time)
        self.assertEqual(len(recovery), 1)
        self.assertEqual(recovery[0].claim_id, first[0].claim_id)
        self.assertEqual(recovery[0].status, "RECOVERY_REQUIRED")

        # Fail closed: the next wall-clock occurrence must not overlap an
        # unresolved claim whose execution outcome is unknown.
        self.assertEqual(self.scheduler.claim_due(now=recovery_time), ())

        terminal = self.scheduler.complete_claim(
            first[0].claim_id,
            "FAILED",
            details={"reason": "worker outcome unknown after lease expiry"},
            now=recovery_time,
        )
        self.assertEqual(terminal.status, "FAILED")
        next_claim = self.scheduler.claim_due(now=recovery_time)
        self.assertEqual(len(next_claim), 1)
        self.assertNotEqual(next_claim[0].claim_id, first[0].claim_id)

    def test_event_chain_detects_tamper(self):
        self.scheduler.register_interval(
            "sched:audit",
            self.task.task_id,
            60,
            start_at=self.t0,
            now=self.t0,
        )
        claim = self.scheduler.claim_due(now=self.t0)[0]
        self.scheduler.complete_claim(claim.claim_id, "SUCCEEDED", now=self.t0)
        self.assertTrue(self.scheduler.verify_event_chain())

        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT sequence,details_json FROM schedule_events ORDER BY sequence LIMIT 1"
            ).fetchone()
            details = json.loads(str(row["details_json"]))
            details["tampered"] = True
            conn.execute(
                "UPDATE schedule_events SET details_json=? WHERE sequence=?",
                (json.dumps(details), int(row["sequence"])),
            )
        self.assertFalse(self.scheduler.verify_event_chain())

    def test_registration_requires_existing_task_contract(self):
        other = self.store.create_task("no contract", "should fail closed")
        with self.assertRaisesRegex(
            PersistentSchedulerError,
            "SCHEDULE_TASK_CONTRACT_REQUIRED",
        ):
            self.scheduler.register_interval(
                "sched:no-contract",
                other.task_id,
                60,
                start_at=self.t0,
                now=self.t0,
            )


if __name__ == "__main__":
    unittest.main()
