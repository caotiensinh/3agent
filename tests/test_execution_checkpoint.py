from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.execution_checkpoint import (
    ExecutionCheckpointError,
    ExecutionCheckpointRepository,
)
from three_agent.execution_observation import ExecutionObservation
from three_agent.execution_scheduler import DispatchTicket
from three_agent.store import TaskStore


def _canonical_json(payload):
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity_digest(payload) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _ticket(task_id: str, *, node_id: str = "lane-a", sequence: int = 1) -> DispatchTicket:
    provisional = DispatchTicket(
        ticket_id="dispatch:" + "0" * 24,
        task_id=task_id,
        plan_fingerprint=_sha("plan"),
        node_id=node_id,
        node_fingerprint=_sha("node:" + node_id),
        authority_fingerprint=_sha("authority:" + node_id),
        dependency_observation_fingerprints=(),
        dispatch_sequence=sequence,
        execution_level=1,
    )
    ticket_id = "dispatch:" + _identity_digest(provisional._identity_dict()).split(":", 1)[1][:24]
    return DispatchTicket(
        ticket_id=ticket_id,
        task_id=provisional.task_id,
        plan_fingerprint=provisional.plan_fingerprint,
        node_id=provisional.node_id,
        node_fingerprint=provisional.node_fingerprint,
        authority_fingerprint=provisional.authority_fingerprint,
        dependency_observation_fingerprints=provisional.dependency_observation_fingerprints,
        dispatch_sequence=provisional.dispatch_sequence,
        execution_level=provisional.execution_level,
        schema_version=provisional.schema_version,
    ).validate()


def _observation(ticket: DispatchTicket, *, status: str = "SUCCEEDED") -> ExecutionObservation:
    output_json = _canonical_json({"node": ticket.node_id, "status": status})
    provisional = ExecutionObservation(
        observation_id="observation:" + "0" * 24,
        task_id=ticket.task_id,
        task_context_fingerprint=_sha("context"),
        plan_fingerprint=ticket.plan_fingerprint,
        node_id=ticket.node_id,
        node_fingerprint=ticket.node_fingerprint,
        authority_fingerprint=ticket.authority_fingerprint,
        status=status,
        started_at="2026-09-09T00:00:00Z",
        finished_at="2026-09-09T00:00:01Z",
        normalized_output_json=output_json,
        error_class=None if status != "FAILED" else "TOOL_ERROR",
        evidence_bindings=(),
        cost=None,
    )
    observation_id = "observation:" + _identity_digest(provisional._identity_dict()).split(":", 1)[1][:24]
    return ExecutionObservation(
        observation_id=observation_id,
        task_id=provisional.task_id,
        task_context_fingerprint=provisional.task_context_fingerprint,
        plan_fingerprint=provisional.plan_fingerprint,
        node_id=provisional.node_id,
        node_fingerprint=provisional.node_fingerprint,
        authority_fingerprint=provisional.authority_fingerprint,
        status=provisional.status,
        started_at=provisional.started_at,
        finished_at=provisional.finished_at,
        normalized_output_json=provisional.normalized_output_json,
        error_class=provisional.error_class,
        evidence_bindings=provisional.evidence_bindings,
        cost=provisional.cost,
        schema_version=provisional.schema_version,
    ).validate()


class ExecutionCheckpointRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "workspace.sqlite3"
        self.store = TaskStore(self.db)
        self.store.initialize()
        self.task = self.store.create_task("checkpoint", "persist execution state")
        self.repo = ExecutionCheckpointRepository(self.store)
        self.repo.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def test_completed_dispatch_round_trips_without_recovery_requirement(self):
        ticket = _ticket(self.task.task_id)
        observation = _observation(ticket)
        self.repo.record_dispatch(ticket)
        self.repo.record_observation(observation)

        recovered = self.repo.load(
            task_id=self.task.task_id,
            plan_fingerprint=ticket.plan_fingerprint,
        )
        self.assertEqual(recovered.dispatches, (ticket,))
        self.assertEqual(recovered.observations, (observation,))
        self.assertEqual(recovered.recovery_required_ticket_ids, ())
        self.assertEqual(recovered.max_dispatch_sequence, 1)
        self.assertTrue(
            self.repo.verify_event_chain(
                task_id=self.task.task_id,
                plan_fingerprint=ticket.plan_fingerprint,
            )
        )

    def test_unfinished_dispatch_is_recovered_fail_closed(self):
        ticket = _ticket(self.task.task_id)
        self.repo.record_dispatch(ticket)

        recovered = self.repo.load(
            task_id=self.task.task_id,
            plan_fingerprint=ticket.plan_fingerprint,
        )
        self.assertEqual(recovered.observations, ())
        self.assertEqual(recovered.recovery_required_ticket_ids, (ticket.ticket_id,))

    def test_observation_requires_persisted_exact_dispatch(self):
        ticket = _ticket(self.task.task_id)
        observation = _observation(ticket)
        with self.assertRaisesRegex(
            ExecutionCheckpointError,
            "OBSERVATION_CHECKPOINT_REQUIRES_DISPATCH",
        ):
            self.repo.record_observation(observation)

    def test_duplicate_node_dispatch_with_new_identity_is_denied(self):
        first = _ticket(self.task.task_id, sequence=1)
        second = _ticket(self.task.task_id, sequence=2)
        self.repo.record_dispatch(first)
        with self.assertRaisesRegex(
            ExecutionCheckpointError,
            "DISPATCH_CHECKPOINT_NODE_CONFLICT",
        ):
            self.repo.record_dispatch(second)

    def test_idempotent_replay_does_not_append_duplicate_event(self):
        ticket = _ticket(self.task.task_id)
        self.repo.record_dispatch(ticket)
        self.repo.record_dispatch(ticket)
        with self.store.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM execution_checkpoint_events"
            ).fetchone()["n"]
        self.assertEqual(count, 1)

    def test_cancellation_is_persisted_without_replaying_work(self):
        ticket = _ticket(self.task.task_id)
        self.repo.record_dispatch(ticket)
        self.repo.record_cancellation(
            task_id=self.task.task_id,
            plan_fingerprint=ticket.plan_fingerprint,
            reason_code="OPERATOR_CANCELLED",
        )
        recovered = self.repo.load(
            task_id=self.task.task_id,
            plan_fingerprint=ticket.plan_fingerprint,
        )
        self.assertEqual(recovered.cancellation_reason, "OPERATOR_CANCELLED")
        self.assertEqual(recovered.recovery_required_ticket_ids, (ticket.ticket_id,))

    def test_event_chain_tamper_is_detected(self):
        ticket = _ticket(self.task.task_id)
        self.repo.record_dispatch(ticket)
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE execution_checkpoint_events SET event_type='TAMPERED' WHERE sequence=1"
            )
        self.assertFalse(
            self.repo.verify_event_chain(
                task_id=self.task.task_id,
                plan_fingerprint=ticket.plan_fingerprint,
            )
        )
        with self.assertRaisesRegex(
            ExecutionCheckpointError,
            "EXECUTION_CHECKPOINT_EVENT_CHAIN_INVALID",
        ):
            self.repo.load(
                task_id=self.task.task_id,
                plan_fingerprint=ticket.plan_fingerprint,
            )

    def test_dispatch_record_tamper_is_detected_even_with_intact_event_chain(self):
        ticket = _ticket(self.task.task_id)
        self.repo.record_dispatch(ticket)
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE execution_dispatch_checkpoints SET ticket_json='{}' WHERE ticket_id=?",
                (ticket.ticket_id,),
            )
        with self.assertRaisesRegex(
            ExecutionCheckpointError,
            "DISPATCH_CHECKPOINT_DIGEST_MISMATCH",
        ):
            self.repo.load(
                task_id=self.task.task_id,
                plan_fingerprint=ticket.plan_fingerprint,
            )


if __name__ == "__main__":
    unittest.main()
