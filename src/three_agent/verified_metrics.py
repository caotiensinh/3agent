from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .store import TaskStore
from .validator_ledger import ValidatorLedger


@dataclass(frozen=True)
class VerifiedWorkMetrics:
    attempted_tasks: int
    contract_bound_tasks: int
    unbound_tasks: int
    verified_tasks: int
    first_pass_verified_tasks: int
    verified_task_success_rate: float
    first_pass_verified_success_rate: float
    missing_validator_counts: dict[str, int]
    failed_validator_counts: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "schema_version": "workspace-verified-work-metrics/v1",
            "attempted_tasks": self.attempted_tasks,
            "contract_bound_tasks": self.contract_bound_tasks,
            "unbound_tasks": self.unbound_tasks,
            "verified_tasks": self.verified_tasks,
            "first_pass_verified_tasks": self.first_pass_verified_tasks,
            "verified_task_success_rate": self.verified_task_success_rate,
            "first_pass_verified_success_rate": self.first_pass_verified_success_rate,
            "missing_validator_counts": dict(sorted(self.missing_validator_counts.items())),
            "failed_validator_counts": dict(sorted(self.failed_validator_counts.items())),
        }


class VerifiedWorkMetricAggregator:
    """Aggregate D3-01/D3-02 from contract-bound validator evidence only.

    TaskStatus, workflow outcome strings and model self-reports are deliberately
    excluded from the definition of verified success. Unbound tasks remain in the
    attempted denominator, making instrumentation gaps visible rather than silently
    improving the success rate.
    """

    def __init__(self, store: TaskStore):
        self.store = store
        self.ledger = ValidatorLedger(store)

    @staticmethod
    def _rate(numerator: int, denominator: int) -> float:
        if denominator <= 0:
            return 0.0
        return round(numerator / denominator, 6)

    def snapshot(self, task_ids: Iterable[str] | None = None) -> VerifiedWorkMetrics:
        if task_ids is None:
            ids = [task.task_id for task in self.store.list_tasks()]
        else:
            ids = list(dict.fromkeys(str(task_id).strip() for task_id in task_ids if str(task_id).strip()))

        attempted = len(ids)
        contract_bound = 0
        verified = 0
        first_pass = 0
        missing_counts: dict[str, int] = {}
        failed_counts: dict[str, int] = {}

        for task_id in ids:
            state = self.ledger.evaluate(task_id)
            if state.contract_bound:
                contract_bound += 1
            if state.verified:
                verified += 1
            if state.first_pass_verified:
                first_pass += 1
            for validator in state.missing_validators:
                missing_counts[validator] = missing_counts.get(validator, 0) + 1
            for validator in state.failed_validators:
                failed_counts[validator] = failed_counts.get(validator, 0) + 1

        return VerifiedWorkMetrics(
            attempted_tasks=attempted,
            contract_bound_tasks=contract_bound,
            unbound_tasks=attempted - contract_bound,
            verified_tasks=verified,
            first_pass_verified_tasks=first_pass,
            verified_task_success_rate=self._rate(verified, attempted),
            first_pass_verified_success_rate=self._rate(first_pass, attempted),
            missing_validator_counts=missing_counts,
            failed_validator_counts=failed_counts,
        )

    def snapshot_for_date(self, date: str) -> VerifiedWorkMetrics:
        task_ids = [str(row["task_id"]) for row in self.store.tasks_for_date(date)]
        return self.snapshot(task_ids)
