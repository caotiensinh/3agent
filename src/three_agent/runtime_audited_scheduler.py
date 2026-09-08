from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from .capability_registry import CapabilityRegistry
from .runtime_checkpoint import RuntimeCheckpoint, RuntimeCheckpointError, RuntimeCheckpointStore
from .runtime_execution_plan import ExecutionObservation
from .runtime_observation_ledger import (
    RuntimeObservationLedger,
    RuntimeObservationLedgerError,
)
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_scheduler import (
    CapabilityAdapterRegistry,
    ExecutionBudgetLike,
    RuntimeDAGScheduler,
    RuntimeSchedulerError,
    RuntimeSchedulerResult,
)
from .task_contract import TaskContract

RUNTIME_RECONCILIATION_REPORT_SCHEMA = "workspace-runtime-reconciliation-report/v1"


class AuditedRuntimeDAGScheduler(RuntimeDAGScheduler):
    """Production DAG path with durable proof-before-completion ordering.

    For every execution round the ordering is deliberately:

        durable RUNNING checkpoint
        -> capability adapter(s)
        -> durable observation ledger transaction
        -> durable READY/FAILED/COMPLETED checkpoint

    Therefore a crash after a side effect but before completion never makes the
    node eligible for blind replay. Any observation persistence failure also
    leaves the last durable checkpoint in RUNNING state and requires explicit
    reconciliation.
    """

    def __init__(
        self,
        *,
        observation_ledger: RuntimeObservationLedger,
        checkpoint_store: RuntimeCheckpointStore,
        registry: CapabilityRegistry | None = None,
        adapters: CapabilityAdapterRegistry | None = None,
    ):
        if observation_ledger is None or not bool(getattr(observation_ledger, "durable", False)):
            raise RuntimeSchedulerError("DURABLE_OBSERVATION_LEDGER_REQUIRED")
        if checkpoint_store is None:
            raise RuntimeSchedulerError("DURABLE_CHECKPOINT_STORE_REQUIRED")
        super().__init__(
            registry=registry,
            adapters=adapters,
            checkpoint_store=checkpoint_store,
        )
        self.observation_ledger = observation_ledger

    def _record_round(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        observations: tuple[ExecutionObservation, ...],
    ) -> None:
        try:
            self.observation_ledger.record_many(
                compiled_plan=compiled_plan,
                observations=observations,
            )
        except Exception as exc:
            raise RuntimeSchedulerError(
                "OBSERVATION_PERSISTENCE_FAILED_RECONCILIATION_REQUIRED"
            ) from exc

    def run(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        budget: ExecutionBudgetLike,
        approved_node_ids: Iterable[str] = (),
        checkpoint: RuntimeCheckpoint | None = None,
    ) -> RuntimeSchedulerResult:
        compiled_plan.validate_current(task_contract=task_contract, registry=self.registry)
        if budget.task_id != compiled_plan.plan.task_id:
            raise RuntimeSchedulerError("SCHEDULER_BUDGET_TASK_MISMATCH")

        completed: set[str] = set()
        observations: list[ExecutionObservation] = []
        prior_observation_ids: tuple[str, ...] = ()
        if checkpoint is not None:
            try:
                checkpoint.validate(compiled_plan)
            except RuntimeCheckpointError as exc:
                raise RuntimeSchedulerError(str(exc)) from exc
            if checkpoint.running_node_ids:
                raise RuntimeSchedulerError("INFLIGHT_CHECKPOINT_REQUIRES_RECONCILIATION")
            if checkpoint.failed_node_ids:
                raise RuntimeSchedulerError("FAILED_CHECKPOINT_REQUIRES_RECONCILIATION")
            completed.update(checkpoint.completed_node_ids)
            prior_observation_ids = checkpoint.observation_ids

        known = {node.node_id for node in compiled_plan.plan.nodes}
        approved = set(approved_node_ids)
        if not approved.issubset(known):
            raise RuntimeSchedulerError("SCHEDULER_APPROVAL_CONTAINS_UNKNOWN_NODE")

        if completed == known:
            final_checkpoint = self._checkpoint(
                compiled_plan=compiled_plan,
                status="completed",
                completed=completed,
                prior_observation_ids=prior_observation_ids,
            )
            return RuntimeSchedulerResult(
                "completed",
                compiled_plan.plan.task_id,
                compiled_plan.plan.plan_id,
                tuple(sorted(completed)),
                (),
                (),
                final_checkpoint,
                "durable_audited",
            )

        failed: set[str] = set()
        current_checkpoint: RuntimeCheckpoint | None = checkpoint
        while completed != known:
            ready = self._ready_round(
                compiled_plan=compiled_plan,
                completed=completed,
                approved=approved,
            )
            if not ready:
                blocked = self._checkpoint(
                    compiled_plan=compiled_plan,
                    status="blocked",
                    completed=completed,
                    prior_observation_ids=prior_observation_ids,
                )
                return RuntimeSchedulerResult(
                    "blocked",
                    compiled_plan.plan.task_id,
                    compiled_plan.plan.plan_id,
                    tuple(sorted(completed)),
                    (),
                    tuple(observations),
                    blocked,
                    "durable_audited",
                )

            running_ids = tuple(node.node_id for node in ready)
            self._checkpoint(
                compiled_plan=compiled_plan,
                status="running",
                completed=completed,
                running=running_ids,
                prior_observation_ids=prior_observation_ids,
            )

            results: dict[str, tuple[ExecutionObservation, bool]] = {}
            if len(ready) == 1:
                node = ready[0]
                results[node.node_id] = self._invoke_node(
                    compiled_plan=compiled_plan,
                    node=node,
                    budget=budget,
                )
            else:
                with ThreadPoolExecutor(
                    max_workers=min(len(ready), compiled_plan.plan.max_parallel)
                ) as pool:
                    futures = {
                        pool.submit(
                            self._invoke_node,
                            compiled_plan=compiled_plan,
                            node=node,
                            budget=budget,
                        ): node.node_id
                        for node in ready
                    }
                    for future in as_completed(futures):
                        node_id = futures[future]
                        try:
                            results[node_id] = future.result()
                        except Exception as exc:
                            results[node_id] = (
                                ExecutionObservation.capture(
                                    plan=compiled_plan.plan,
                                    node_id=node_id,
                                    status="failed",
                                    reason_code="SCHEDULER_WORKER_EXCEPTION",
                                    result={"exception_type": type(exc).__name__},
                                ),
                                False,
                            )

            round_observations = tuple(
                results[node_id][0] for node_id in sorted(results)
            )
            # This is the audit durability boundary. Do not update node state or
            # write a quiescent checkpoint before this transaction commits.
            self._record_round(
                compiled_plan=compiled_plan,
                observations=round_observations,
            )

            round_failed = False
            for node_id in sorted(results):
                observation, succeeded = results[node_id]
                observations.append(observation)
                if succeeded:
                    completed.add(node_id)
                else:
                    failed.add(node_id)
                    round_failed = True

            cumulative_ids = tuple(
                dict.fromkeys(
                    (*prior_observation_ids, *(o.observation_id for o in round_observations))
                )
            )
            if round_failed:
                failed_checkpoint = self._checkpoint(
                    compiled_plan=compiled_plan,
                    status="failed",
                    completed=completed,
                    failed=failed,
                    prior_observation_ids=cumulative_ids,
                )
                return RuntimeSchedulerResult(
                    "failed",
                    compiled_plan.plan.task_id,
                    compiled_plan.plan.plan_id,
                    tuple(sorted(completed)),
                    tuple(sorted(failed)),
                    tuple(observations),
                    failed_checkpoint,
                    "durable_audited",
                )

            status = "completed" if completed == known else "ready"
            current_checkpoint = self._checkpoint(
                compiled_plan=compiled_plan,
                status=status,
                completed=completed,
                prior_observation_ids=cumulative_ids,
            )
            prior_observation_ids = current_checkpoint.observation_ids

        if current_checkpoint is None:
            raise RuntimeSchedulerError("SCHEDULER_CHECKPOINT_STATE_MISSING")
        return RuntimeSchedulerResult(
            "completed",
            compiled_plan.plan.task_id,
            compiled_plan.plan.plan_id,
            tuple(sorted(completed)),
            (),
            tuple(observations),
            current_checkpoint,
            "durable_audited",
        )

    def reconciliation_report(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        checkpoint: RuntimeCheckpoint,
    ) -> dict[str, object]:
        checkpoint.validate(compiled_plan)
        verification = self.observation_ledger.verify_chain(
            compiled_plan.plan.task_id,
            compiled_plan.plan.plan_id,
        )
        records = self.observation_ledger.records_for_plan(
            compiled_plan.plan.task_id,
            compiled_plan.plan.plan_id,
        )
        uncertain_nodes = set(checkpoint.running_node_ids) | set(checkpoint.failed_node_ids)
        relevant = [
            record["observation"]
            for record in records
            if str(record["observation"].get("node_id")) in uncertain_nodes
        ]
        return {
            "schema_version": RUNTIME_RECONCILIATION_REPORT_SCHEMA,
            "task_id": compiled_plan.plan.task_id,
            "plan_id": compiled_plan.plan.plan_id,
            "checkpoint_id": checkpoint.checkpoint_id,
            "checkpoint_status": checkpoint.status,
            "running_node_ids": list(checkpoint.running_node_ids),
            "failed_node_ids": list(checkpoint.failed_node_ids),
            "completed_node_ids": list(checkpoint.completed_node_ids),
            "ledger_verified": bool(verification["verified"]),
            "ledger_record_count": int(verification["record_count"]),
            "ledger_head_record_sha256": str(verification["head_record_sha256"]),
            "uncertain_node_observations": relevant,
            "requires_reconciliation": bool(uncertain_nodes),
            "automatic_replay_authorized": False,
        }
