from __future__ import annotations

from dataclasses import dataclass

from .capability_authority import TaskCapabilityAuthority
from .execution_checkpoint_writer_fence import WriterFencedExecutionCheckpointRepository
from .execution_plan import ExecutionPlan
from .execution_scheduler import (
    ExecutionScheduler,
    SchedulerBudgetGuard,
    SchedulerRevocationGuard,
)
from .runtime_scheduler import RuntimeScheduler, RuntimeSchedulerError
from .runtime_writer_lease import (
    RuntimeWriterLease,
    RuntimeWriterLeaseError,
    RuntimeWriterLeaseRepository,
)
from .store import TaskStore
from .task_context import TaskContext

EXECUTION_RUNTIME_COMPOSITION_SCHEMA = "workspace-execution-runtime-composition/v1"


class ExecutionRuntimeCompositionError(RuntimeError):
    """Canonical writer-fenced execution runtime composition failed closed."""


@dataclass(frozen=True)
class WriterFencedExecutionRuntime:
    """Bound runtime parts for one caller-supplied execution run identity.

    This object is intentionally a composition result, not a second runtime. The
    canonical ``ExecutionScheduler`` remains the scheduler and the existing
    ``TaskStore`` remains the persistence substrate.
    """

    run_id: str
    writer_lease: RuntimeWriterLease
    checkpoint_repository: WriterFencedExecutionCheckpointRepository
    scheduler: ExecutionScheduler
    schema_version: str = EXECUTION_RUNTIME_COMPOSITION_SCHEMA

    def validate(self) -> "WriterFencedExecutionRuntime":
        if self.schema_version != EXECUTION_RUNTIME_COMPOSITION_SCHEMA:
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_SCHEMA_MISMATCH"
            )
        if not isinstance(self.run_id, str) or self.run_id != self.writer_lease.run_id:
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_RUN_ID_MISMATCH"
            )
        self.writer_lease.validate()
        if self.writer_lease.status != "ACTIVE":
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_WRITER_NOT_ACTIVE"
            )
        if not isinstance(
            self.checkpoint_repository,
            WriterFencedExecutionCheckpointRepository,
        ):
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_REPOSITORY_NOT_FENCED"
            )
        if self.checkpoint_repository.writer_lease != self.writer_lease:
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_LEASE_BINDING_MISMATCH"
            )
        if not isinstance(self.scheduler, ExecutionScheduler):
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_SCHEDULER_INVALID"
            )
        if self.scheduler.checkpoint_repository is not self.checkpoint_repository:
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_SCHEDULER_REPOSITORY_MISMATCH"
            )
        return self


def compose_writer_fenced_execution_runtime(
    *,
    task_store: TaskStore,
    run_id: str,
    task_context: TaskContext,
    plan: ExecutionPlan,
    parent_authority: TaskCapabilityAuthority,
    budget_guard: SchedulerBudgetGuard,
    revocation_guard: SchedulerRevocationGuard,
    max_concurrency: int = 4,
    checkpoint_reapproved_nodes: frozenset[str] = frozenset(),
) -> WriterFencedExecutionRuntime:
    """Compose the canonical scheduler with mandatory writer-fenced persistence.

    ``run_id`` must come from the caller's durable run/session lifecycle. This
    function deliberately does not generate one and exposes no unfenced fallback.

    Canonical scheduling admission is evaluated before writer ownership changes,
    preventing invalid task/plan/authority input from superseding a healthy run.
    After admission succeeds, the existing writer-lease repository claims the
    exact task/plan generation and the existing writer-fenced checkpoint adapter
    becomes the only checkpoint repository supplied to ``ExecutionScheduler``.
    """

    if not isinstance(task_store, TaskStore):
        raise ExecutionRuntimeCompositionError("EXECUTION_RUNTIME_TASK_STORE_INVALID")
    if not isinstance(run_id, str) or not run_id or run_id != run_id.strip():
        raise ExecutionRuntimeCompositionError("EXECUTION_RUNTIME_RUN_ID_REQUIRED")
    if budget_guard is None:
        raise ExecutionRuntimeCompositionError("EXECUTION_RUNTIME_BUDGET_GUARD_REQUIRED")
    if revocation_guard is None:
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_REVOCATION_GUARD_REQUIRED"
        )
    if not isinstance(checkpoint_reapproved_nodes, frozenset):
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_REAPPROVED_NODES_MUST_BE_FROZENSET"
        )

    try:
        RuntimeScheduler.evaluate(
            task_context=task_context,
            plan=plan,
            parent_authority=parent_authority,
        )
    except RuntimeSchedulerError as exc:
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_CANONICAL_ADMISSION_FAILED"
        ) from exc

    lease_repository = RuntimeWriterLeaseRepository(task_store)
    lease_repository.initialize()
    try:
        writer_lease = lease_repository.claim(
            task_id=plan.task_id,
            plan_fingerprint=plan.fingerprint,
            run_id=run_id,
        )
    except RuntimeWriterLeaseError as exc:
        raise ExecutionRuntimeCompositionError(
            f"EXECUTION_RUNTIME_WRITER_CLAIM_FAILED:{exc}"
        ) from exc

    checkpoint_repository = WriterFencedExecutionCheckpointRepository(
        task_store,
        writer_lease,
    )
    try:
        scheduler = ExecutionScheduler(
            task_context=task_context,
            plan=plan,
            parent_authority=parent_authority,
            budget_guard=budget_guard,
            revocation_guard=revocation_guard,
            max_concurrency=max_concurrency,
            checkpoint_repository=checkpoint_repository,
            checkpoint_reapproved_nodes=checkpoint_reapproved_nodes,
        )
    except Exception as exc:
        # Do not silently fall back to an unfenced repository. The claimed
        # generation remains durable so a caller can retry with the same run_id.
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_SCHEDULER_COMPOSITION_FAILED"
        ) from exc

    return WriterFencedExecutionRuntime(
        run_id=run_id,
        writer_lease=writer_lease,
        checkpoint_repository=checkpoint_repository,
        scheduler=scheduler,
    ).validate()
