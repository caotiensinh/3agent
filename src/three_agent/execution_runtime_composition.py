from __future__ import annotations

from dataclasses import dataclass

from .capability_authority import TaskCapabilityAuthority
from .execution_budget import TaskExecutionBudgetState
from .execution_dispatch_budget import (
    AtomicBudgetWriterFencedExecutionCheckpointRepository,
    DispatchBudgetController,
    DispatchBudgetPreflightGuard,
    ExecutionDispatchBudgetError,
)
from .execution_plan import ExecutionPlan
from .execution_scheduler import (
    MAX_SCHEDULER_CONCURRENCY,
    ExecutionScheduler,
    ExecutionSchedulerError,
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
    checkpoint_repository: AtomicBudgetWriterFencedExecutionCheckpointRepository
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
            AtomicBudgetWriterFencedExecutionCheckpointRepository,
        ):
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_REPOSITORY_NOT_ATOMIC_BUDGET_FENCED"
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
        if not isinstance(self.scheduler.budget_guard, DispatchBudgetPreflightGuard):
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_BUDGET_PREFLIGHT_GUARD_MISSING"
            )
        if (
            self.scheduler.budget_guard.controller
            is not self.checkpoint_repository.dispatch_budget_controller
        ):
            raise ExecutionRuntimeCompositionError(
                "EXECUTION_RUNTIME_COMPOSITION_BUDGET_CONTROLLER_MISMATCH"
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
    """Compose canonical execution with writer fencing and atomic dispatch budget.

    ``run_id`` must come from the caller's durable run/session lifecycle. This
    function deliberately does not generate one and exposes no unfenced fallback.

    Canonical admission plus all non-persistent composition inputs are validated
    before writer ownership changes. The canonical persistent
    ``TaskExecutionBudgetState`` is mandatory: one dispatch step is preflighted by
    the scheduler but mutated only in the same SQLite transaction that commits the
    writer-fenced dispatch checkpoint. A checkpoint failure therefore cannot burn
    an extra step, and a budget failure cannot leave a dispatch receipt behind.
    """

    if not isinstance(task_store, TaskStore):
        raise ExecutionRuntimeCompositionError("EXECUTION_RUNTIME_TASK_STORE_INVALID")
    if not isinstance(run_id, str) or not run_id or run_id != run_id.strip():
        raise ExecutionRuntimeCompositionError("EXECUTION_RUNTIME_RUN_ID_REQUIRED")
    if not isinstance(budget_guard, TaskExecutionBudgetState):
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_CANONICAL_BUDGET_STATE_REQUIRED"
        )
    if revocation_guard is None:
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_REVOCATION_GUARD_REQUIRED"
        )
    if (
        isinstance(max_concurrency, bool)
        or not isinstance(max_concurrency, int)
        or not 1 <= max_concurrency <= MAX_SCHEDULER_CONCURRENCY
    ):
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_MAX_CONCURRENCY_INVALID"
        )
    if not isinstance(checkpoint_reapproved_nodes, frozenset):
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_REAPPROVED_NODES_MUST_BE_FROZENSET"
        )
    if any(
        not isinstance(node_id, str) or not node_id.strip()
        for node_id in checkpoint_reapproved_nodes
    ):
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_REAPPROVED_NODE_INVALID"
        )

    # Validate the canonical task/plan/authority shape before reading fields from
    # those objects and before any writer generation can be claimed.
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

    if budget_guard.task_id != plan.task_id:
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_BUDGET_TASK_SCOPE_MISMATCH"
        )
    if (
        budget_guard.store.db_path.resolve(strict=False)
        != task_store.db_path.resolve(strict=False)
    ):
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_BUDGET_STORE_MISMATCH"
        )

    try:
        dispatch_budget_controller = DispatchBudgetController(task_store, budget_guard)
    except ExecutionDispatchBudgetError as exc:
        raise ExecutionRuntimeCompositionError(
            f"EXECUTION_RUNTIME_DISPATCH_BUDGET_BINDING_FAILED:{exc}"
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

    checkpoint_repository = AtomicBudgetWriterFencedExecutionCheckpointRepository(
        task_store,
        writer_lease,
        budget_guard,
    )
    # Reuse the controller already validated before the writer claim so the
    # scheduler preflight and persistence commit share the exact same binding.
    checkpoint_repository.dispatch_budget_controller = dispatch_budget_controller
    scheduler_budget_guard = DispatchBudgetPreflightGuard(dispatch_budget_controller)
    try:
        scheduler = ExecutionScheduler(
            task_context=task_context,
            plan=plan,
            parent_authority=parent_authority,
            budget_guard=scheduler_budget_guard,
            revocation_guard=revocation_guard,
            max_concurrency=max_concurrency,
            checkpoint_repository=checkpoint_repository,
            checkpoint_reapproved_nodes=checkpoint_reapproved_nodes,
        )
    except ExecutionSchedulerError as exc:
        # Never fall back to unfenced or non-atomic persistence. Keeping the
        # claimed generation lets the same durable run_id retry without creating
        # another writer generation.
        raise ExecutionRuntimeCompositionError(
            "EXECUTION_RUNTIME_SCHEDULER_COMPOSITION_FAILED"
        ) from exc

    return WriterFencedExecutionRuntime(
        run_id=run_id,
        writer_lease=writer_lease,
        checkpoint_repository=checkpoint_repository,
        scheduler=scheduler,
    ).validate()
