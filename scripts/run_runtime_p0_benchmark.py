#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.capability_revocation import CapabilityRevocation
from three_agent.execution_budget import ExecutionBudgetExceeded
from three_agent.execution_observation import (
    ExecutionEvidenceBinding,
    ExecutionObservation,
    ExecutionObservationBuilder,
    ObservationCost,
)
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlan, ExecutionPlanBuilder
from three_agent.execution_scheduler import ExecutionScheduler, ExecutionSchedulerError
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_checkpoint import RuntimeCheckpointBuilder
from three_agent.runtime_dispatch_recovery import (
    RuntimeDispatchRecovery,
    RuntimeDispatchRecoveryBindingBuilder,
)
from three_agent.task_context import TaskContext, TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler

SCHEMA = "workspace.runtime-p0-benchmark/v1"
BENCHMARK_ID = "runtime-p0-control-plane-v1"
ARCHITECTURE_DIMENSIONS = (
    "inference_turns_per_completed_task",
    "tool_calls_per_inference_turn",
    "wall_clock_time_to_result_ms",
    "parallel_execution_efficiency",
    "model_token_consumption",
    "model_provider_cost_usd",
    "task_completion_rate",
    "partial_result_quality",
    "failure_recovery_rate",
    "evidence_completeness",
    "policy_enforcement_correctness",
    "approval_correctness",
    "hallucinated_action_mismatch_rate",
    "deterministic_replay_reconstruction_coverage",
    "operator_intervention_rate",
)


def canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass
class _BenchmarkBudget:
    task_id: str
    max_steps: int = 8
    max_tool_calls: int = 12
    max_model_retries: int = 2
    max_model_escalations: int = 1
    max_wall_time_ms: int = 600_000
    steps_used: int = 0
    tool_calls_used: int = 0
    model_retries_used: int = 0
    model_escalations_used: int = 0
    active: bool = True

    def assert_active(self) -> None:
        if not self.active:
            raise ExecutionBudgetExceeded("TASK_WALL_TIME_BUDGET_EXHAUSTED")

    def reserve(
        self,
        *,
        steps: int = 0,
        tool_calls: int = 0,
        retries: int = 0,
        escalations: int = 0,
    ) -> None:
        self.assert_active()
        updates = {
            "steps_used": steps,
            "tool_calls_used": tool_calls,
            "model_retries_used": retries,
            "model_escalations_used": escalations,
        }
        limits = {
            "steps_used": "max_steps",
            "tool_calls_used": "max_tool_calls",
            "model_retries_used": "max_model_retries",
            "model_escalations_used": "max_model_escalations",
        }
        for field, delta in updates.items():
            if getattr(self, field) + delta > getattr(self, limits[field]):
                raise ExecutionBudgetExceeded("TASK_EXECUTION_BUDGET_EXHAUSTED")
        for field, delta in updates.items():
            setattr(self, field, getattr(self, field) + delta)

    def snapshot(self) -> dict[str, int | str]:
        return {
            "schema_version": "workspace-task-execution-budget-state/v2",
            "task_id": self.task_id,
            "max_steps": self.max_steps,
            "max_tool_calls": self.max_tool_calls,
            "max_model_retries": self.max_model_retries,
            "max_model_escalations": self.max_model_escalations,
            "max_wall_time_ms": self.max_wall_time_ms,
            "steps_used": self.steps_used,
            "tool_calls_used": self.tool_calls_used,
            "model_retries_used": self.model_retries_used,
            "model_escalations_used": self.model_escalations_used,
            "deadline_at": "2026-09-08T04:00:00Z",
        }


class _BenchmarkRevocations:
    def __init__(self) -> None:
        self._rows: dict[str, CapabilityRevocation] = {}

    def is_revoked(self, task_id: str, capability: str) -> bool:
        row = self._rows.get(capability)
        return row is not None and row.task_id == task_id

    def list_for_task(self, task_id: str) -> tuple[CapabilityRevocation, ...]:
        return tuple(
            self._rows[key]
            for key in sorted(self._rows)
            if self._rows[key].task_id == task_id
        )

    def revoke(self, task_id: str, capability: str) -> CapabilityRevocation:
        row = CapabilityRevocation(
            task_id=task_id,
            capability=capability,
            reason_code="BENCHMARK_REVOKED",
            revoked_at="2026-09-08T02:30:00Z",
        )
        self._rows[capability] = row
        return row


def _workflow() -> dict[str, Any]:
    return {
        "title": "Runtime P0 benchmark",
        "objective": "Measure the canonical non-provider runtime control path.",
        "trigger": "manual",
        "risk_level": "medium",
        "data_class": "internal",
        "nodes": [
            {
                "id": "start",
                "label": "Start",
                "kind": "input",
                "action": "input",
                "depends_on": [],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "probe_a",
                "label": "Probe A",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "probe_b",
                "label": "Probe B",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "aggregate",
                "label": "Aggregate",
                "kind": "validation",
                "action": "validate",
                "depends_on": ["probe_a", "probe_b"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "approve",
                "label": "Approve",
                "kind": "approval",
                "action": "human_approval",
                "depends_on": ["aggregate"],
                "condition": "benchmark approval",
                "approval_required": True,
            },
            {
                "id": "report",
                "label": "Report",
                "kind": "output",
                "action": "output",
                "depends_on": ["approve"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Benchmark acceptance receipt"],
        "warnings": [],
    }


def build_runtime() -> tuple[TaskContext, TaskCapabilityAuthority, ExecutionPlan]:
    task_id = "TASK-RUNTIME-P0-BENCHMARK"
    contract = TaskContractCompiler().compile(
        task_id=task_id,
        task_type="analysis",
        sensitivity="internal",
        risk_level="medium",
        allowed_sources=("repo", "evidence"),
        allowed_tools=("read_file", "search_docs"),
        write_scope="none",
    )
    acceptance = AcceptanceContract(
        task_id=task_id,
        criteria=(
            AcceptanceCriterion(
                criterion_id="runtime-p0-benchmark",
                statement="Measure the canonical runtime control path without provider execution.",
                verifier="unit_test",
            ),
        ),
    )
    canonical = HarnessTaskCompiler().compile(
        user_prompt="Benchmark the canonical WorkSpace runtime control path.",
        task_contract=contract,
        acceptance_contract=acceptance,
    )
    context = TaskContextBuilder.build(
        task_contract=contract,
        canonical_task=canonical,
        session_id="SESSION-RUNTIME-P0-BENCHMARK",
        trace_id="TRACE-RUNTIME-P0-BENCHMARK",
        actor_id="ACTOR-RUNTIME-P0-BENCHMARK",
        purpose="runtime P0 final acceptance benchmark",
        project_id="WORKSPACE",
        created_at=datetime(2026, 9, 8, 2, 0, tzinfo=timezone.utc),
    )
    authority = TaskCapabilityAuthority.from_contract(contract)
    plan = ExecutionPlanBuilder.build(
        task_context=context,
        parent_authority=authority,
        workflow_contract=_workflow(),
        node_bindings={
            "probe_a": ExecutionNodeBinding(
                allowed_sources=("repo",),
                allowed_tools=("read_file",),
                resource_budget=TaskResourceBudget(
                    wall_time_s=3,
                    model_tokens=0,
                    tool_calls=1,
                ),
                evidence_requirements=("probe-a-result",),
            ),
            "probe_b": ExecutionNodeBinding(
                allowed_sources=("evidence",),
                allowed_tools=("search_docs",),
                resource_budget=TaskResourceBudget(
                    wall_time_s=3,
                    model_tokens=0,
                    tool_calls=1,
                ),
                evidence_requirements=("probe-b-result",),
            ),
        },
    )
    return context, authority, plan


def _evidence(requirement: str, node_id: str) -> ExecutionEvidenceBinding:
    payload = {"benchmark_id": BENCHMARK_ID, "node_id": node_id, "requirement": requirement}
    return ExecutionEvidenceBinding(
        evidence_ref=f"benchmark:{node_id}",
        evidence_fingerprint=canonical_sha256(payload),
        requirement=requirement,
    )


def _observation(
    plan: ExecutionPlan,
    authority: TaskCapabilityAuthority,
    node_id: str,
    second: int,
    *,
    requirement: str | None = None,
    tool_call: bool = False,
) -> ExecutionObservation:
    bindings = () if requirement is None else (_evidence(requirement, node_id),)
    cost = (
        ObservationCost(wall_time_s=0.0, model_tokens=0, tool_calls=1)
        if tool_call
        else None
    )
    return ExecutionObservationBuilder.build(
        plan=plan,
        node_id=node_id,
        parent_authority=authority,
        status="SUCCEEDED",
        started_at=f"2026-09-08T02:10:{second:02d}Z",
        finished_at=f"2026-09-08T02:10:{second:02d}Z",
        normalized_output={"benchmark_node": node_id},
        evidence_bindings=bindings,
        cost=cost,
    )


def _new_scheduler(
    context: TaskContext,
    authority: TaskCapabilityAuthority,
    plan: ExecutionPlan,
) -> tuple[ExecutionScheduler, _BenchmarkBudget, _BenchmarkRevocations]:
    budget = _BenchmarkBudget(plan.task_id)
    revocations = _BenchmarkRevocations()
    scheduler = ExecutionScheduler(
        task_context=context,
        plan=plan,
        parent_authority=authority,
        budget_guard=budget,
        revocation_guard=revocations,
        max_concurrency=2,
    )
    return scheduler, budget, revocations


def _happy_path(
    context: TaskContext,
    authority: TaskCapabilityAuthority,
    plan: ExecutionPlan,
) -> dict[str, Any]:
    scheduler, budget, revocations = _new_scheduler(context, authority, plan)

    scheduler.issue_dispatch("start")
    start = _observation(plan, authority, "start", 0)
    scheduler.accept_observation(start)

    parallel_ready = scheduler.ready_node_ids()
    if parallel_ready != ("probe_a", "probe_b"):
        raise RuntimeError(f"unexpected parallel ready set: {parallel_ready}")
    tickets = scheduler.issue_ready()
    if tuple(ticket.node_id for ticket in tickets) != ("probe_a", "probe_b"):
        raise RuntimeError("parallel dispatch order is not deterministic")

    probe_a = _observation(
        plan,
        authority,
        "probe_a",
        1,
        requirement="probe-a-result",
        tool_call=True,
    )
    probe_b = _observation(
        plan,
        authority,
        "probe_b",
        2,
        requirement="probe-b-result",
        tool_call=True,
    )
    scheduler.accept_observation(probe_b)
    scheduler.accept_observation(probe_a)

    fan_in = scheduler.fan_in("aggregate")
    if tuple(row.node_id for row in fan_in) != ("probe_a", "probe_b"):
        raise RuntimeError("fan-in order changed with completion order")

    scheduler.issue_dispatch("aggregate")
    aggregate = _observation(plan, authority, "aggregate", 3)
    scheduler.accept_observation(aggregate)

    approval_denied = False
    try:
        scheduler.issue_dispatch("approve")
    except ExecutionSchedulerError as exc:
        approval_denied = str(exc) == "NODE_APPROVAL_REQUIRED:approve"
    if not approval_denied:
        raise RuntimeError("approval boundary did not fail closed")

    scheduler.issue_dispatch("approve", approval_granted=True)
    approve = _observation(plan, authority, "approve", 4)
    scheduler.accept_observation(approve)

    scheduler.issue_dispatch("report")
    report = _observation(plan, authority, "report", 5)
    scheduler.accept_observation(report)

    decision = scheduler.admission_decision()
    if decision.status != "COMPLETE":
        raise RuntimeError(f"happy path did not complete: {decision.status}")

    checkpoint = RuntimeCheckpointBuilder.build(
        task_context=context,
        plan=plan,
        parent_authority=authority,
        observations=(start, probe_a, probe_b, aggregate, approve, report),
        approved_node_ids=("approve",),
        captured_at=datetime(2026, 9, 8, 2, 20, tzinfo=timezone.utc),
    )
    binding = RuntimeDispatchRecoveryBindingBuilder.build(
        checkpoint=checkpoint,
        scheduler_snapshot=scheduler.snapshot(),
        budget_snapshot=budget.snapshot(),
        revocations=revocations.list_for_task(plan.task_id),
    )
    recovered_a = RuntimeDispatchRecovery.evaluate(
        binding=binding,
        checkpoint=checkpoint,
        task_context=context,
        plan=plan,
        parent_authority=authority,
        budget_guard=budget,
        revocation_guard=revocations,
        observations=(start, probe_a, probe_b, aggregate, approve, report),
    )
    recovered_b = RuntimeDispatchRecovery.evaluate(
        binding=binding,
        checkpoint=checkpoint,
        task_context=context,
        plan=plan,
        parent_authority=authority,
        budget_guard=budget,
        revocation_guard=revocations,
        observations=(report, approve, aggregate, probe_b, probe_a, start),
    )
    if recovered_a.status != "COMPLETE":
        raise RuntimeError(f"completed checkpoint recovery changed state: {recovered_a.status}")
    if recovered_a.fingerprint != recovered_b.fingerprint:
        raise RuntimeError("recovery reconstruction is not deterministic")

    required = sum(len(node.evidence_requirements) for node in plan.nodes)
    satisfied = sum(
        len(observation.evidence_bindings)
        for observation in (start, probe_a, probe_b, aggregate, approve, report)
    )
    return {
        "completed": True,
        "parallel_efficiency": len(parallel_ready) / 2.0,
        "tool_calls": 2,
        "evidence_required": required,
        "evidence_satisfied": satisfied,
        "approval_correct": approval_denied,
        "reconstruction_deterministic": True,
        "final_decision_fingerprint": decision.fingerprint,
        "recovery_fingerprint": recovered_a.fingerprint,
    }


def _security_and_recovery_checks(
    context: TaskContext,
    authority: TaskCapabilityAuthority,
    plan: ExecutionPlan,
) -> dict[str, bool]:
    scheduler, _budget, revocations = _new_scheduler(context, authority, plan)
    scheduler.issue_dispatch("start")
    start = _observation(plan, authority, "start", 0)
    scheduler.accept_observation(start)

    revocations.revoke(plan.task_id, "read_file")
    revocation_denied = False
    try:
        scheduler.issue_dispatch("probe_a")
    except ExecutionSchedulerError as exc:
        revocation_denied = str(exc) == "SCHEDULER_CAPABILITY_REVOKED:probe_a:read_file"

    hallucinated_action_denied = False
    try:
        scheduler.issue_dispatch("invented_action")
    except ExecutionSchedulerError as exc:
        hallucinated_action_denied = str(exc) == "UNKNOWN_EXECUTION_NODE:invented_action"

    recovery_scheduler, recovery_budget, recovery_revocations = _new_scheduler(
        context, authority, plan
    )
    recovery_scheduler.issue_dispatch("start")
    recovery_start = _observation(plan, authority, "start", 0)
    recovery_scheduler.accept_observation(recovery_start)
    checkpoint = RuntimeCheckpointBuilder.build(
        task_context=context,
        plan=plan,
        parent_authority=authority,
        observations=(recovery_start,),
        captured_at=datetime(2026, 9, 8, 2, 25, tzinfo=timezone.utc),
    )
    binding = RuntimeDispatchRecoveryBindingBuilder.build(
        checkpoint=checkpoint,
        scheduler_snapshot=recovery_scheduler.snapshot(),
        budget_snapshot=recovery_budget.snapshot(),
        revocations=recovery_revocations.list_for_task(plan.task_id),
    )
    first = RuntimeDispatchRecovery.evaluate(
        binding=binding,
        checkpoint=checkpoint,
        task_context=context,
        plan=plan,
        parent_authority=authority,
        budget_guard=recovery_budget,
        revocation_guard=recovery_revocations,
        observations=(recovery_start,),
    )
    second = RuntimeDispatchRecovery.evaluate(
        binding=binding,
        checkpoint=checkpoint,
        task_context=context,
        plan=plan,
        parent_authority=authority,
        budget_guard=recovery_budget,
        revocation_guard=recovery_revocations,
        observations=(recovery_start,),
    )
    recovery_correct = (
        first.status == "RECOVERABLE" and first.fingerprint == second.fingerprint
    )

    inflight_scheduler, inflight_budget, inflight_revocations = _new_scheduler(
        context, authority, plan
    )
    ticket = inflight_scheduler.issue_dispatch("start")
    inflight_checkpoint = RuntimeCheckpointBuilder.build(
        task_context=context,
        plan=plan,
        parent_authority=authority,
        captured_at=datetime(2026, 9, 8, 2, 26, tzinfo=timezone.utc),
    )
    inflight_binding = RuntimeDispatchRecoveryBindingBuilder.build(
        checkpoint=inflight_checkpoint,
        scheduler_snapshot=inflight_scheduler.snapshot(),
        budget_snapshot=inflight_budget.snapshot(),
        revocations=inflight_revocations.list_for_task(plan.task_id),
    )
    inflight = RuntimeDispatchRecovery.evaluate(
        binding=inflight_binding,
        checkpoint=inflight_checkpoint,
        task_context=context,
        plan=plan,
        parent_authority=authority,
        budget_guard=inflight_budget,
        revocation_guard=inflight_revocations,
    )
    manual_reconciliation_correct = (
        inflight.status == "MANUAL_RECONCILIATION"
        and inflight.manual_dispatch_fingerprints == (ticket.fingerprint,)
    )

    return {
        "revocation_denied": revocation_denied,
        "hallucinated_action_denied": hallucinated_action_denied,
        "recovery_correct": recovery_correct,
        "manual_reconciliation_correct": manual_reconciliation_correct,
    }


def _metric(value: Any, unit: str, *, applicability: str = "measured", note: str) -> dict[str, Any]:
    return {
        "value": value,
        "unit": unit,
        "applicability": applicability,
        "note": note,
    }


def run_benchmark(iterations: int = 100) -> dict[str, Any]:
    if isinstance(iterations, bool) or not isinstance(iterations, int) or not 1 <= iterations <= 10_000:
        raise ValueError("iterations must be an integer within [1, 10000]")

    context, authority, plan = build_runtime()
    elapsed_ms: list[float] = []
    completion_hits = 0
    parallel_efficiencies: list[float] = []
    evidence_required = 0
    evidence_satisfied = 0
    approval_hits = 0
    reconstruction_hits = 0
    policy_hits = 0
    hallucinated_action_rejections = 0
    recovery_hits = 0
    manual_reconciliation_hits = 0
    deterministic_fingerprints: set[tuple[str, str]] = set()

    for _ in range(iterations):
        started = time.perf_counter()
        happy = _happy_path(context, authority, plan)
        checks = _security_and_recovery_checks(context, authority, plan)
        elapsed_ms.append((time.perf_counter() - started) * 1000.0)

        completion_hits += int(happy["completed"])
        parallel_efficiencies.append(float(happy["parallel_efficiency"]))
        evidence_required += int(happy["evidence_required"])
        evidence_satisfied += int(happy["evidence_satisfied"])
        approval_hits += int(happy["approval_correct"])
        reconstruction_hits += int(happy["reconstruction_deterministic"])
        policy_hits += int(checks["revocation_denied"])
        hallucinated_action_rejections += int(checks["hallucinated_action_denied"])
        recovery_hits += int(checks["recovery_correct"])
        manual_reconciliation_hits += int(checks["manual_reconciliation_correct"])
        deterministic_fingerprints.add(
            (
                str(happy["final_decision_fingerprint"]),
                str(happy["recovery_fingerprint"]),
            )
        )

    completion_rate = completion_hits / iterations
    evidence_completeness = (
        evidence_satisfied / evidence_required if evidence_required else 1.0
    )
    metrics = {
        "inference_turns_per_completed_task": _metric(
            0.0,
            "turns/task",
            applicability="not_applicable",
            note="Control-plane benchmark deliberately performs no model inference.",
        ),
        "tool_calls_per_inference_turn": _metric(
            None,
            "tool_calls/turn",
            applicability="not_applicable",
            note="Undefined because the benchmark performs zero inference turns.",
        ),
        "wall_clock_time_to_result_ms": _metric(
            {
                "p50": statistics.median(elapsed_ms),
                "p95": sorted(elapsed_ms)[max(0, int(len(elapsed_ms) * 0.95) - 1)],
                "mean": statistics.fmean(elapsed_ms),
            },
            "ms",
            note="Measured locally inside the CI/runtime process; informational, not a hardware SLA.",
        ),
        "parallel_execution_efficiency": _metric(
            statistics.fmean(parallel_efficiencies),
            "ratio",
            note="Ready-lane utilization for the two independent probe nodes at max_concurrency=2.",
        ),
        "model_token_consumption": _metric(
            0,
            "tokens",
            applicability="not_applicable",
            note="Control-plane benchmark performs no model inference.",
        ),
        "model_provider_cost_usd": _metric(
            0.0,
            "USD",
            applicability="not_applicable",
            note="Control-plane benchmark performs no paid or remote provider calls.",
        ),
        "task_completion_rate": _metric(
            completion_rate,
            "ratio",
            note="Completed canonical six-node DAGs divided by benchmark iterations.",
        ),
        "partial_result_quality": _metric(
            None,
            "ratio",
            applicability="not_applicable",
            note="Happy-path benchmark emits no PARTIAL result; PARTIAL semantics are covered by runtime regression gates.",
        ),
        "failure_recovery_rate": _metric(
            recovery_hits / iterations,
            "ratio",
            note="Expected quiescent recovery decisions reproduced deterministically.",
        ),
        "evidence_completeness": _metric(
            evidence_completeness,
            "ratio",
            note="Declared evidence requirements satisfied by canonical evidence bindings.",
        ),
        "policy_enforcement_correctness": _metric(
            policy_hits / iterations,
            "ratio",
            note="Live capability revocation denied the planned read_file dispatch.",
        ),
        "approval_correctness": _metric(
            approval_hits / iterations,
            "ratio",
            note="Approval node failed closed without explicit approval and completed only after approval.",
        ),
        "hallucinated_action_mismatch_rate": _metric(
            1.0 - (hallucinated_action_rejections / iterations),
            "ratio",
            note="Rate of invented node IDs incorrectly admitted by the canonical scheduler; target is 0.",
        ),
        "deterministic_replay_reconstruction_coverage": _metric(
            reconstruction_hits / iterations,
            "ratio",
            note="Completed checkpoint recovery fingerprints remained identical under reordered observation input.",
        ),
        "operator_intervention_rate": _metric(
            0.0,
            "ratio",
            note="Happy path requires no operator recovery; separate in-flight recovery case must require manual reconciliation.",
        ),
    }

    functional_acceptance = {
        "all_dimensions_reported": tuple(metrics) == ARCHITECTURE_DIMENSIONS,
        "completion_rate_is_one": completion_rate == 1.0,
        "parallel_efficiency_is_one": metrics["parallel_execution_efficiency"]["value"] == 1.0,
        "evidence_completeness_is_one": evidence_completeness == 1.0,
        "policy_correctness_is_one": metrics["policy_enforcement_correctness"]["value"] == 1.0,
        "approval_correctness_is_one": metrics["approval_correctness"]["value"] == 1.0,
        "hallucinated_action_mismatch_is_zero": metrics["hallucinated_action_mismatch_rate"]["value"] == 0.0,
        "recovery_rate_is_one": metrics["failure_recovery_rate"]["value"] == 1.0,
        "reconstruction_coverage_is_one": metrics["deterministic_replay_reconstruction_coverage"]["value"] == 1.0,
        "inflight_requires_manual_reconciliation": manual_reconciliation_hits == iterations,
        "fingerprints_stable_across_iterations": len(deterministic_fingerprints) == 1,
        "no_provider_execution": True,
        "no_network_execution": True,
    }
    accepted = all(functional_acceptance.values())

    identity = {
        "schema": SCHEMA,
        "benchmark_id": BENCHMARK_ID,
        "iterations": iterations,
        "task_context_fingerprint": context.fingerprint,
        "plan_fingerprint": plan.fingerprint,
        "parent_authority_fingerprint": authority.fingerprint,
        "architecture_dimensions": list(ARCHITECTURE_DIMENSIONS),
        "functional_acceptance": functional_acceptance,
    }
    return {
        **identity,
        "receipt_fingerprint": canonical_sha256(identity),
        "accepted": accepted,
        "metrics": metrics,
        "scope": {
            "track": "WorkSpace Agent Runtime P0 convergence",
            "provider_execution": False,
            "network_execution": False,
            "performance_threshold_policy": "informational_latency_functional_security_gates_authoritative",
            "out_of_scope_followups": [
                "provider/resource-lock adapters",
                "provider timeout/safe-retry adapters",
                "runtime-wide subagent delegation contract",
            ],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark the canonical WorkSpace P0 runtime control path without provider execution."
    )
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--output")
    args = parser.parse_args()
    receipt = run_benchmark(args.iterations)
    payload = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload)
    else:
        print(payload, end="")
    return 0 if receipt["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
