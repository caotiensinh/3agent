from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from typing import Any

from .capability_registry import SecurityCapabilityDenied, SecurityCapabilityRegistry
from .capability_router import SecurityCapabilityRouter, SecurityRoutingDecision
from .contracts import sha256_fingerprint
from .operation_binding import (
    SecurityOperationBindingRegistry,
    SecurityOperationHandlerUnbound,
    SecurityPlanBinding,
)
from .operation_invocation import (
    SecurityInvocationResult,
    SecurityOperationInvocationDenied,
    SecurityOperationInvocationError,
    SecurityOperationInvoker,
    SecurityTypedInvocationRequest,
)
from .operation_plan import (
    SecurityOperationPlan,
    SecurityOperationPlanCompiler,
    SecurityOperationPlanError,
)
from .workflow_audit import SecurityWorkflowAuditJournal, SecurityWorkflowAuditRecord

SECURITY_WORKFLOW_SESSION_SCHEMA = "workspace-security-analyst-workflow-session/v1"
SECURITY_WORKFLOW_STEP_SCHEMA = "workspace-security-analyst-workflow-step/v1"
SECURITY_WORKFLOW_EXECUTION_SCHEMA = "workspace-security-analyst-workflow-execution/v1"
WORKFLOW_STEP_STATES = frozenset({"awaiting_typed_input", "unbound", "completed"})
WORKFLOW_STATUSES = frozenset({"ready", "partial", "blocked", "completed", "denied", "no_route"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SESSION_RE = re.compile(r"^security-session:[0-9a-f]{24}$")
_STEP_RE = re.compile(r"^step:[0-9a-f]{24}$")
_INVOCATION_RE = re.compile(r"^invoke-[0-9a-f]{24}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")


class SecurityWorkflowError(ValueError):
    """Workflow state, lineage, or typed execution request is invalid."""


class SecurityWorkflowDenied(PermissionError):
    """Workflow transition is not admitted by the current reviewed state."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise SecurityWorkflowError(f"{field_name} must be SHA-256")
    return text


def _failure_reason(exc: BaseException) -> str:
    reason = getattr(exc, "reason_code", None)
    if isinstance(reason, str) and _REASON_RE.fullmatch(reason):
        return reason
    text = str(exc).strip()
    if _REASON_RE.fullmatch(text):
        return text
    return "WORKFLOW_INVOCATION_FAILED_CLOSED"


@dataclass(frozen=True)
class SecurityWorkflowStepState:
    sequence: int
    step_id: str
    capability_id: str
    operation_id: str
    binding_status: str
    state: str
    binding_reason_code: str
    handler_id: str | None = None
    input_fingerprint: str | None = None
    invocation_id: str | None = None
    invocation_receipt_sha256: str | None = None
    schema_version: str = SECURITY_WORKFLOW_STEP_SCHEMA

    def validate(self) -> "SecurityWorkflowStepState":
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or not 1 <= self.sequence <= 6:
            raise SecurityWorkflowError("workflow step sequence is invalid")
        if not _STEP_RE.fullmatch(str(self.step_id or "")):
            raise SecurityWorkflowError("workflow step_id is invalid")
        if self.binding_status not in {"bound", "unbound"}:
            raise SecurityWorkflowError("workflow binding_status is invalid")
        if self.state not in WORKFLOW_STEP_STATES:
            raise SecurityWorkflowError("workflow step state is invalid")
        if not _REASON_RE.fullmatch(str(self.binding_reason_code or "")):
            raise SecurityWorkflowError("workflow binding reason is invalid")
        if self.binding_status == "bound":
            if not self.handler_id:
                raise SecurityWorkflowError("bound workflow step requires handler_id")
            if self.state == "unbound":
                raise SecurityWorkflowError("bound workflow step cannot be unbound")
        else:
            if self.handler_id is not None or self.state != "unbound":
                raise SecurityWorkflowError("unbound workflow step cannot expose a handler")
        if self.state == "completed":
            _sha(str(self.input_fingerprint or ""), "input_fingerprint")
            if not _INVOCATION_RE.fullmatch(str(self.invocation_id or "")):
                raise SecurityWorkflowError("completed workflow step requires invocation_id")
            _sha(str(self.invocation_receipt_sha256 or ""), "invocation_receipt_sha256")
        else:
            if any(value is not None for value in (self.input_fingerprint, self.invocation_id, self.invocation_receipt_sha256)):
                raise SecurityWorkflowError("non-completed workflow step cannot retain invocation lineage")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class SecurityWorkflowSession:
    session_id: str
    request_sha256: str
    route_status: str
    plan_status: str
    status: str
    steps: tuple[SecurityWorkflowStepState, ...]
    plan_fingerprint: str
    registry_fingerprint: str
    binding_fingerprint: str
    runtime_fingerprint: str
    workflow_fingerprint: str
    reason_codes: tuple[str, ...]
    authority: str = "advisory"
    auto_execute: bool = False
    schema_version: str = SECURITY_WORKFLOW_SESSION_SCHEMA

    def validate(self) -> "SecurityWorkflowSession":
        if not _SESSION_RE.fullmatch(str(self.session_id or "")):
            raise SecurityWorkflowError("workflow session_id is invalid")
        for field_name, value in (
            ("request_sha256", self.request_sha256),
            ("plan_fingerprint", self.plan_fingerprint),
            ("registry_fingerprint", self.registry_fingerprint),
            ("binding_fingerprint", self.binding_fingerprint),
            ("runtime_fingerprint", self.runtime_fingerprint),
            ("workflow_fingerprint", self.workflow_fingerprint),
        ):
            _sha(value, field_name)
        if self.route_status not in {"routed", "no_route", "denied"}:
            raise SecurityWorkflowError("workflow route_status is invalid")
        if self.plan_status not in {"planned", "no_route", "denied"}:
            raise SecurityWorkflowError("workflow plan_status is invalid")
        if self.status not in WORKFLOW_STATUSES:
            raise SecurityWorkflowError("workflow status is invalid")
        if self.authority != "advisory" or self.auto_execute:
            raise SecurityWorkflowError("workflow sessions cannot grant automatic execution authority")
        if not self.reason_codes or len(self.reason_codes) > 24:
            raise SecurityWorkflowError("workflow reason_codes are required and bounded")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise SecurityWorkflowError("workflow reason_codes must be unique")
        if any(not _REASON_RE.fullmatch(str(value)) for value in self.reason_codes):
            raise SecurityWorkflowError("workflow reason_code is invalid")
        for expected, step in enumerate(self.steps, 1):
            step.validate()
            if step.sequence != expected:
                raise SecurityWorkflowError("workflow steps must be contiguous and ordered")
        if self.plan_status == "planned" and not self.steps:
            raise SecurityWorkflowError("planned workflow requires steps")
        if self.plan_status != "planned" and self.steps:
            raise SecurityWorkflowError("non-planned workflow cannot contain steps")
        expected_status = _session_status(self.route_status, self.plan_status, self.steps)
        if self.status != expected_status:
            raise SecurityWorkflowError("workflow status does not match step state")
        expected_id = _session_id(
            request_sha256=self.request_sha256,
            plan_fingerprint=self.plan_fingerprint,
            binding_fingerprint=self.binding_fingerprint,
        )
        if self.session_id != expected_id:
            raise SecurityWorkflowError("session_id does not match workflow lineage")
        expected_fingerprint = _workflow_fingerprint(
            session_id=self.session_id,
            request_sha256=self.request_sha256,
            route_status=self.route_status,
            plan_status=self.plan_status,
            status=self.status,
            steps=self.steps,
            plan_fingerprint=self.plan_fingerprint,
            registry_fingerprint=self.registry_fingerprint,
            binding_fingerprint=self.binding_fingerprint,
            runtime_fingerprint=self.runtime_fingerprint,
            reason_codes=self.reason_codes,
        )
        if self.workflow_fingerprint != expected_fingerprint:
            raise SecurityWorkflowError("workflow_fingerprint does not match session state")
        return self

    @property
    def step_completion_percent(self) -> float:
        self.validate()
        if not self.steps:
            return 0.0
        completed = sum(1 for step in self.steps if step.state == "completed")
        return round((completed / len(self.steps)) * 100.0, 3)

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "request_sha256": self.request_sha256,
            "route_status": self.route_status,
            "plan_status": self.plan_status,
            "status": self.status,
            "steps": [step.public_dict() for step in self.steps],
            "step_completion_percent": self.step_completion_percent,
            "plan_fingerprint": self.plan_fingerprint,
            "registry_fingerprint": self.registry_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
            "runtime_fingerprint": self.runtime_fingerprint,
            "workflow_fingerprint": self.workflow_fingerprint,
            "reason_codes": list(self.reason_codes),
            "authority": self.authority,
            "auto_execute": self.auto_execute,
        }


@dataclass(frozen=True)
class SecurityWorkflowPrepared:
    session: SecurityWorkflowSession
    routing: SecurityRoutingDecision
    plan: SecurityOperationPlan
    binding: SecurityPlanBinding
    audit_record: SecurityWorkflowAuditRecord


@dataclass(frozen=True)
class SecurityWorkflowExecution:
    session: SecurityWorkflowSession
    result: SecurityInvocationResult
    audit_record: SecurityWorkflowAuditRecord
    schema_version: str = SECURITY_WORKFLOW_EXECUTION_SCHEMA


def _session_id(*, request_sha256: str, plan_fingerprint: str, binding_fingerprint: str) -> str:
    digest = sha256_fingerprint(
        {
            "request_sha256": request_sha256,
            "plan_fingerprint": plan_fingerprint,
            "binding_fingerprint": binding_fingerprint,
        }
    )
    return "security-session:" + digest.split(":", 1)[1][:24]


def _session_status(
    route_status: str,
    plan_status: str,
    steps: tuple[SecurityWorkflowStepState, ...],
) -> str:
    if plan_status == "denied" or route_status == "denied":
        return "denied"
    if plan_status == "no_route" or route_status == "no_route":
        return "no_route"
    completed = sum(1 for step in steps if step.state == "completed")
    awaiting = sum(1 for step in steps if step.state == "awaiting_typed_input")
    unbound = sum(1 for step in steps if step.state == "unbound")
    if completed == len(steps):
        return "completed"
    if awaiting and not unbound:
        return "ready"
    if awaiting and unbound:
        return "partial"
    if completed and unbound:
        return "partial"
    if unbound == len(steps):
        return "blocked"
    raise SecurityWorkflowError("unsupported workflow step-state combination")


def _workflow_fingerprint(
    *,
    session_id: str,
    request_sha256: str,
    route_status: str,
    plan_status: str,
    status: str,
    steps: tuple[SecurityWorkflowStepState, ...],
    plan_fingerprint: str,
    registry_fingerprint: str,
    binding_fingerprint: str,
    runtime_fingerprint: str,
    reason_codes: tuple[str, ...],
) -> str:
    return sha256_fingerprint(
        {
            "schema_version": SECURITY_WORKFLOW_SESSION_SCHEMA,
            "session_id": session_id,
            "request_sha256": request_sha256,
            "route_status": route_status,
            "plan_status": plan_status,
            "status": status,
            "steps": [step.public_dict() for step in steps],
            "plan_fingerprint": plan_fingerprint,
            "registry_fingerprint": registry_fingerprint,
            "binding_fingerprint": binding_fingerprint,
            "runtime_fingerprint": runtime_fingerprint,
            "reason_codes": list(reason_codes),
            "authority": "advisory",
            "auto_execute": False,
        }
    )


def _build_session(
    *,
    request_sha256: str,
    route_status: str,
    plan_status: str,
    steps: tuple[SecurityWorkflowStepState, ...],
    plan_fingerprint: str,
    registry_fingerprint: str,
    binding_fingerprint: str,
    runtime_fingerprint: str,
    reason_codes: tuple[str, ...],
) -> SecurityWorkflowSession:
    session_id = _session_id(
        request_sha256=request_sha256,
        plan_fingerprint=plan_fingerprint,
        binding_fingerprint=binding_fingerprint,
    )
    status = _session_status(route_status, plan_status, steps)
    fingerprint = _workflow_fingerprint(
        session_id=session_id,
        request_sha256=request_sha256,
        route_status=route_status,
        plan_status=plan_status,
        status=status,
        steps=steps,
        plan_fingerprint=plan_fingerprint,
        registry_fingerprint=registry_fingerprint,
        binding_fingerprint=binding_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
        reason_codes=reason_codes,
    )
    return SecurityWorkflowSession(
        session_id=session_id,
        request_sha256=request_sha256,
        route_status=route_status,
        plan_status=plan_status,
        status=status,
        steps=steps,
        plan_fingerprint=plan_fingerprint,
        registry_fingerprint=registry_fingerprint,
        binding_fingerprint=binding_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
        workflow_fingerprint=fingerprint,
        reason_codes=reason_codes,
    ).validate()


class SecurityAnalystWorkflow:
    """Coordinator for route -> plan -> binding -> one typed invocation at a time.

    Natural-language request content is consumed only by the deterministic router and
    never retained in the workflow session or audit journal. There is deliberately no
    `run_all` API. Every executable step requires a separate typed request and is
    delegated to the v0.5 invoker, which re-authorizes the exact trusted resource.
    """

    def __init__(
        self,
        *,
        invoker: SecurityOperationInvoker,
        journal: SecurityWorkflowAuditJournal,
        registry: SecurityCapabilityRegistry | None = None,
        router: SecurityCapabilityRouter | None = None,
        compiler: SecurityOperationPlanCompiler | None = None,
        binding_registry: SecurityOperationBindingRegistry | None = None,
    ) -> None:
        if not isinstance(invoker, SecurityOperationInvoker):
            raise SecurityWorkflowError("workflow requires SecurityOperationInvoker")
        if not isinstance(journal, SecurityWorkflowAuditJournal):
            raise SecurityWorkflowError("workflow requires SecurityWorkflowAuditJournal")
        self.registry = registry or invoker.registry
        self.router = router or SecurityCapabilityRouter(self.registry)
        self.compiler = compiler or SecurityOperationPlanCompiler(self.registry)
        self.binding_registry = binding_registry or invoker.binding_registry
        self.invoker = invoker
        self.journal = journal
        expected = self.registry.fingerprint
        if self.router.registry.fingerprint != expected:
            raise SecurityWorkflowError("workflow router registry mismatch")
        if self.compiler.registry.fingerprint != expected:
            raise SecurityWorkflowError("workflow compiler registry mismatch")
        if self.binding_registry.registry.fingerprint != expected:
            raise SecurityWorkflowError("workflow binding registry mismatch")
        if self.invoker.registry.fingerprint != expected:
            raise SecurityWorkflowError("workflow invoker registry mismatch")

    def prepare(self, request: str) -> SecurityWorkflowPrepared:
        routing = self.router.route(request)
        plan = self.compiler.compile(routing)
        binding = self.binding_registry.bind_plan(plan)
        steps = self._step_states(plan, binding)
        reasons = tuple(dict.fromkeys(tuple(plan.reason_codes) + ("WORKFLOW_PREPARED_NO_AUTO_EXECUTE",)))
        session = _build_session(
            request_sha256=plan.request_sha256,
            route_status=routing.status,
            plan_status=plan.status,
            steps=steps,
            plan_fingerprint=plan.plan_fingerprint,
            registry_fingerprint=self.registry.fingerprint,
            binding_fingerprint=self.binding_registry.fingerprint,
            runtime_fingerprint=self.invoker.runtime_fingerprint,
            reason_codes=reasons,
        )
        audit_record = self.journal.append(
            event_type="SESSION_PREPARED",
            session_id=session.session_id,
            request_sha256=session.request_sha256,
            plan_fingerprint=session.plan_fingerprint,
            binding_fingerprint=session.binding_fingerprint,
            workflow_fingerprint=session.workflow_fingerprint,
            reason_codes=("WORKFLOW_SESSION_PREPARED",),
        )
        return SecurityWorkflowPrepared(
            session=session,
            routing=routing,
            plan=plan,
            binding=binding,
            audit_record=audit_record,
        )

    def execute_step(
        self,
        prepared: SecurityWorkflowPrepared,
        *,
        step_id: str,
        request: SecurityTypedInvocationRequest,
    ) -> SecurityWorkflowExecution:
        self._validate_prepared(prepared)
        session = prepared.session.validate()
        if session.status in {"denied", "no_route", "blocked", "completed"}:
            raise SecurityWorkflowDenied("WORKFLOW_SESSION_NOT_EXECUTABLE")
        if session.runtime_fingerprint != self.invoker.runtime_fingerprint:
            raise SecurityWorkflowDenied("WORKFLOW_RUNTIME_FINGERPRINT_CHANGED")
        wanted = str(step_id or "").strip()
        states = [step for step in session.steps if step.step_id == wanted]
        if len(states) != 1:
            raise SecurityWorkflowDenied("WORKFLOW_STEP_NOT_IN_SESSION")
        state = states[0].validate()
        if state.state == "unbound":
            raise SecurityWorkflowDenied("WORKFLOW_STEP_HANDLER_UNBOUND")
        if state.state == "completed":
            raise SecurityWorkflowDenied("WORKFLOW_STEP_ALREADY_COMPLETED")

        request.validate()
        input_fingerprint = request.fingerprint
        self._require_audit_replay_safe(session, state.step_id)
        self.journal.append(
            event_type="STEP_REQUESTED",
            session_id=session.session_id,
            request_sha256=session.request_sha256,
            plan_fingerprint=session.plan_fingerprint,
            binding_fingerprint=session.binding_fingerprint,
            workflow_fingerprint=session.workflow_fingerprint,
            reason_codes=("WORKFLOW_TYPED_STEP_REQUESTED",),
            step_id=state.step_id,
            input_fingerprint=input_fingerprint,
        )

        try:
            result = self.invoker.invoke(
                prepared.plan,
                step_id=state.step_id,
                request=request,
            )
        except (
            SecurityOperationHandlerUnbound,
            SecurityOperationInvocationDenied,
            SecurityOperationInvocationError,
            SecurityOperationPlanError,
            SecurityCapabilityDenied,
        ) as exc:
            self.journal.append(
                event_type="STEP_FAILED",
                session_id=session.session_id,
                request_sha256=session.request_sha256,
                plan_fingerprint=session.plan_fingerprint,
                binding_fingerprint=session.binding_fingerprint,
                workflow_fingerprint=session.workflow_fingerprint,
                reason_codes=(_failure_reason(exc),),
                step_id=state.step_id,
                input_fingerprint=input_fingerprint,
            )
            raise

        receipt = result.receipt.validate()
        if receipt.plan_fingerprint != session.plan_fingerprint:
            raise SecurityWorkflowError("invocation receipt plan lineage mismatch")
        if receipt.step_id != state.step_id:
            raise SecurityWorkflowError("invocation receipt step lineage mismatch")
        if receipt.binding_fingerprint != session.binding_fingerprint:
            raise SecurityWorkflowError("invocation receipt binding lineage mismatch")
        if receipt.registry_fingerprint != session.registry_fingerprint:
            raise SecurityWorkflowError("invocation receipt registry lineage mismatch")
        if receipt.input_fingerprint != input_fingerprint:
            raise SecurityWorkflowError("invocation receipt input lineage mismatch")

        receipt_sha256 = sha256_fingerprint(receipt.public_dict())
        completed_state = replace(
            state,
            state="completed",
            input_fingerprint=input_fingerprint,
            invocation_id=receipt.invocation_id,
            invocation_receipt_sha256=receipt_sha256,
        ).validate()
        updated_steps = tuple(
            completed_state if step.step_id == state.step_id else step
            for step in session.steps
        )
        updated_session = _build_session(
            request_sha256=session.request_sha256,
            route_status=session.route_status,
            plan_status=session.plan_status,
            steps=updated_steps,
            plan_fingerprint=session.plan_fingerprint,
            registry_fingerprint=session.registry_fingerprint,
            binding_fingerprint=session.binding_fingerprint,
            runtime_fingerprint=session.runtime_fingerprint,
            reason_codes=session.reason_codes,
        )
        completed_audit = self.journal.append(
            event_type="STEP_COMPLETED",
            session_id=updated_session.session_id,
            request_sha256=updated_session.request_sha256,
            plan_fingerprint=updated_session.plan_fingerprint,
            binding_fingerprint=updated_session.binding_fingerprint,
            workflow_fingerprint=updated_session.workflow_fingerprint,
            reason_codes=("WORKFLOW_TYPED_STEP_COMPLETED",),
            step_id=state.step_id,
            input_fingerprint=input_fingerprint,
            invocation_id=receipt.invocation_id,
        )
        return SecurityWorkflowExecution(
            session=updated_session,
            result=result,
            audit_record=completed_audit,
        )

    @staticmethod
    def _step_states(
        plan: SecurityOperationPlan,
        binding: SecurityPlanBinding,
    ) -> tuple[SecurityWorkflowStepState, ...]:
        plan.validate()
        binding.validate()
        if plan.plan_fingerprint != binding.plan_fingerprint:
            raise SecurityWorkflowError("workflow plan/binding fingerprint mismatch")
        if plan.status != "planned":
            return ()
        if len(plan.steps) != len(binding.steps):
            raise SecurityWorkflowError("workflow plan/binding step count mismatch")
        rows: list[SecurityWorkflowStepState] = []
        for plan_step, bound_step in zip(plan.steps, binding.steps, strict=True):
            if (
                plan_step.step_id != bound_step.step_id
                or plan_step.capability_id != bound_step.capability_id
                or plan_step.operation_id != bound_step.operation_id
            ):
                raise SecurityWorkflowError("workflow plan/binding step lineage mismatch")
            rows.append(
                SecurityWorkflowStepState(
                    sequence=plan_step.sequence,
                    step_id=plan_step.step_id,
                    capability_id=plan_step.capability_id,
                    operation_id=plan_step.operation_id,
                    binding_status=bound_step.status,
                    state=("awaiting_typed_input" if bound_step.status == "bound" else "unbound"),
                    binding_reason_code=bound_step.reason_code,
                    handler_id=bound_step.handler_id,
                ).validate()
            )
        return tuple(rows)

    def _validate_prepared(self, prepared: SecurityWorkflowPrepared) -> None:
        if not isinstance(prepared, SecurityWorkflowPrepared):
            raise SecurityWorkflowError("execute_step requires SecurityWorkflowPrepared")
        prepared.routing.validate()
        prepared.plan.validate()
        prepared.binding.validate()
        prepared.session.validate()
        if prepared.routing.request_sha256 != prepared.session.request_sha256:
            raise SecurityWorkflowError("prepared routing/session request mismatch")
        if prepared.plan.request_sha256 != prepared.session.request_sha256:
            raise SecurityWorkflowError("prepared plan/session request mismatch")
        if prepared.plan.plan_fingerprint != prepared.session.plan_fingerprint:
            raise SecurityWorkflowError("prepared plan/session fingerprint mismatch")
        if prepared.binding.binding_fingerprint != prepared.session.binding_fingerprint:
            raise SecurityWorkflowError("prepared binding/session fingerprint mismatch")
        if prepared.session.registry_fingerprint != self.registry.fingerprint:
            raise SecurityWorkflowError("prepared session registry is stale")
        if prepared.session.binding_fingerprint != self.binding_registry.fingerprint:
            raise SecurityWorkflowError("prepared session binding registry is stale")
        expected_states = self._step_states(prepared.plan, prepared.binding)
        for actual, expected in zip(prepared.session.steps, expected_states, strict=True):
            if actual.state == "completed":
                if (
                    actual.step_id != expected.step_id
                    or actual.capability_id != expected.capability_id
                    or actual.operation_id != expected.operation_id
                    or actual.binding_status != expected.binding_status
                    or actual.handler_id != expected.handler_id
                ):
                    raise SecurityWorkflowError("completed workflow state changed reviewed binding lineage")
            elif actual != expected:
                raise SecurityWorkflowError("prepared session step state does not match plan/binding")
        if len(prepared.session.steps) != len(expected_states):
            raise SecurityWorkflowError("prepared session step count mismatch")
        self._require_session_audited(prepared.session)

    def _require_session_audited(self, session: SecurityWorkflowSession) -> None:
        for record in self.journal.records():
            if record.session_id != session.session_id or record.event_type != "SESSION_PREPARED":
                continue
            if (
                record.request_sha256 == session.request_sha256
                and record.plan_fingerprint == session.plan_fingerprint
                and record.binding_fingerprint == session.binding_fingerprint
            ):
                return
        raise SecurityWorkflowDenied("WORKFLOW_SESSION_PREPARE_AUDIT_MISSING")

    def _require_audit_replay_safe(self, session: SecurityWorkflowSession, step_id: str) -> None:
        relevant = [
            record
            for record in self.journal.records()
            if record.session_id == session.session_id and record.step_id == step_id
        ]
        if any(record.event_type == "STEP_COMPLETED" for record in relevant):
            raise SecurityWorkflowDenied("WORKFLOW_STEP_ALREADY_COMPLETED_IN_AUDIT")
        if relevant and relevant[-1].event_type == "STEP_REQUESTED":
            raise SecurityWorkflowDenied("WORKFLOW_STEP_REQUEST_UNRESOLVED_IN_AUDIT")
