from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol
from urllib.parse import urlsplit

from .capability_registry import CapabilityRegistry
from .execution_budget import TaskExecutionBudgetState
from .metered_runtime import MeteredInternetGateway
from .runtime_invocation import RuntimeInvocationBundle
from .runtime_node_authority import RuntimeNodeAuthority
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_production_scheduler import ProductionNodeExecutionResult
from .runtime_reviewed_execution import ReviewedExecutionBoundary
from .runtime_scheduler import (
    CapabilityAdapterRegistry,
    CapabilityInvocation,
    RuntimeSchedulerError,
)
from .task_contract import TaskContract

RUNTIME_PRODUCTION_ADAPTER_SCHEMA = "workspace-runtime-production-adapter/v1"
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_IMPLEMENTED = {"run_tests", "run_linter", "web_gateway"}


class RuntimeProductionAdapterError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class WebEvidenceSink(Protocol):
    """Durably persist bounded public-web evidence and return compact references."""

    def persist_search_response(
        self,
        *,
        task_id: str,
        node_id: str,
        response: bytes,
        response_sha256: str,
        query_sha256: str,
    ) -> tuple[str, ...]: ...


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _safe_evidence_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise RuntimeProductionAdapterError("PRODUCTION_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise RuntimeProductionAdapterError("PRODUCTION_EVIDENCE_REF_LIMIT_EXCEEDED")
    if not refs:
        raise RuntimeProductionAdapterError("PRODUCTION_EVIDENCE_REQUIRED")
    return tuple(refs)


class ProductionCapabilityAdapterRegistry(CapabilityAdapterRegistry):
    """Typed, boundary-accounted adapters for the production audited scheduler.

    Planner output never provides argv, cwd, HTTP endpoint, callable, or raw SQL.
    Execution profile IDs and public search data are interpreted only through the
    reviewed runtime-owned boundaries below. Unimplemented capabilities fail at
    construction rather than falling back to a weaker path.
    """

    boundary_accounted = True
    schema_version = RUNTIME_PRODUCTION_ADAPTER_SCHEMA

    def __init__(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        invocation_bundle: RuntimeInvocationBundle,
        budget: TaskExecutionBudgetState,
        execution_boundary: ReviewedExecutionBoundary | None = None,
        internet_gateway: MeteredInternetGateway | None = None,
        web_evidence_sink: WebEvidenceSink | None = None,
        search_endpoint: str | None = None,
        registry: CapabilityRegistry | None = None,
    ):
        active_registry = registry or CapabilityRegistry.default()
        super().__init__(active_registry)
        compiled_plan.validate_current(
            task_contract=task_contract,
            registry=active_registry,
        )
        invocation_bundle.validate(compiled_plan)
        if budget.task_id != compiled_plan.plan.task_id:
            raise RuntimeProductionAdapterError("PRODUCTION_ADAPTER_BUDGET_TASK_MISMATCH")

        capabilities = {node.capability for node in compiled_plan.plan.nodes}
        unsupported = sorted(capabilities - _IMPLEMENTED)
        if unsupported:
            raise RuntimeProductionAdapterError(
                "PRODUCTION_CAPABILITY_BOUNDARY_NOT_IMPLEMENTED:" + ",".join(unsupported)
            )
        if capabilities & {"run_tests", "run_linter"} and execution_boundary is None:
            raise RuntimeProductionAdapterError("REVIEWED_EXECUTION_BOUNDARY_REQUIRED")
        if "web_gateway" in capabilities:
            if internet_gateway is None:
                raise RuntimeProductionAdapterError("METERED_INTERNET_GATEWAY_REQUIRED")
            if web_evidence_sink is None:
                raise RuntimeProductionAdapterError("WEB_EVIDENCE_SINK_REQUIRED")
            parsed = urlsplit(str(search_endpoint or ""))
            if parsed.scheme.casefold() != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise RuntimeProductionAdapterError("RUNTIME_SEARCH_ENDPOINT_INVALID")

        self.compiled_plan = compiled_plan
        self.task_contract = task_contract
        self.invocation_bundle = invocation_bundle
        self.budget = budget
        self.execution_boundary = execution_boundary
        self.internet_gateway = internet_gateway
        self.web_evidence_sink = web_evidence_sink
        self.search_endpoint = str(search_endpoint or "")

        for capability in sorted(capabilities):
            if capability in {"run_tests", "run_linter"}:
                self.register(
                    capability,
                    self._execution_handler,
                    timeout_mode="hard",
                )
            elif capability == "web_gateway":
                self.register(
                    capability,
                    self._web_handler,
                    timeout_mode="cooperative",
                )

    def _node_authority(self, node_id: str) -> RuntimeNodeAuthority:
        return RuntimeNodeAuthority.compile(
            task_contract=self.task_contract,
            compiled_plan=self.compiled_plan,
            node_id=node_id,
            registry=self.capability_registry,
        )

    def _execution_handler(
        self,
        invocation: CapabilityInvocation,
    ) -> ProductionNodeExecutionResult:
        if self.execution_boundary is None:
            raise RuntimeProductionAdapterError("REVIEWED_EXECUTION_BOUNDARY_REQUIRED")
        spec = self.invocation_bundle.for_node(invocation.node.node_id)
        if spec.capability != invocation.node.capability:
            raise RuntimeProductionAdapterError("PRODUCTION_INVOCATION_CAPABILITY_MISMATCH")
        arguments = spec.argument_map()
        selector_key = "suite" if spec.capability == "run_tests" else "profile"
        profile_id = str(arguments.get(selector_key, "default"))
        authority = self._node_authority(invocation.node.node_id)
        with authority.scope(self.budget):
            result = self.execution_boundary.invoke(
                task_id=self.task_contract.task_id,
                node=invocation.node,
                profile_id=profile_id,
                timeout_seconds=invocation.remaining_seconds(),
            )
        succeeded = result.returncode == 0
        return ProductionNodeExecutionResult(
            result={
                "returncode": result.returncode,
                "stdout_sha256": result.stdout_sha256,
                "stderr_sha256": result.stderr_sha256,
                "profile_id": profile_id,
                "invocation_fingerprint": spec.fingerprint,
                "node_authority_fingerprint": authority.fingerprint,
            },
            evidence_refs=_safe_evidence_refs(result.evidence_refs),
            reason_code="EXECUTION_OK" if succeeded else "COMMAND_EXIT_NONZERO",
            succeeded=succeeded,
        )

    def _web_handler(
        self,
        invocation: CapabilityInvocation,
    ) -> ProductionNodeExecutionResult:
        if self.internet_gateway is None or self.web_evidence_sink is None:
            raise RuntimeProductionAdapterError("WEB_RUNTIME_BOUNDARY_REQUIRED")
        spec = self.invocation_bundle.for_node(invocation.node.node_id)
        if spec.capability != "web_gateway" or invocation.node.resource_ref != "public_search":
            raise RuntimeProductionAdapterError("PRODUCTION_WEB_INVOCATION_INVALID")
        arguments = spec.argument_map()
        query = str(arguments["query"])
        count = int(arguments.get("count", 10))
        remaining = invocation.remaining_seconds()
        if remaining <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")
        timeout = max(1, min(300, int(math.ceil(remaining))))
        authority = self._node_authority(invocation.node.node_id)
        with authority.scope(self.budget):
            response = self.internet_gateway.search_get(
                "runtime_node",
                self.task_contract.task_id,
                self.search_endpoint,
                {"q": query, "count": count},
                timeout=timeout,
            )
        if not isinstance(response, bytes):
            raise RuntimeProductionAdapterError("WEB_GATEWAY_RESPONSE_INVALID")
        response_sha = _sha256_bytes(response)
        query_sha = _sha256_bytes(query.encode("utf-8"))
        refs = self.web_evidence_sink.persist_search_response(
            task_id=self.task_contract.task_id,
            node_id=invocation.node.node_id,
            response=response,
            response_sha256=response_sha,
            query_sha256=query_sha,
        )
        return ProductionNodeExecutionResult(
            result={
                "response_sha256": response_sha,
                "response_bytes": len(response),
                "query_sha256": query_sha,
                "invocation_fingerprint": spec.fingerprint,
                "node_authority_fingerprint": authority.fingerprint,
            },
            evidence_refs=_safe_evidence_refs(tuple(refs)),
            reason_code="WEB_SEARCH_OK",
            succeeded=True,
        )
