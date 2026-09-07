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
from .runtime_readonly_query import RuntimeReadonlyQueryBundle
from .runtime_reviewed_db_query import ReviewedReadonlyDatabaseQueryBoundary
from .runtime_reviewed_execution import ReviewedExecutionBoundary
from .runtime_reviewed_knowledge_search import ReviewedKnowledgeSearchBoundary
from .runtime_reviewed_read import ReviewedReadBoundary
from .runtime_reviewed_search import ReviewedRepoSearchBoundary
from .runtime_scheduler import (
    CapabilityAdapterRegistry,
    CapabilityInvocation,
    RuntimeSchedulerError,
)
from .runtime_source_authority import RuntimeSourceBindingBundle
from .task_contract import TaskContract

RUNTIME_PRODUCTION_ADAPTER_SCHEMA = "workspace-runtime-production-adapter/v1"
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_IMPLEMENTED = {
    "read_file",
    "search_repo",
    "search_docs",
    "query_db_readonly",
    "run_tests",
    "run_linter",
    "web_gateway",
}


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

    Planner output never provides argv, cwd, HTTP endpoint, callable, raw SQL,
    trusted source class, or trusted local root. Runtime-owned reviewed boundaries
    interpret only typed selectors and immutable source/query bindings. Unimplemented
    capabilities fail at construction rather than falling back to a weaker path.
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
        read_boundary: ReviewedReadBoundary | None = None,
        repo_search_boundary: ReviewedRepoSearchBoundary | None = None,
        knowledge_search_boundary: ReviewedKnowledgeSearchBoundary | None = None,
        db_query_boundary: ReviewedReadonlyDatabaseQueryBoundary | None = None,
        readonly_query_bundle: RuntimeReadonlyQueryBundle | None = None,
        source_binding_bundle: RuntimeSourceBindingBundle | None = None,
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
        if capabilities & {"read_file", "search_repo", "search_docs", "query_db_readonly"}:
            if source_binding_bundle is None:
                raise RuntimeProductionAdapterError("SOURCE_BINDING_BUNDLE_REQUIRED")
            source_binding_bundle.validate(
                compiled_plan=compiled_plan,
                task_contract=task_contract,
                registry=active_registry,
            )
        if "read_file" in capabilities:
            if read_boundary is None:
                raise RuntimeProductionAdapterError("REVIEWED_READ_BOUNDARY_REQUIRED")
            if (
                read_boundary.source_binding_bundle.fingerprint
                != source_binding_bundle.fingerprint
            ):
                raise RuntimeProductionAdapterError(
                    "READ_BOUNDARY_SOURCE_BINDING_MISMATCH"
                )
        if "search_repo" in capabilities:
            if repo_search_boundary is None:
                raise RuntimeProductionAdapterError("REVIEWED_REPO_SEARCH_BOUNDARY_REQUIRED")
            if (
                repo_search_boundary.source_binding_bundle.fingerprint
                != source_binding_bundle.fingerprint
            ):
                raise RuntimeProductionAdapterError(
                    "REPO_SEARCH_BOUNDARY_SOURCE_BINDING_MISMATCH"
                )
        if "search_docs" in capabilities:
            if knowledge_search_boundary is None:
                raise RuntimeProductionAdapterError("REVIEWED_KNOWLEDGE_SEARCH_BOUNDARY_REQUIRED")
            if (
                knowledge_search_boundary.source_binding_bundle.fingerprint
                != source_binding_bundle.fingerprint
            ):
                raise RuntimeProductionAdapterError(
                    "KNOWLEDGE_SEARCH_BOUNDARY_SOURCE_BINDING_MISMATCH"
                )
        if "query_db_readonly" in capabilities:
            if readonly_query_bundle is None:
                raise RuntimeProductionAdapterError("REVIEWED_QUERY_BUNDLE_REQUIRED")
            readonly_query_bundle.validate(
                compiled_plan=compiled_plan,
                invocation_bundle=invocation_bundle,
            )
            if db_query_boundary is None:
                raise RuntimeProductionAdapterError("REVIEWED_DB_QUERY_BOUNDARY_REQUIRED")
            if (
                db_query_boundary.source_binding_bundle.fingerprint
                != source_binding_bundle.fingerprint
            ):
                raise RuntimeProductionAdapterError(
                    "DB_QUERY_BOUNDARY_SOURCE_BINDING_MISMATCH"
                )
            if db_query_boundary.query_bundle.fingerprint != readonly_query_bundle.fingerprint:
                raise RuntimeProductionAdapterError("DB_QUERY_BOUNDARY_QUERY_BUNDLE_MISMATCH")
        elif readonly_query_bundle is not None or db_query_boundary is not None:
            raise RuntimeProductionAdapterError("REVIEWED_DB_QUERY_RUNTIME_UNEXPECTED")
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
        self.read_boundary = read_boundary
        self.repo_search_boundary = repo_search_boundary
        self.knowledge_search_boundary = knowledge_search_boundary
        self.db_query_boundary = db_query_boundary
        self.readonly_query_bundle = readonly_query_bundle
        self.source_binding_bundle = source_binding_bundle
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
            elif capability == "read_file":
                self.register(
                    capability,
                    self._read_file_handler,
                    timeout_mode="cooperative",
                )
            elif capability == "search_repo":
                self.register(
                    capability,
                    self._search_repo_handler,
                    timeout_mode="cooperative",
                )
            elif capability == "search_docs":
                self.register(
                    capability,
                    self._search_docs_handler,
                    timeout_mode="cooperative",
                )
            elif capability == "query_db_readonly":
                self.register(
                    capability,
                    self._query_db_readonly_handler,
                    timeout_mode="cooperative",
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

    def _read_file_handler(
        self,
        invocation: CapabilityInvocation,
    ) -> ProductionNodeExecutionResult:
        if self.read_boundary is None or self.source_binding_bundle is None:
            raise RuntimeProductionAdapterError("REVIEWED_READ_RUNTIME_BOUNDARY_REQUIRED")
        spec = self.invocation_bundle.for_node(invocation.node.node_id)
        if spec.capability != "read_file" or spec.operation != "read":
            raise RuntimeProductionAdapterError("PRODUCTION_READ_INVOCATION_INVALID")
        source_binding = self.source_binding_bundle.for_node(invocation.node.node_id)
        arguments = spec.argument_map()
        max_bytes = int(arguments.get("max_bytes", 1024 * 1024))
        if invocation.remaining_seconds() <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")
        authority = self._node_authority(invocation.node.node_id)
        with authority.scope(self.budget):
            result = self.read_boundary.read_file(
                task_id=self.task_contract.task_id,
                node=invocation.node,
                max_bytes=max_bytes,
            )
        return ProductionNodeExecutionResult(
            result={
                "content_sha256": result.content_sha256,
                "content_bytes": result.content_bytes,
                "invocation_fingerprint": spec.fingerprint,
                "node_authority_fingerprint": authority.fingerprint,
                "source_binding_fingerprint": source_binding.fingerprint,
                "source_binding_bundle_fingerprint": self.source_binding_bundle.fingerprint,
            },
            evidence_refs=_safe_evidence_refs(result.evidence_refs),
            reason_code="READ_FILE_OK",
            succeeded=True,
        )

    def _search_repo_handler(
        self,
        invocation: CapabilityInvocation,
    ) -> ProductionNodeExecutionResult:
        if self.repo_search_boundary is None or self.source_binding_bundle is None:
            raise RuntimeProductionAdapterError("REVIEWED_REPO_SEARCH_RUNTIME_BOUNDARY_REQUIRED")
        spec = self.invocation_bundle.for_node(invocation.node.node_id)
        if spec.capability != "search_repo" or spec.operation != "search":
            raise RuntimeProductionAdapterError("PRODUCTION_REPO_SEARCH_INVOCATION_INVALID")
        arguments = spec.argument_map()
        query = str(arguments["query"])
        max_results = int(arguments.get("max_results", 20))
        remaining = invocation.remaining_seconds()
        if remaining <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")
        source_binding = self.source_binding_bundle.for_node(invocation.node.node_id)
        authority = self._node_authority(invocation.node.node_id)
        with authority.scope(self.budget):
            result = self.repo_search_boundary.search_repo(
                task_id=self.task_contract.task_id,
                node=invocation.node,
                query=query,
                max_results=max_results,
                timeout_seconds=remaining,
            )
        return ProductionNodeExecutionResult(
            result={
                "query_sha256": result.query_sha256,
                "result_sha256": result.result_sha256,
                "result_bytes": result.result_bytes,
                "match_count": result.match_count,
                "files_scanned": result.files_scanned,
                "bytes_scanned": result.bytes_scanned,
                "invocation_fingerprint": spec.fingerprint,
                "node_authority_fingerprint": authority.fingerprint,
                "source_binding_fingerprint": source_binding.fingerprint,
                "source_binding_bundle_fingerprint": self.source_binding_bundle.fingerprint,
            },
            evidence_refs=_safe_evidence_refs(result.evidence_refs),
            reason_code="SEARCH_REPO_OK",
            succeeded=True,
        )

    def _search_docs_handler(
        self,
        invocation: CapabilityInvocation,
    ) -> ProductionNodeExecutionResult:
        if self.knowledge_search_boundary is None or self.source_binding_bundle is None:
            raise RuntimeProductionAdapterError("REVIEWED_KNOWLEDGE_SEARCH_RUNTIME_BOUNDARY_REQUIRED")
        spec = self.invocation_bundle.for_node(invocation.node.node_id)
        if spec.capability != "search_docs" or spec.operation != "search":
            raise RuntimeProductionAdapterError("PRODUCTION_KNOWLEDGE_SEARCH_INVOCATION_INVALID")
        arguments = spec.argument_map()
        query = str(arguments["query"])
        max_results = int(arguments.get("max_results", 5))
        remaining = invocation.remaining_seconds()
        if remaining <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")
        source_binding = self.source_binding_bundle.for_node(invocation.node.node_id)
        authority = self._node_authority(invocation.node.node_id)
        with authority.scope(self.budget):
            result = self.knowledge_search_boundary.search_docs(
                task_id=self.task_contract.task_id,
                node=invocation.node,
                query=query,
                max_results=max_results,
                timeout_seconds=remaining,
            )
        return ProductionNodeExecutionResult(
            result={
                "query_sha256": result.query_sha256,
                "result_sha256": result.result_sha256,
                "result_bytes": result.result_bytes,
                "hit_count": result.hit_count,
                "invocation_fingerprint": spec.fingerprint,
                "node_authority_fingerprint": authority.fingerprint,
                "source_binding_fingerprint": source_binding.fingerprint,
                "source_binding_bundle_fingerprint": self.source_binding_bundle.fingerprint,
            },
            evidence_refs=_safe_evidence_refs(result.evidence_refs),
            reason_code="SEARCH_DOCS_OK",
            succeeded=True,
        )

    def _query_db_readonly_handler(
        self,
        invocation: CapabilityInvocation,
    ) -> ProductionNodeExecutionResult:
        if (
            self.db_query_boundary is None
            or self.readonly_query_bundle is None
            or self.source_binding_bundle is None
        ):
            raise RuntimeProductionAdapterError("REVIEWED_DB_QUERY_RUNTIME_BOUNDARY_REQUIRED")
        spec = self.invocation_bundle.for_node(invocation.node.node_id)
        if spec.capability != "query_db_readonly" or spec.operation != "query":
            raise RuntimeProductionAdapterError("PRODUCTION_DB_QUERY_INVOCATION_INVALID")
        arguments = spec.argument_map()
        query_ref = str(arguments["query_ref"])
        raw_parameters_ref = arguments.get("parameters_ref")
        parameters_ref = None if raw_parameters_ref is None else str(raw_parameters_ref)
        remaining = invocation.remaining_seconds()
        if remaining <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")
        source_binding = self.source_binding_bundle.for_node(invocation.node.node_id)
        authority = self._node_authority(invocation.node.node_id)
        with authority.scope(self.budget):
            result = self.db_query_boundary.query(
                task_id=self.task_contract.task_id,
                node=invocation.node,
                query_ref=query_ref,
                parameters_ref=parameters_ref,
                timeout_seconds=remaining,
            )
        return ProductionNodeExecutionResult(
            result={
                "query_ref": result.query_ref,
                "sql_sha256": result.sql_sha256,
                "parameters_sha256": result.parameters_sha256,
                "result_sha256": result.result_sha256,
                "result_bytes": result.result_bytes,
                "row_count": result.row_count,
                "column_count": result.column_count,
                "invocation_fingerprint": spec.fingerprint,
                "node_authority_fingerprint": authority.fingerprint,
                "source_binding_fingerprint": source_binding.fingerprint,
                "source_binding_bundle_fingerprint": self.source_binding_bundle.fingerprint,
                "query_bundle_fingerprint": self.readonly_query_bundle.fingerprint,
            },
            evidence_refs=_safe_evidence_refs(result.evidence_refs),
            reason_code="DB_QUERY_READONLY_OK",
            succeeded=True,
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
