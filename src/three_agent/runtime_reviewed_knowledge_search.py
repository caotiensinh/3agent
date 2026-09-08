from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Protocol

from .capability_registry import CapabilityRegistry
from .inference_scope import current_capability_authority
from .knowledge_plane import InboundKnowledgeImporter, KnowledgePlaneError, LocalKnowledgeIndex
from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_source_authority import (
    RuntimeSourceAuthorityDenied,
    RuntimeSourceBindingBundle,
)
from .task_contract import TaskContract

RUNTIME_REVIEWED_KNOWLEDGE_SEARCH_SCHEMA = "workspace-runtime-reviewed-knowledge-search/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_BUNDLE_RE = re.compile(r"^kb_[a-f0-9]{24}$")
_DEFAULT_MAX_RESULTS = 5
_HARD_MAX_RESULTS = 20
_DEFAULT_MAX_CHARS = 20_000
_HARD_MAX_CHARS = 200_000
_HARD_MAX_BUNDLES = 512


class ReviewedKnowledgeSearchError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class KnowledgeSearchEvidenceSink(Protocol):
    """Persist bounded knowledge-search evidence and return compact evidence refs."""

    def persist_knowledge_search(
        self,
        *,
        task_id: str,
        node_id: str,
        source_class: str,
        resource_ref: str,
        query_sha256: str,
        result: bytes,
        result_sha256: str,
    ) -> tuple[str, ...]: ...


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _validate_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_EVIDENCE_REF_LIMIT_EXCEEDED")
    if not refs:
        raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_EVIDENCE_REQUIRED")
    return tuple(refs)


@dataclass(frozen=True)
class ReviewedKnowledgeSearchResult:
    query_sha256: str
    result_sha256: str
    result_bytes: int
    hit_count: int
    evidence_refs: tuple[str, ...]
    source_binding_fingerprint: str
    schema_version: str = RUNTIME_REVIEWED_KNOWLEDGE_SEARCH_SCHEMA

    def validate(self) -> "ReviewedKnowledgeSearchResult":
        for digest in (
            self.query_sha256,
            self.result_sha256,
            self.source_binding_fingerprint,
        ):
            if not _SHA256_RE.fullmatch(str(digest)):
                raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_DIGEST_INVALID")
        if (
            isinstance(self.result_bytes, bool)
            or not isinstance(self.result_bytes, int)
            or not 0 <= self.result_bytes <= 4 * 1024 * 1024
        ):
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_RESULT_BYTES_INVALID")
        if (
            isinstance(self.hit_count, bool)
            or not isinstance(self.hit_count, int)
            or not 0 <= self.hit_count <= _HARD_MAX_RESULTS
        ):
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_HIT_COUNT_INVALID")
        _validate_refs(tuple(self.evidence_refs))
        return self


class ReviewedKnowledgeSearchBoundary:
    """Production search boundary over the existing one-way public knowledge mirror.

    The runtime-owned source binding supplies the exact trusted knowledge root;
    planner input supplies only a bounded query and result count. Existing bundle
    integrity/public-classification checks are replayed before retrieval, live
    authority is rechecked immediately before backend I/O, and raw hit text is
    emitted only to the injected evidence sink rather than the observation ledger.
    """

    def __init__(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        source_binding_bundle: RuntimeSourceBindingBundle,
        evidence_sink: KnowledgeSearchEvidenceSink,
        registry: CapabilityRegistry | None = None,
        recorder: ResourceEventRecorder | None = None,
        max_chars: int = _DEFAULT_MAX_CHARS,
        max_bundles: int = _HARD_MAX_BUNDLES,
    ):
        active_registry = registry or CapabilityRegistry.default()
        source_binding_bundle.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            registry=active_registry,
        )
        if evidence_sink is None or not callable(
            getattr(evidence_sink, "persist_knowledge_search", None)
        ):
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_EVIDENCE_SINK_REQUIRED")
        if (
            isinstance(max_chars, bool)
            or not isinstance(max_chars, int)
            or not 1 <= max_chars <= _HARD_MAX_CHARS
        ):
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_MAX_CHARS_INVALID")
        if (
            isinstance(max_bundles, bool)
            or not isinstance(max_bundles, int)
            or not 1 <= max_bundles <= _HARD_MAX_BUNDLES
        ):
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_MAX_BUNDLES_INVALID")

        docs_nodes = [
            node for node in compiled_plan.plan.nodes if node.capability == "search_docs"
        ]
        for node in docs_nodes:
            binding = source_binding_bundle.for_node(node.node_id)
            if binding.local_root is None:
                raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_TRUSTED_ROOT_REQUIRED")

        self.compiled_plan = compiled_plan
        self.task_contract = task_contract
        self.source_binding_bundle = source_binding_bundle
        self.evidence_sink = evidence_sink
        self.registry = active_registry
        self.recorder = recorder
        self.max_chars = max_chars
        self.max_bundles = max_bundles

    @staticmethod
    def _deadline(deadline: float) -> None:
        if time.monotonic() > deadline:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")

    def _validate_mirror(self, root, deadline: float) -> None:
        self._deadline(deadline)
        try:
            entries = sorted(root.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_MIRROR_UNAVAILABLE") from exc
        bundles = [
            entry
            for entry in entries
            if _BUNDLE_RE.fullmatch(entry.name)
        ]
        if len(bundles) > self.max_bundles:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_MIRROR_BUNDLE_LIMIT_EXCEEDED")
        validator = InboundKnowledgeImporter(root)
        try:
            for bundle in bundles:
                self._deadline(deadline)
                validator._validate_bundle(bundle)
        except (KnowledgePlaneError, OSError, ValueError) as exc:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_MIRROR_INTEGRITY_INVALID") from exc

    def search_docs(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        query: str,
        max_results: int = _DEFAULT_MAX_RESULTS,
        timeout_seconds: float,
    ) -> ReviewedKnowledgeSearchResult:
        if node.capability != "search_docs" or node.effect != "read" or node.resource_kind != "knowledge":
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_NODE_UNSUPPORTED")
        if task_id != self.task_contract.task_id:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_TASK_MISMATCH")
        if not isinstance(query, str) or not query.strip() or len(query) > 2048 or "\x00" in query:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_QUERY_INVALID")
        if (
            isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= _HARD_MAX_RESULTS
        ):
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_MAX_RESULTS_INVALID")
        if timeout_seconds <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")

        binding = self.source_binding_bundle.for_node(node.node_id)
        binding.validate(
            compiled_plan=self.compiled_plan,
            task_contract=self.task_contract,
            registry=self.registry,
        )
        if (
            binding.capability != node.capability
            or binding.resource_kind != node.resource_kind
            or binding.resource_ref != node.resource_ref
        ):
            raise RuntimeSourceAuthorityDenied("SOURCE_NODE_BINDING_MISMATCH")
        root = binding.local_root
        if root is None:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_TRUSTED_ROOT_REQUIRED")

        authority = current_capability_authority()
        if authority is None:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_NODE_AUTHORITY_REQUIRED")
        if binding.source_class not in authority.allowed_sources:
            raise RuntimeSourceAuthorityDenied("SOURCE_CLASS_NOT_ALLOWED")
        if authority.network_scope != "deny" or authority.write_scope != "none":
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_SCOPE_NOT_ISOLATED")

        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_knowledge_search",
        )

        deadline = time.monotonic() + float(timeout_seconds)
        self._validate_mirror(root, deadline)
        query_text = query.strip()
        query_sha = _sha256(query_text.encode("utf-8"))
        try:
            hits = LocalKnowledgeIndex(root).search(
                query_text,
                max_hits=max_results,
                max_chars=self.max_chars,
            )
        except (KnowledgePlaneError, OSError, ValueError, UnicodeError) as exc:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_BACKEND_FAILED") from exc
        self._deadline(deadline)

        rows: list[dict] = []
        for hit in hits:
            if hit.trust != "untrusted_external":
                raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_TRUST_INVALID")
            if hit.injection_risk not in {"low", "medium", "high"}:
                raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_INJECTION_RISK_INVALID")
            if not _SHA256_RE.fullmatch(str(hit.content_sha256)):
                raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_CONTENT_DIGEST_INVALID")
            rows.append(hit.to_dict())
        if len(rows) > max_results:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_RESULT_LIMIT_EXCEEDED")

        payload = {
            "schema_version": RUNTIME_REVIEWED_KNOWLEDGE_SEARCH_SCHEMA,
            "query_sha256": query_sha,
            "hits": rows,
            "hit_count": len(rows),
        }
        result_bytes = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(result_bytes) > 4 * 1024 * 1024:
            raise ReviewedKnowledgeSearchError("KNOWLEDGE_SEARCH_RESULT_TOO_LARGE")
        result_sha = _sha256(result_bytes)
        refs = self.evidence_sink.persist_knowledge_search(
            task_id=task_id,
            node_id=node.node_id,
            source_class=binding.source_class,
            resource_ref=binding.resource_ref,
            query_sha256=query_sha,
            result=result_bytes,
            result_sha256=result_sha,
        )
        return ReviewedKnowledgeSearchResult(
            query_sha256=query_sha,
            result_sha256=result_sha,
            result_bytes=len(result_bytes),
            hit_count=len(rows),
            evidence_refs=_validate_refs(tuple(refs)),
            source_binding_fingerprint=binding.fingerprint,
        ).validate()
