from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from .model_authority import ModelAuthorityDenied, TaskModelAuthority
from .task_contract import TaskContract


MODEL_GATEWAY_SCHEMA = "workspace-local-model-gateway/v1"
MODEL_CAPABILITIES = frozenset(
    {
        "generation.text",
        "generation.json",
        "retrieval.embedding.query",
        "retrieval.embedding.document",
    }
)
MODEL_TIERS = frozenset({"small", "specialist", "strong"})
_MODEL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
_RUNTIME_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class LocalModelGatewayError(RuntimeError):
    """A model invocation violates the trusted local gateway contract."""


class LocalModelGatewayPolicyError(LocalModelGatewayError):
    """A requested model/capability exceeds immutable task/model policy."""


class GenerationBackend(Protocol):
    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str: ...

    def generate_json(
        self, system_prompt: str, user_prompt: str, **kwargs: Any
    ) -> dict[str, Any]: ...


class EmbeddingBackend(Protocol):
    model_id: str

    def encode_queries(self, inputs: Sequence[str]) -> Any: ...

    def encode_documents(self, inputs: Sequence[str]) -> Any: ...


@dataclass(frozen=True)
class LocalAIModelBinding:
    """Trusted WorkSpace model identity mapped to one already-managed local backend."""

    model_id: str
    runtime_id: str
    runtime_model: str
    tier: str
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        model_id = str(self.model_id).strip().lower()
        runtime_id = str(self.runtime_id).strip().lower()
        runtime_model = str(self.runtime_model).strip()
        tier = str(self.tier).strip().lower()
        capabilities = tuple(
            dict.fromkeys(str(item).strip() for item in self.capabilities if str(item).strip())
        )
        if not _MODEL_ID_RE.fullmatch(model_id):
            raise LocalModelGatewayPolicyError("invalid trusted model_id")
        if not _RUNTIME_ID_RE.fullmatch(runtime_id):
            raise LocalModelGatewayPolicyError("invalid trusted runtime_id")
        if not runtime_model or len(runtime_model) > 256:
            raise LocalModelGatewayPolicyError("runtime_model must be a bounded trusted identifier")
        if tier not in MODEL_TIERS:
            raise LocalModelGatewayPolicyError("model binding tier must be small, specialist, or strong")
        if not capabilities or any(item not in MODEL_CAPABILITIES for item in capabilities):
            raise LocalModelGatewayPolicyError("model binding contains an unsupported capability")
        object.__setattr__(self, "model_id", model_id)
        object.__setattr__(self, "runtime_id", runtime_id)
        object.__setattr__(self, "runtime_model", runtime_model)
        object.__setattr__(self, "tier", tier)
        object.__setattr__(self, "capabilities", capabilities)


class LocalAIModelBindingRegistry:
    """Deny-by-default model/capability registry; user input never creates bindings."""

    def __init__(self, bindings: Sequence[LocalAIModelBinding] = ()) -> None:
        self._bindings: dict[str, LocalAIModelBinding] = {}
        for binding in bindings:
            self.register(binding)

    def register(self, binding: LocalAIModelBinding) -> None:
        if not isinstance(binding, LocalAIModelBinding):
            raise TypeError("model binding registry accepts LocalAIModelBinding only")
        if binding.model_id in self._bindings:
            raise LocalModelGatewayPolicyError(f"duplicate model binding: {binding.model_id}")
        self._bindings[binding.model_id] = binding

    def require(self, model_id: str, capability: str) -> LocalAIModelBinding:
        trusted_id = str(model_id or "").strip().lower()
        binding = self._bindings.get(trusted_id)
        if binding is None:
            raise LocalModelGatewayPolicyError("MODEL_NOT_TRUSTED")
        if capability not in binding.capabilities:
            raise LocalModelGatewayPolicyError("MODEL_CAPABILITY_NOT_TRUSTED")
        return binding

    def bindings(self) -> tuple[LocalAIModelBinding, ...]:
        return tuple(self._bindings[key] for key in sorted(self._bindings))


@dataclass(frozen=True)
class LocalModelInvocationResult:
    value: Any
    task_id: str
    model_id: str
    runtime_id: str
    runtime_model: str
    model_tier: str
    capability: str
    authority_fingerprint: str
    schema_version: str = MODEL_GATEWAY_SCHEMA

    def metadata(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "model_id": self.model_id,
            "runtime_id": self.runtime_id,
            "runtime_model": self.runtime_model,
            "model_tier": self.model_tier,
            "capability": self.capability,
            "authority_fingerprint": self.authority_fingerprint,
            "runtime_download": False,
            "authority_source": "TaskContract",
            "raw_prompt_persisted_by_gateway": False,
        }


class LocalModelGateway:
    """Authority-bound facade over already-created local generation/embedding backends.

    The gateway deliberately does not construct Ollama/vLLM/Transformers clients,
    discover remote models, download weights, select a model from prompt text, or
    grant model tiers. Backend lifecycle/resource management stays with existing
    WorkSpace components. The caller supplies a trusted model id and immutable
    TaskContract; the gateway only verifies that the binding is allowed and calls
    the pre-registered backend.
    """

    def __init__(
        self,
        registry: LocalAIModelBindingRegistry,
        *,
        generation_backends: Mapping[str, GenerationBackend] | None = None,
        embedding_backends: Mapping[str, EmbeddingBackend] | None = None,
    ) -> None:
        self.registry = registry
        self._generation = dict(generation_backends or {})
        self._embedding = dict(embedding_backends or {})

    @staticmethod
    def _authority(contract: TaskContract, binding: LocalAIModelBinding) -> TaskModelAuthority:
        contract.validate()
        authority = TaskModelAuthority.from_contract(contract)
        try:
            authority.require_tier(binding.tier)
        except ModelAuthorityDenied as exc:
            raise LocalModelGatewayPolicyError(exc.reason_code) from exc
        return authority

    @staticmethod
    def _generation_runtime_model(backend: Any) -> str | None:
        config = getattr(backend, "config", None)
        value = getattr(config, "model", None) if config is not None else None
        if value is None:
            value = getattr(backend, "runtime_model", None)
        text = str(value or "").strip()
        return text or None

    def _generation_backend(self, binding: LocalAIModelBinding) -> GenerationBackend:
        backend = self._generation.get(binding.model_id)
        if backend is None:
            raise LocalModelGatewayError("GENERATION_BACKEND_NOT_REGISTERED")
        actual_model = self._generation_runtime_model(backend)
        if actual_model is not None and actual_model != binding.runtime_model:
            raise LocalModelGatewayError("GENERATION_BACKEND_MODEL_MISMATCH")
        return backend

    def _embedding_backend(self, binding: LocalAIModelBinding) -> EmbeddingBackend:
        backend = self._embedding.get(binding.model_id)
        if backend is None:
            raise LocalModelGatewayError("EMBEDDING_BACKEND_NOT_REGISTERED")
        actual_model = str(getattr(backend, "model_id", "") or "").strip()
        if actual_model and actual_model != binding.runtime_model:
            raise LocalModelGatewayError("EMBEDDING_BACKEND_MODEL_MISMATCH")
        return backend

    @staticmethod
    def _output_tokens(contract: TaskContract, requested: int | None) -> int:
        maximum = int(contract.generation_budget.max_output_tokens)
        value = maximum if requested is None else int(requested)
        if value < 1 or value > maximum:
            raise LocalModelGatewayPolicyError("GENERATION_OUTPUT_BUDGET_EXCEEDED")
        return value

    @staticmethod
    def _result(
        value: Any,
        *,
        contract: TaskContract,
        authority: TaskModelAuthority,
        binding: LocalAIModelBinding,
        capability: str,
    ) -> LocalModelInvocationResult:
        return LocalModelInvocationResult(
            value=value,
            task_id=contract.task_id,
            model_id=binding.model_id,
            runtime_id=binding.runtime_id,
            runtime_model=binding.runtime_model,
            model_tier=binding.tier,
            capability=capability,
            authority_fingerprint=authority.fingerprint,
        )

    def generate(
        self,
        contract: TaskContract,
        model_id: str,
        system_prompt: str,
        user_prompt: str,
        *,
        num_predict: int | None = None,
        think: bool = False,
        temperature: float | None = None,
    ) -> LocalModelInvocationResult:
        capability = "generation.text"
        binding = self.registry.require(model_id, capability)
        authority = self._authority(contract, binding)
        backend = self._generation_backend(binding)
        value = backend.generate(
            str(system_prompt),
            str(user_prompt),
            num_predict=self._output_tokens(contract, num_predict),
            think=bool(think),
            temperature=temperature,
            trust_domain=contract.cache_policy.trust_domain,
        )
        if not isinstance(value, str) or not value.strip():
            raise LocalModelGatewayError("GENERATION_BACKEND_RETURNED_INVALID_TEXT")
        return self._result(
            value.strip(),
            contract=contract,
            authority=authority,
            binding=binding,
            capability=capability,
        )

    def generate_json(
        self,
        contract: TaskContract,
        model_id: str,
        system_prompt: str,
        user_prompt: str,
        *,
        num_predict: int | None = None,
        think: bool = False,
        schema_id: str | None = None,
    ) -> LocalModelInvocationResult:
        capability = "generation.json"
        binding = self.registry.require(model_id, capability)
        authority = self._authority(contract, binding)
        if contract.output_schema is None:
            raise LocalModelGatewayPolicyError("TASK_CONTRACT_OUTPUT_SCHEMA_REQUIRED")
        backend = self._generation_backend(binding)
        value = backend.generate_json(
            str(system_prompt),
            str(user_prompt),
            schema=contract.output_schema,
            schema_id=schema_id,
            num_predict=self._output_tokens(contract, num_predict),
            think=bool(think),
            trust_domain=contract.cache_policy.trust_domain,
        )
        if not isinstance(value, dict):
            raise LocalModelGatewayError("GENERATION_BACKEND_RETURNED_INVALID_JSON")
        return self._result(
            value,
            contract=contract,
            authority=authority,
            binding=binding,
            capability=capability,
        )

    def embed_queries(
        self,
        contract: TaskContract,
        model_id: str,
        inputs: Sequence[str],
    ) -> LocalModelInvocationResult:
        capability = "retrieval.embedding.query"
        binding = self.registry.require(model_id, capability)
        authority = self._authority(contract, binding)
        backend = self._embedding_backend(binding)
        value = backend.encode_queries(inputs)
        return self._result(
            value,
            contract=contract,
            authority=authority,
            binding=binding,
            capability=capability,
        )

    def embed_documents(
        self,
        contract: TaskContract,
        model_id: str,
        inputs: Sequence[str],
    ) -> LocalModelInvocationResult:
        capability = "retrieval.embedding.document"
        binding = self.registry.require(model_id, capability)
        authority = self._authority(contract, binding)
        backend = self._embedding_backend(binding)
        value = backend.encode_documents(inputs)
        return self._result(
            value,
            contract=contract,
            authority=authority,
            binding=binding,
            capability=capability,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": MODEL_GATEWAY_SCHEMA,
            "runtime_download": False,
            "model_selection_from_prompt": False,
            "authority_source": "TaskContract",
            "bindings": [
                {
                    "model_id": item.model_id,
                    "runtime_id": item.runtime_id,
                    "runtime_model": item.runtime_model,
                    "tier": item.tier,
                    "capabilities": list(item.capabilities),
                }
                for item in self.registry.bindings()
            ],
        }


def canonical_binding_fingerprint(bindings: Sequence[LocalAIModelBinding]) -> str:
    """Stable digest for trusted binding review/audit without model weights or prompts."""
    import hashlib

    payload = [
        {
            "model_id": item.model_id,
            "runtime_id": item.runtime_id,
            "runtime_model": item.runtime_model,
            "tier": item.tier,
            "capabilities": list(item.capabilities),
        }
        for item in sorted(bindings, key=lambda value: value.model_id)
    ]
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()
