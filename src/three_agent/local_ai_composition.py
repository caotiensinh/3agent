from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .config import AppConfig
from .local_ai_gateway import (
    EmbeddingBackend,
    GenerationBackend,
    LocalAIModelBinding,
    LocalAIModelBindingRegistry,
    LocalModelGateway,
    LocalModelGatewayPolicyError,
    canonical_binding_fingerprint,
)

LOCAL_AI_COMPOSITION_SCHEMA = "workspace-local-ai-composition/v1"
_BINDING_KEYS = frozenset({"model_id", "runtime_id", "runtime_model", "tier", "capabilities"})


class LocalAICompositionError(ValueError):
    """Trusted local-AI composition is malformed or missing a required backend."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = str(code)
        self.detail = str(detail)
        super().__init__(self.code if not self.detail else f"{self.code}: {self.detail}")


@dataclass(frozen=True)
class LocalAICompositionSpec:
    """Immutable, config-derived local model binding set."""

    bindings: tuple[LocalAIModelBinding, ...]
    schema_version: str = LOCAL_AI_COMPOSITION_SCHEMA

    @property
    def fingerprint(self) -> str:
        return canonical_binding_fingerprint(self.bindings)

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "enabled": True,
            "runtime_download": False,
            "authority_source": "TaskContract",
            "binding_fingerprint": self.fingerprint,
            "bindings": [
                {
                    "model_id": item.model_id,
                    "runtime_id": item.runtime_id,
                    "runtime_model": item.runtime_model,
                    "tier": item.tier,
                    "capabilities": list(item.capabilities),
                }
                for item in self.bindings
            ],
        }


def local_ai_composition_spec(config: AppConfig) -> LocalAICompositionSpec | None:
    """Parse trusted config into immutable bindings without runtime side effects."""

    raw = config.raw.get("local_ai")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise LocalAICompositionError("LOCAL_AI_CONFIG_INVALID", "local_ai must be an object")

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise LocalAICompositionError("LOCAL_AI_CONFIG_INVALID", "local_ai.enabled must be boolean")
    if not enabled:
        return None

    bindings_raw = raw.get("bindings")
    if not isinstance(bindings_raw, list) or not bindings_raw:
        raise LocalAICompositionError(
            "LOCAL_AI_BINDINGS_REQUIRED",
            "enabled local AI requires a non-empty bindings array",
        )

    bindings: list[LocalAIModelBinding] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(bindings_raw):
        if not isinstance(item, Mapping):
            raise LocalAICompositionError(
                "LOCAL_AI_BINDING_INVALID", f"binding[{index}] must be an object"
            )

        keys = frozenset(str(key) for key in item.keys())
        missing = _BINDING_KEYS - keys
        extra = keys - _BINDING_KEYS
        if missing:
            raise LocalAICompositionError(
                "LOCAL_AI_BINDING_INVALID",
                f"binding[{index}] missing keys: {','.join(sorted(missing))}",
            )
        if extra:
            raise LocalAICompositionError(
                "LOCAL_AI_BINDING_INVALID",
                f"binding[{index}] contains unsupported keys: {','.join(sorted(extra))}",
            )

        capabilities = item.get("capabilities")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or any(not isinstance(value, str) or not value.strip() for value in capabilities)
        ):
            raise LocalAICompositionError(
                "LOCAL_AI_BINDING_INVALID",
                f"binding[{index}].capabilities must be a non-empty string array",
            )
        normalized_capabilities = tuple(value.strip() for value in capabilities)
        if len(set(normalized_capabilities)) != len(normalized_capabilities):
            raise LocalAICompositionError(
                "LOCAL_AI_BINDING_INVALID",
                f"binding[{index}].capabilities contains duplicates",
            )

        for field in ("model_id", "runtime_id", "runtime_model", "tier"):
            if not isinstance(item.get(field), str) or not str(item[field]).strip():
                raise LocalAICompositionError(
                    "LOCAL_AI_BINDING_INVALID",
                    f"binding[{index}].{field} must be a non-empty string",
                )

        try:
            binding = LocalAIModelBinding(
                model_id=str(item["model_id"]),
                runtime_id=str(item["runtime_id"]),
                runtime_model=str(item["runtime_model"]),
                tier=str(item["tier"]),
                capabilities=normalized_capabilities,
            )
        except (LocalModelGatewayPolicyError, TypeError, ValueError) as exc:
            raise LocalAICompositionError(
                "LOCAL_AI_BINDING_INVALID", f"binding[{index}] rejected: {exc}"
            ) from exc

        if binding.model_id in seen_ids:
            raise LocalAICompositionError("LOCAL_AI_BINDING_DUPLICATE", binding.model_id)
        seen_ids.add(binding.model_id)
        bindings.append(binding)

    return LocalAICompositionSpec(tuple(bindings))


def build_local_model_gateway(
    config: AppConfig,
    *,
    generation_backends: Mapping[str, GenerationBackend] | None = None,
    embedding_backends: Mapping[str, EmbeddingBackend] | None = None,
) -> LocalModelGateway | None:
    """Compose only trusted bindings onto already-created local backends.

    This function never creates a runtime client, downloads a model, or grants
    model authority. TaskModelAuthority remains derived by LocalModelGateway
    from the immutable TaskContract at invocation time.
    """

    spec = local_ai_composition_spec(config)
    if spec is None:
        return None

    generation_pool = dict(generation_backends or {})
    embedding_pool = dict(embedding_backends or {})
    generation_required = {
        binding.model_id
        for binding in spec.bindings
        if any(capability.startswith("generation.") for capability in binding.capabilities)
    }
    embedding_required = {
        binding.model_id
        for binding in spec.bindings
        if any(
            capability.startswith("retrieval.embedding.")
            for capability in binding.capabilities
        )
    }

    missing_generation = sorted(generation_required - generation_pool.keys())
    if missing_generation:
        raise LocalAICompositionError(
            "LOCAL_AI_GENERATION_BACKEND_MISSING", ",".join(missing_generation)
        )
    missing_embedding = sorted(embedding_required - embedding_pool.keys())
    if missing_embedding:
        raise LocalAICompositionError(
            "LOCAL_AI_EMBEDDING_BACKEND_MISSING", ",".join(missing_embedding)
        )

    registry = LocalAIModelBindingRegistry(spec.bindings)
    return LocalModelGateway(
        registry,
        generation_backends={
            model_id: generation_pool[model_id] for model_id in sorted(generation_required)
        },
        embedding_backends={
            model_id: embedding_pool[model_id] for model_id in sorted(embedding_required)
        },
    )
