from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .config import AppConfig
from .local_ai_composition import build_local_model_gateway
from .local_ai_gateway import EmbeddingBackend, GenerationBackend, LocalModelGateway
from .orchestrator import Orchestrator


@dataclass(frozen=True)
class ApplicationRuntime:
    """Trusted application composition result.

    Local AI remains an optional application dependency. The runtime wrapper does
    not grant model authority or expose request-time mutation of trusted bindings.
    """

    orchestrator: Orchestrator
    local_model_gateway: LocalModelGateway | None


def build_application_runtime(
    config: AppConfig,
    *,
    generation_backends: Mapping[str, GenerationBackend] | None = None,
    embedding_backends: Mapping[str, EmbeddingBackend] | None = None,
) -> ApplicationRuntime:
    """Build application services from trusted config without model side effects.

    Gateway composition happens before the Orchestrator is constructed. Invalid
    enabled configuration or missing trusted backend injections therefore fail
    closed before application startup. Backends are supplied by the caller and
    are never created, downloaded, discovered, or invoked by this bootstrap.
    """

    local_model_gateway = build_local_model_gateway(
        config,
        generation_backends=generation_backends,
        embedding_backends=embedding_backends,
    )
    orchestrator = Orchestrator(config)
    return ApplicationRuntime(
        orchestrator=orchestrator,
        local_model_gateway=local_model_gateway,
    )


def build_orchestrator(
    config: AppConfig,
    *,
    generation_backends: Mapping[str, GenerationBackend] | None = None,
    embedding_backends: Mapping[str, EmbeddingBackend] | None = None,
) -> Orchestrator:
    """Backward-compatible startup facade used by existing command surfaces."""

    return build_application_runtime(
        config,
        generation_backends=generation_backends,
        embedding_backends=embedding_backends,
    ).orchestrator
