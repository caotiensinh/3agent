from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .config import AppConfig
from .model_artifacts import (
    ApprovedModelManifest,
    ModelArtifactError,
    RuntimeModelResolver,
)


LOCAL_AI_STATUS_SCHEMA = "workspace-local-ai-status/v1"
RUNTIME_KINDS = frozenset({"ollama", "huggingface_local"})
MAX_HEALTH_RESPONSE_BYTES = 1024 * 1024
MAX_DISCOVERED_MODELS = 1024
_RUNTIME_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class LocalAIRuntimeError(ValueError):
    """A local AI runtime declaration violates the trusted runtime boundary."""


def _loopback_base_url(value: str) -> str:
    raw = str(value or "").strip().rstrip("/")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise LocalAIRuntimeError("runtime endpoint is invalid") from exc
    if parsed.scheme not in {"http", "https"}:
        raise LocalAIRuntimeError("network runtime endpoint must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise LocalAIRuntimeError("runtime endpoint credentials are forbidden")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise LocalAIRuntimeError("runtime endpoint must be an origin without path/query/fragment")
    host = (parsed.hostname or "").strip().casefold()
    if not host:
        raise LocalAIRuntimeError("runtime endpoint requires a host")
    if host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise LocalAIRuntimeError("runtime endpoint must use a loopback literal or localhost") from exc
        if not address.is_loopback:
            raise LocalAIRuntimeError("runtime endpoint must remain on loopback")
    if port is not None and not 1 <= port <= 65535:
        raise LocalAIRuntimeError("runtime endpoint port is invalid")
    return raw


def _model_names(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        name = str(value or "").strip()
        if name and name not in result:
            result.append(name)
    return tuple(result)


@dataclass(frozen=True)
class LocalAIRuntimeSpec:
    runtime_id: str
    kind: str
    endpoint: str | None = None
    configured_models: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        runtime_id = str(self.runtime_id).strip().lower()
        kind = str(self.kind).strip().lower()
        if not _RUNTIME_ID_RE.fullmatch(runtime_id):
            raise LocalAIRuntimeError("runtime_id must be a compact trusted identifier")
        if kind not in RUNTIME_KINDS:
            raise LocalAIRuntimeError(f"unsupported local AI runtime kind: {kind}")
        endpoint = self.endpoint
        if kind == "ollama":
            if not endpoint:
                raise LocalAIRuntimeError("ollama runtime requires a loopback endpoint")
            endpoint = _loopback_base_url(endpoint)
        elif endpoint is not None:
            raise LocalAIRuntimeError("huggingface_local runtime does not accept a network endpoint")
        object.__setattr__(self, "runtime_id", runtime_id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "endpoint", endpoint)
        object.__setattr__(self, "configured_models", _model_names(self.configured_models))


@dataclass(frozen=True)
class LocalAIModelStatus:
    model_id: str
    runtime_id: str
    configured: bool
    installed: bool
    available: bool
    reason_code: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "runtime_id": self.runtime_id,
            "configured": self.configured,
            "installed": self.installed,
            "available": self.available,
            "reason_code": self.reason_code,
            "authority": "observation",
            "runtime_authority": False,
        }


@dataclass(frozen=True)
class LocalAIRuntimeStatus:
    runtime_id: str
    kind: str
    configured: bool
    healthy: bool
    available: bool
    reason_code: str
    discovered_models: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "runtime_id": self.runtime_id,
            "kind": self.kind,
            "configured": self.configured,
            "healthy": self.healthy,
            "available": self.available,
            "reason_code": self.reason_code,
            "discovered_models": list(self.discovered_models),
            "authority": "observation",
            "runtime_authority": False,
        }


class LocalAIRuntimeRegistry:
    """Trusted in-process registry of local runtime origins, never remote model identity."""

    def __init__(self, specs: Iterable[LocalAIRuntimeSpec] = ()) -> None:
        self._specs: dict[str, LocalAIRuntimeSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: LocalAIRuntimeSpec) -> None:
        if not isinstance(spec, LocalAIRuntimeSpec):
            raise TypeError("runtime registry accepts LocalAIRuntimeSpec only")
        if spec.runtime_id in self._specs:
            raise LocalAIRuntimeError(f"duplicate runtime_id: {spec.runtime_id}")
        self._specs[spec.runtime_id] = spec

    def specs(self) -> tuple[LocalAIRuntimeSpec, ...]:
        return tuple(self._specs[key] for key in sorted(self._specs))


HealthOpener = Callable[[Request, float], Any]


def _default_opener(request: Request, timeout: float) -> Any:
    return urlopen(request, timeout=timeout)


class LocalAIStatusService:
    """Read-only status plane between WorkSpace and already-installed local AI runtimes.

    The service has no model downloader, no model-selection authority, no task
    authority, and no repair action. Runtime health is operational evidence only.
    """

    def __init__(
        self,
        registry: LocalAIRuntimeRegistry,
        *,
        manifest_path: str | Path = "config/models.approved.json",
        model_store: str | Path = "/var/lib/workspace/models",
        timeout_seconds: float = 2.0,
        opener: HealthOpener | None = None,
    ) -> None:
        timeout = float(timeout_seconds)
        if not 0.1 <= timeout <= 10.0:
            raise LocalAIRuntimeError("health timeout must be between 0.1 and 10 seconds")
        self.registry = registry
        self.manifest_path = Path(manifest_path)
        self.model_store = Path(model_store)
        self.timeout_seconds = timeout
        self._opener = opener or _default_opener

    def _ollama(self, spec: LocalAIRuntimeSpec) -> tuple[LocalAIRuntimeStatus, tuple[LocalAIModelStatus, ...]]:
        assert spec.endpoint is not None
        request = Request(f"{spec.endpoint}/api/tags", method="GET")
        try:
            with self._opener(request, self.timeout_seconds) as response:
                raw = response.read(MAX_HEALTH_RESPONSE_BYTES + 1)
            if len(raw) > MAX_HEALTH_RESPONSE_BYTES:
                raise LocalAIRuntimeError("ollama health response exceeds bounded size")
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("models", []), list):
                raise LocalAIRuntimeError("ollama health response has invalid shape")
            discovered: list[str] = []
            for item in payload.get("models", [])[:MAX_DISCOVERED_MODELS]:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("model") or "").strip()
                if name and name not in discovered:
                    discovered.append(name)
            discovered_tuple = tuple(discovered)
            discovered_set = set(discovered_tuple)
            models = tuple(
                LocalAIModelStatus(
                    model_id=name,
                    runtime_id=spec.runtime_id,
                    configured=True,
                    installed=name in discovered_set,
                    available=name in discovered_set,
                    reason_code=("MODEL_AVAILABLE" if name in discovered_set else "MODEL_NOT_INSTALLED"),
                )
                for name in spec.configured_models
            )
            return (
                LocalAIRuntimeStatus(
                    runtime_id=spec.runtime_id,
                    kind=spec.kind,
                    configured=True,
                    healthy=True,
                    available=True,
                    reason_code="RUNTIME_HEALTHY",
                    discovered_models=discovered_tuple,
                ),
                models,
            )
        except Exception:
            models = tuple(
                LocalAIModelStatus(
                    model_id=name,
                    runtime_id=spec.runtime_id,
                    configured=True,
                    installed=False,
                    available=False,
                    reason_code="RUNTIME_UNAVAILABLE",
                )
                for name in spec.configured_models
            )
            return (
                LocalAIRuntimeStatus(
                    runtime_id=spec.runtime_id,
                    kind=spec.kind,
                    configured=True,
                    healthy=False,
                    available=False,
                    reason_code="RUNTIME_UNAVAILABLE",
                ),
                models,
            )

    def _huggingface_local(self, spec: LocalAIRuntimeSpec) -> tuple[LocalAIRuntimeStatus, tuple[LocalAIModelStatus, ...]]:
        try:
            manifest = ApprovedModelManifest.load(self.manifest_path)
        except (OSError, ModelArtifactError):
            return (
                LocalAIRuntimeStatus(
                    runtime_id=spec.runtime_id,
                    kind=spec.kind,
                    configured=True,
                    healthy=False,
                    available=False,
                    reason_code="MODEL_MANIFEST_INVALID",
                ),
                (),
            )
        if not manifest.models:
            return (
                LocalAIRuntimeStatus(
                    runtime_id=spec.runtime_id,
                    kind=spec.kind,
                    configured=True,
                    healthy=True,
                    available=False,
                    reason_code="NO_APPROVED_MODELS",
                ),
                (),
            )

        resolver = RuntimeModelResolver(manifest, self.model_store)
        statuses: list[LocalAIModelStatus] = []
        for model in manifest.models:
            try:
                resolver.resolve(model.model_id)
                installed = True
                reason = "MODEL_AVAILABLE"
            except ModelArtifactError:
                installed = False
                reason = "MODEL_NOT_PROVISIONED_OR_INVALID"
            statuses.append(
                LocalAIModelStatus(
                    model_id=model.model_id,
                    runtime_id=spec.runtime_id,
                    configured=True,
                    installed=installed,
                    available=installed,
                    reason_code=reason,
                )
            )
        available = any(item.available for item in statuses)
        return (
            LocalAIRuntimeStatus(
                runtime_id=spec.runtime_id,
                kind=spec.kind,
                configured=True,
                healthy=True,
                available=available,
                reason_code=("RUNTIME_READY" if available else "NO_VALID_PROVISIONED_MODELS"),
            ),
            tuple(statuses),
        )

    def snapshot(self) -> dict[str, Any]:
        runtimes: list[LocalAIRuntimeStatus] = []
        models: list[LocalAIModelStatus] = []
        for spec in self.registry.specs():
            if spec.kind == "ollama":
                runtime, runtime_models = self._ollama(spec)
            elif spec.kind == "huggingface_local":
                runtime, runtime_models = self._huggingface_local(spec)
            else:  # guarded by LocalAIRuntimeSpec, retained as a fail-closed invariant
                raise LocalAIRuntimeError(f"unsupported runtime kind: {spec.kind}")
            runtimes.append(runtime)
            models.extend(runtime_models)
        return {
            "schema_version": LOCAL_AI_STATUS_SCHEMA,
            "authority": "observation",
            "runtime_download": False,
            "grants_model_authority": False,
            "grants_capability_authority": False,
            "runtimes": [item.as_dict() for item in runtimes],
            "models": [item.as_dict() for item in models],
        }


def default_local_ai_runtime_registry(config: AppConfig) -> LocalAIRuntimeRegistry:
    """Build registry only from trusted local WorkSpace configuration."""
    specs: list[LocalAIRuntimeSpec] = [
        LocalAIRuntimeSpec(runtime_id="huggingface-local", kind="huggingface_local")
    ]
    if str(config.llm.provider).strip().lower() == "ollama":
        policy = config.model_policy
        configured = [config.llm.model]
        if policy is not None and policy.enabled:
            configured.extend(
                [
                    policy.fast_model,
                    policy.research_model,
                    policy.presentation_model,
                    policy.report_model,
                    policy.deep_model,
                ]
            )
        specs.append(
            LocalAIRuntimeSpec(
                runtime_id="ollama-local",
                kind="ollama",
                endpoint=config.llm.base_url,
                configured_models=_model_names(configured),
            )
        )
    return LocalAIRuntimeRegistry(specs)


def local_ai_status_service_from_config(
    config: AppConfig,
    *,
    manifest_path: str | Path = "config/models.approved.json",
    model_store: str | Path | None = None,
    timeout_seconds: float = 2.0,
    opener: HealthOpener | None = None,
) -> LocalAIStatusService:
    store = model_store or os.getenv("WORKSPACE_MODEL_STORE") or "/var/lib/workspace/models"
    return LocalAIStatusService(
        default_local_ai_runtime_registry(config),
        manifest_path=manifest_path,
        model_store=store,
        timeout_seconds=timeout_seconds,
        opener=opener,
    )
