from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol
from urllib.request import Request, urlopen

from .resource_budget import ResourceAdmissionError, ResourceBusyError


class ResidencyBackend(Protocol):
    """Minimal local backend contract for VRAM residency management."""

    def resident_models(self) -> set[str]: ...

    def unload(self, model: str) -> bool: ...


@dataclass(frozen=True)
class ModelResidencyConfig:
    enabled: bool = True
    strategy: str = "on_demand"
    idle_ttl_seconds: float = 120.0
    eviction_policy: str = "idle_lru"
    runtime_download: bool = False

    def __post_init__(self) -> None:
        if self.strategy != "on_demand":
            raise ValueError("model residency strategy must be on_demand")
        if self.eviction_policy != "idle_lru":
            raise ValueError("model residency eviction_policy must be idle_lru")
        if self.idle_ttl_seconds < 0:
            raise ValueError("model residency idle_ttl_seconds must be >= 0")
        if self.runtime_download:
            raise ValueError("runtime model download is forbidden; provision models during deployment")


@dataclass
class _ModelState:
    active_leases: int = 0
    last_used_at: float = 0.0


class OllamaResidencyBackend:
    """Observe and unload already-installed Ollama models using localhost only.

    This adapter never pulls, installs, updates, or discovers remote models.
    Loading remains demand-driven: the normal local inference request asks
    Ollama to materialize an already-provisioned model when it is actually used.
    """

    def __init__(self, base_url: str, *, timeout_seconds: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.scope = f"ollama:{self.base_url}"

    def resident_models(self) -> set[str]:
        with urlopen(f"{self.base_url}/api/ps", timeout=min(self.timeout_seconds, 10.0)) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            return set()
        result: set[str] = set()
        for item in payload.get("models", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if name:
                result.add(name)
        return result

    def unload(self, model: str) -> bool:
        model = str(model).strip()
        if not model:
            return False
        body = json.dumps(
            {"model": model, "prompt": "", "stream": False, "keep_alive": 0},
            ensure_ascii=False,
        ).encode("utf-8")
        req = Request(
            f"{self.base_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=min(self.timeout_seconds, 60.0)) as response:
                response.read()
            return True
        except Exception:
            # Eviction is an optimization and must not corrupt a completed task.
            return False


class ModelResidencyManager:
    """Lease-based, demand-only model residency with TTL/LRU eviction.

    Invariants:
    - this component never downloads or preloads a model;
    - a model is considered active while a lease is held;
    - active models are never eviction candidates;
    - Linux processes coordinate through shared/exclusive file leases;
    - unknown resident models are observed first, not immediately evicted;
    - idle eviction uses TTL then least-recently-used order;
    - pressure eviction ignores TTL but still protects active models;
    - there is no fixed resident-model count.
    """

    def __init__(
        self,
        backend: ResidencyBackend,
        config: ModelResidencyConfig | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        active_probe: Callable[[], set[str]] | None = None,
        lock_root: Path | None = None,
    ):
        self.backend = backend
        self.config = config or ModelResidencyConfig()
        self._clock = clock
        self._active_probe = active_probe
        self._states: dict[str, _ModelState] = {}
        self._lock = threading.RLock()
        self._acquisitions = 0
        self._reuse_hits = 0
        self._evictions = 0
        runtime_dir = Path(os.getenv("THREE_AGENT_RUNTIME_DIR", "/tmp"))
        self._lock_root = lock_root or runtime_dir / "workspace-model-residency"
        backend_scope = str(getattr(backend, "scope", backend.__class__.__name__))
        self._scope_hash = hashlib.sha256(backend_scope.encode("utf-8")).hexdigest()[:16]

    def _lease_path(self, model: str) -> Path:
        model_hash = hashlib.sha256(model.encode("utf-8")).hexdigest()[:24]
        return self._lock_root / f"{self._scope_hash}-{model_hash}.lock"

    @contextmanager
    def _cross_process_active_lease(self, model: str) -> Iterator[None]:
        """Hold a shared Linux flock for the lifetime of one inference lease."""
        path = self._lease_path(model)
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+", encoding="utf-8")
        locked = False
        try:
            try:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
                locked = True
            except (ImportError, OSError):
                # Non-Linux deployments retain in-process protection. The
                # high-assurance WorkSpace deployment is Linux and gets flock.
                pass
            yield
        finally:
            if locked:
                try:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
            handle.close()

    @contextmanager
    def _exclusive_eviction_guard(self, model: str) -> Iterator[bool]:
        """Try to prove no other Linux process currently holds an active lease."""
        path = self._lease_path(model)
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+", encoding="utf-8")
        locked = False
        allowed = True
        try:
            try:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except BlockingIOError:
                    allowed = False
            except (ImportError, OSError):
                # Fall back to local lease/ref-count protection on platforms
                # without flock. Do not invent a network coordination service.
                allowed = True
            yield allowed
        finally:
            if locked:
                try:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
            handle.close()

    def _external_active_models(self) -> set[str]:
        if self._active_probe is None:
            return set()
        try:
            return {str(model) for model in self._active_probe() if str(model).strip()}
        except Exception:
            # Fail safe for an optional external activity source: keep all locally
            # known models out of forced eviction if the source is unavailable.
            return set(self._states)

    def resident_models(self) -> set[str]:
        try:
            return self.backend.resident_models()
        except Exception:
            return set()

    def acquire(self, model: str) -> None:
        model = str(model).strip()
        if not model:
            raise ValueError("model lease requires a non-empty model name")
        if not self.config.enabled:
            return
        now = self._clock()
        residents = self.resident_models()
        with self._lock:
            state = self._states.setdefault(model, _ModelState(last_used_at=now))
            state.active_leases += 1
            state.last_used_at = now
            self._acquisitions += 1
            if model in residents:
                self._reuse_hits += 1

    def release(self, model: str) -> None:
        model = str(model).strip()
        if not model or not self.config.enabled:
            return
        now = self._clock()
        with self._lock:
            state = self._states.setdefault(model, _ModelState(last_used_at=now))
            state.active_leases = max(0, state.active_leases - 1)
            state.last_used_at = now

    @contextmanager
    def lease(self, model: str) -> Iterator[None]:
        if not self.config.enabled:
            yield
            return
        model = str(model).strip()
        if not model:
            raise ValueError("model lease requires a non-empty model name")
        with self._cross_process_active_lease(model):
            self.acquire(model)
            try:
                self.evict_idle(exclude={model})
                yield
            finally:
                self.release(model)

    def active_leases(self, model: str) -> int:
        with self._lock:
            state = self._states.get(model)
            return state.active_leases if state else 0

    def _candidates(self, *, exclude: set[str], honor_ttl: bool) -> list[tuple[float, str]]:
        if not self.config.enabled:
            return []
        now = self._clock()
        residents = self.resident_models()
        external_active = self._external_active_models()
        candidates: list[tuple[float, str]] = []
        with self._lock:
            for model in sorted(residents):
                if model in exclude or model in external_active:
                    continue
                state = self._states.get(model)
                if state is None:
                    # Observe an externally/pre-existing resident model first.
                    # It can become an eviction candidate only after a later pass.
                    self._states[model] = _ModelState(last_used_at=now)
                    continue
                if state.active_leases > 0:
                    continue
                idle_for = max(0.0, now - state.last_used_at)
                if honor_ttl and idle_for < self.config.idle_ttl_seconds:
                    continue
                candidates.append((state.last_used_at, model))
        candidates.sort(key=lambda item: (item[0], item[1]))
        return candidates

    def _evict(self, candidates: list[tuple[float, str]], *, limit: int | None = None) -> tuple[str, ...]:
        evicted: list[str] = []
        for _, model in candidates:
            if limit is not None and len(evicted) >= max(0, limit):
                break
            with self._exclusive_eviction_guard(model) as can_evict:
                if not can_evict:
                    continue
                with self._lock:
                    state = self._states.get(model)
                    if state is not None and state.active_leases > 0:
                        continue
                if self.backend.unload(model):
                    with self._lock:
                        self._states.pop(model, None)
                        self._evictions += 1
                    evicted.append(model)
        return tuple(evicted)

    def evict_idle(self, *, exclude: set[str] | None = None) -> tuple[str, ...]:
        """Evict expired idle models in deterministic LRU order."""
        candidates = self._candidates(exclude=set(exclude or ()), honor_ttl=True)
        return self._evict(candidates)

    def evict_inactive(
        self,
        *,
        exclude: set[str] | None = None,
        limit: int | None = None,
    ) -> tuple[str, ...]:
        """Reclaim inactive resident models under resource pressure.

        TTL is intentionally ignored here; active local/cross-process leases are
        still protected. This is the pressure valve used before refusing a new
        model solely because idle weights occupy VRAM/RAM budget.
        """
        candidates = self._candidates(exclude=set(exclude or ()), honor_ttl=False)
        return self._evict(candidates, limit=limit)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            states = {
                model: {
                    "active_leases": state.active_leases,
                    "last_used_at": state.last_used_at,
                }
                for model, state in sorted(self._states.items())
            }
            return {
                "enabled": self.config.enabled,
                "strategy": self.config.strategy,
                "eviction_policy": self.config.eviction_policy,
                "idle_ttl_seconds": self.config.idle_ttl_seconds,
                "runtime_download": self.config.runtime_download,
                "fixed_model_count_limit": False,
                "cross_process_linux_flock": True,
                "acquisitions": self._acquisitions,
                "reuse_hits": self._reuse_hits,
                "evictions": self._evictions,
                "models": states,
            }


class ResidencyManagedClient:
    """Attach demand-only residency to an existing local inference client.

    The wrapped client remains responsible for the actual inference transport and
    resource admission. This wrapper only owns lifecycle: lease, idle cleanup,
    and one bounded LRU reclaim/retry when admission fails specifically because
    VRAM or RAM is occupied. It never downloads or preloads a model.
    """

    def __init__(self, client: Any, residency: ModelResidencyManager):
        self.client = client
        self.residency = residency
        self.config = client.config
        self.budget_managed_residency = True

    @staticmethod
    def _is_memory_pressure(exc: ResourceAdmissionError) -> bool:
        text = str(exc).upper()
        return "VRAM" in text or "RAM" in text

    def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        model = str(self.config.model).strip()
        with self.residency.lease(model):
            try:
                return getattr(self.client, method)(*args, **kwargs)
            except ResourceBusyError:
                raise
            except ResourceAdmissionError as exc:
                if not self._is_memory_pressure(exc):
                    raise
                evicted = self.residency.evict_inactive(exclude={model})
                if not evicted:
                    raise
                # One deterministic retry only. A second failure is authoritative;
                # do not enter an unbounded eviction/retry loop.
                return getattr(self.client, method)(*args, **kwargs)

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        return self._call("generate", system_prompt, user_prompt, **kwargs)

    def generate_json(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> dict[str, Any]:
        return self._call("generate_json", system_prompt, user_prompt, **kwargs)

    def unload(self) -> None:
        self.client.unload()
