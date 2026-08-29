from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Any, Callable

from .config import LLMConfig
from .llm import LocalLLMError, OllamaClient
from .resource_budget import ResourceAdmissionError, ResourceBudgetConfig, ResourceBudgetManager


@dataclass(frozen=True)
class OllamaWorker:
    name: str
    base_url: str
    gpu_indices: tuple[int, ...]
    dual_gpu: bool = False


class OllamaWorkerPool:
    """Route requests to GPU-affined Ollama workers.

    Single-GPU workers are preferred for models that fit below the per-GPU VRAM
    cap. AVAILABLE workers are always preferred over BUSY workers. The dual
    worker is reserved for models that cannot safely fit on either single card.
    For dual-GPU work, projected VRAM skew must be within the configured balance
    target before execution starts.
    """

    def __init__(
        self,
        llm_config: LLMConfig,
        resource_config: ResourceBudgetConfig,
        *,
        gpu0_url: str = "http://127.0.0.1:11435",
        gpu1_url: str = "http://127.0.0.1:11436",
        dual_url: str = "http://127.0.0.1:11434",
        manager_factory: Callable[[OllamaWorker], ResourceBudgetManager] | None = None,
        client_factory: Callable[[OllamaWorker, ResourceBudgetManager], OllamaClient] | None = None,
    ):
        self.config = llm_config
        self.resource_config = resource_config
        self.workers = (
            OllamaWorker("gpu0", gpu0_url.rstrip("/"), (0,), False),
            OllamaWorker("gpu1", gpu1_url.rstrip("/"), (1,), False),
        )
        self.dual_worker = OllamaWorker("dual", dual_url.rstrip("/"), (0, 1), True)
        self._clients: dict[str, OllamaClient] = {}
        self._managers: dict[str, ResourceBudgetManager] = {}
        for worker in (*self.workers, self.dual_worker):
            manager = (
                manager_factory(worker)
                if manager_factory is not None
                else ResourceBudgetManager(
                    worker.base_url,
                    resource_config,
                    gpu_indices=worker.gpu_indices,
                )
            )
            client = (
                client_factory(worker, manager)
                if client_factory is not None
                else OllamaClient(replace(llm_config, base_url=worker.base_url), manager)
            )
            self._managers[worker.name] = manager
            self._clients[worker.name] = client

    @staticmethod
    def _gpu_score(gpu) -> float:
        return (gpu.vram_percent * 0.70) + (gpu.util_percent * 0.30)

    def _single_candidates(self, model: str) -> list[OllamaWorker]:
        candidates: list[tuple[int, float, OllamaWorker]] = []
        for worker in self.workers:
            manager = self._managers[worker.name]
            try:
                snapshot = manager.snapshot()
                if not snapshot.gpus:
                    continue
                gpu = snapshot.gpus[0]
                model_bytes = manager.estimate_model_bytes(model)
            except Exception:
                continue
            cap_bytes = gpu.total_bytes * min(90.0, self.resource_config.max_vram_percent) / 100.0
            if gpu.used_bytes + model_bytes > cap_bytes:
                continue
            if gpu.temp_c >= self.resource_config.max_gpu_temp_c:
                continue
            if gpu.power_percent >= self.resource_config.max_gpu_power_percent:
                continue
            busy_rank = 1 if gpu.util_percent >= self.resource_config.max_gpu_util_percent else 0
            candidates.append((busy_rank, self._gpu_score(gpu), worker))
        candidates.sort(key=lambda item: (item[0], item[1], item[2].name))
        return [worker for _, _, worker in candidates]

    def route_order(self, model: str) -> tuple[OllamaWorker, ...]:
        singles = self._single_candidates(model)
        return tuple(singles) if singles else (self.dual_worker,)

    def _project_dual_skew(self, model: str) -> float | None:
        manager = self._managers[self.dual_worker.name]
        snapshot = manager.snapshot()
        if len(snapshot.gpus) < 2:
            return None
        model_bytes = manager.estimate_model_bytes(model)
        gpus = list(snapshot.gpus)
        projected = [float(gpu.used_bytes) for gpu in gpus]
        totals = [float(gpu.total_bytes) for gpu in gpus]
        limit = min(90.0, self.resource_config.max_vram_percent) / 100.0
        remaining = model_bytes
        chunk = max(64 * 1024 * 1024, remaining // 128 if remaining else 0)
        while remaining > 0:
            eligible = [i for i in range(len(gpus)) if projected[i] < totals[i] * limit]
            if not eligible:
                return None
            idx = min(eligible, key=lambda i: projected[i] / max(1.0, totals[i]))
            capacity = totals[idx] * limit - projected[idx]
            take = min(float(remaining), float(chunk or remaining), capacity)
            if take <= 0:
                return None
            projected[idx] += take
            remaining -= int(take)
        percents = [projected[i] / max(1.0, totals[i]) * 100.0 for i in range(len(gpus))]
        return max(percents) - min(percents)

    def _wait_for_dual_balance(self, model: str) -> None:
        deadline = time.monotonic() + max(0.0, self.resource_config.queue_wait_seconds)
        poll = max(0.05, self.resource_config.queue_poll_seconds)
        target = max(0.0, self.resource_config.max_balance_skew_percent)
        while True:
            try:
                skew = self._project_dual_skew(model)
            except Exception as exc:
                raise ResourceAdmissionError(f"Cannot evaluate dual-GPU balance: {exc}") from exc
            if skew is not None and skew <= target:
                return
            if time.monotonic() >= deadline:
                detail = "capacity unavailable" if skew is None else f"projected skew {skew:.1f}%"
                raise ResourceAdmissionError(
                    f"Dual-GPU balance target <= {target:.1f}% not reached: {detail}"
                )
            time.sleep(poll)

    def _call(self, method: str, *args, **kwargs):
        errors: list[str] = []
        model = self.config.model
        for worker in self.route_order(model):
            client = self._clients[worker.name]
            try:
                if worker.dual_gpu:
                    self._wait_for_dual_balance(model)
                return getattr(client, method)(*args, **kwargs)
            except (ResourceAdmissionError, LocalLLMError) as exc:
                errors.append(f"{worker.name}: {exc}")
                continue
        detail = "; ".join(errors) if errors else "no eligible Ollama worker"
        raise LocalLLMError(f"All Ollama workers failed for {model}: {detail}")

    def generate(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        return self._call("generate", system_prompt, user_prompt, **kwargs)

    def generate_json(self, system_prompt: str, user_prompt: str, **kwargs) -> dict[str, Any]:
        return self._call("generate_json", system_prompt, user_prompt, **kwargs)

    def unload(self) -> None:
        for client in self._clients.values():
            client.unload()

    def status(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for worker in (*self.workers, self.dual_worker):
            manager = self._managers[worker.name]
            try:
                snap = manager.snapshot()
                result[worker.name] = {
                    "base_url": worker.base_url,
                    "gpu_indices": list(worker.gpu_indices),
                    "dual_gpu": worker.dual_gpu,
                    "gpus": [
                        {
                            "index": gpu.index,
                            "vram_percent": round(gpu.vram_percent, 2),
                            "util_percent": round(gpu.util_percent, 2),
                            "power_percent": round(gpu.power_percent, 2),
                            "temp_c": gpu.temp_c,
                        }
                        for gpu in snap.gpus
                    ],
                }
            except Exception as exc:
                result[worker.name] = {
                    "base_url": worker.base_url,
                    "gpu_indices": list(worker.gpu_indices),
                    "dual_gpu": worker.dual_gpu,
                    "error": str(exc),
                }
        return result
