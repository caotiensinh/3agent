from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.request import urlopen


class ResourceAdmissionError(RuntimeError):
    """Raised when starting a model would violate the configured safety budget."""


class ResourceBusyError(ResourceAdmissionError):
    """Raised when resources stay busy beyond the bounded queue wait."""


@dataclass(frozen=True)
class ResourceBudgetConfig:
    enabled: bool = True
    max_vram_percent: float = 90.0
    max_ram_percent: float = 90.0
    max_gpu_util_percent: float = 95.0
    max_gpu_power_percent: float = 95.0
    max_gpu_temp_c: float = 85.0
    max_balance_skew_percent: float = 10.0
    queue_wait_seconds: float = 120.0
    queue_poll_seconds: float = 1.0
    model_size_safety_factor: float = 1.15
    model_ram_overhead_factor: float = 0.15
    serialize_generation: bool = True
    reservation_ttl_seconds: int = 900


@dataclass(frozen=True)
class GPUResourceState:
    index: int
    uuid: str
    total_bytes: int
    used_bytes: int
    util_percent: float
    power_percent: float
    temp_c: float

    @property
    def vram_percent(self) -> float:
        return (self.used_bytes / max(1, self.total_bytes)) * 100.0


@dataclass(frozen=True)
class ResourceSnapshot:
    gpu_total_bytes: int
    gpu_used_bytes: int
    gpu_util_percent: float
    gpu_power_percent: float
    gpu_temp_c: float
    ram_total_bytes: int
    ram_used_bytes: int
    loaded_models: dict[str, int]
    gpus: tuple[GPUResourceState, ...] = ()


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    model: str
    estimated_model_bytes: int
    projected_vram_percent: float
    projected_ram_percent: float
    reason: str = ""
    selected_gpu_indices: tuple[int, ...] = ()
    projected_gpu_vram_percent: tuple[float, ...] = ()
    projected_balance_skew_percent: float = 0.0
    busy: bool = False


class ResourceBudgetManager:
    """Per-component admission control for local Ollama models.

    Safety is evaluated per physical GPU. A hot/busy GPU no longer poisons the
    aggregate state of every other GPU. GPU utilization is temporary BUSY
    pressure and is queued for a bounded period; VRAM, temperature and power are
    hard per-GPU safety limits.

    When gpu_indices is supplied, all admission state and generation locks are
    scoped to that GPU worker. This allows GPU0 and GPU1 workers to execute in
    parallel while each worker remains serialized internally.
    """

    def __init__(
        self,
        base_url: str,
        config: ResourceBudgetConfig,
        *,
        state_path: Path | None = None,
        lock_path: Path | None = None,
        probe: Callable[[], ResourceSnapshot] | None = None,
        model_size_probe: Callable[[str], int] | None = None,
        gpu_indices: tuple[int, ...] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.gpu_indices = tuple(sorted(set(gpu_indices or ())))
        runtime_dir = Path(os.getenv("THREE_AGENT_RUNTIME_DIR", "/tmp"))
        if self.gpu_indices:
            scope = "gpu" + "-".join(str(index) for index in self.gpu_indices)
        else:
            scope = "default"
        endpoint = re.sub(r"[^A-Za-z0-9]+", "-", self.base_url).strip("-")[-32:]
        suffix = f"{scope}-{endpoint}" if self.gpu_indices else ""
        self.state_path = state_path or runtime_dir / (
            f"3agent-model-reservations-{suffix}.json" if suffix else "3agent-model-reservations.json"
        )
        self.lock_path = lock_path or runtime_dir / (
            f"3agent-model-admission-{suffix}.lock" if suffix else "3agent-model-admission.lock"
        )
        self.generation_lock_path = runtime_dir / (
            f"3agent-generation-{suffix}.lock" if suffix else "3agent-generation.lock"
        )
        self._probe_override = probe
        self._model_size_probe_override = model_size_probe
        self._thread_lock = threading.RLock()

    @staticmethod
    def _clamp_percent(value: float, *, low: float = 1.0, high: float = 100.0) -> float:
        return max(low, min(high, float(value)))

    @contextmanager
    def _file_lock(self, path: Path) -> Iterator[None]:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+", encoding="utf-8")
        used_thread_lock = False
        try:
            try:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except (ImportError, OSError):
                self._thread_lock.acquire()
                used_thread_lock = True
            yield
        finally:
            if used_thread_lock:
                self._thread_lock.release()
            else:
                try:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
            handle.close()

    def _ollama_json(self, path: str) -> dict[str, Any]:
        with urlopen(f"{self.base_url}{path}", timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload if isinstance(payload, dict) else {}

    def _loaded_models(self) -> dict[str, int]:
        payload = self._ollama_json("/api/ps")
        result: dict[str, int] = {}
        for item in payload.get("models", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            try:
                size = int(item.get("size_vram", 0) or 0)
            except (TypeError, ValueError):
                size = 0
            result[name] = max(0, size)
        return result

    def _nvidia_snapshot(self) -> tuple[GPUResourceState, ...]:
        cmd = [
            "nvidia-smi",
            "--query-gpu=index,uuid,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw,power.limit",
            "--format=csv,noheader,nounits",
        ]
        completed = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
        states: list[GPUResourceState] = []
        mib = 1024 * 1024
        for line in completed.stdout.splitlines():
            parts = [part.strip() for part in line.split(",")]
            if len(parts) != 8:
                continue
            try:
                index = int(parts[0])
                uuid = parts[1]
                total = float(parts[2])
                used = float(parts[3])
                util = float(parts[4])
                temp = float(parts[5])
                power = float(parts[6])
                limit = float(parts[7])
            except ValueError:
                continue
            if self.gpu_indices and index not in self.gpu_indices:
                continue
            states.append(
                GPUResourceState(
                    index=index,
                    uuid=uuid,
                    total_bytes=int(total * mib),
                    used_bytes=int(used * mib),
                    util_percent=util,
                    power_percent=(power / limit) * 100.0 if limit > 0 else 0.0,
                    temp_c=temp,
                )
            )
        if not states:
            scope = f" for GPUs {self.gpu_indices}" if self.gpu_indices else ""
            raise ResourceAdmissionError(f"Unable to read NVIDIA GPU resource state{scope}")
        return tuple(sorted(states, key=lambda item: item.index))

    @staticmethod
    def _ram_snapshot() -> tuple[int, int]:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            number = raw.strip().split()[0]
            if number.isdigit():
                values[key] = int(number) * 1024
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        if total <= 0:
            raise ResourceAdmissionError("Unable to read system RAM state")
        return total, max(0, total - available)

    def _filter_snapshot_gpus(self, gpus: tuple[GPUResourceState, ...]) -> tuple[GPUResourceState, ...]:
        if not self.gpu_indices:
            return gpus
        return tuple(gpu for gpu in gpus if gpu.index in self.gpu_indices)

    def snapshot(self) -> ResourceSnapshot:
        if self._probe_override is not None:
            snapshot = self._probe_override()
            if snapshot.gpus:
                gpus = self._filter_snapshot_gpus(snapshot.gpus)
                if not gpus:
                    raise ResourceAdmissionError(f"Probe did not provide requested GPUs {self.gpu_indices}")
                return ResourceSnapshot(
                    gpu_total_bytes=sum(g.total_bytes for g in gpus),
                    gpu_used_bytes=sum(g.used_bytes for g in gpus),
                    gpu_util_percent=max(g.util_percent for g in gpus),
                    gpu_power_percent=max(g.power_percent for g in gpus),
                    gpu_temp_c=max(g.temp_c for g in gpus),
                    ram_total_bytes=snapshot.ram_total_bytes,
                    ram_used_bytes=snapshot.ram_used_bytes,
                    loaded_models=snapshot.loaded_models,
                    gpus=gpus,
                )
            return ResourceSnapshot(
                gpu_total_bytes=snapshot.gpu_total_bytes,
                gpu_used_bytes=snapshot.gpu_used_bytes,
                gpu_util_percent=snapshot.gpu_util_percent,
                gpu_power_percent=snapshot.gpu_power_percent,
                gpu_temp_c=snapshot.gpu_temp_c,
                ram_total_bytes=snapshot.ram_total_bytes,
                ram_used_bytes=snapshot.ram_used_bytes,
                loaded_models=snapshot.loaded_models,
                gpus=(
                    GPUResourceState(
                        0,
                        "aggregate-test-gpu",
                        snapshot.gpu_total_bytes,
                        snapshot.gpu_used_bytes,
                        snapshot.gpu_util_percent,
                        snapshot.gpu_power_percent,
                        snapshot.gpu_temp_c,
                    ),
                ),
            )
        gpus = self._nvidia_snapshot()
        ram_total, ram_used = self._ram_snapshot()
        return ResourceSnapshot(
            gpu_total_bytes=sum(g.total_bytes for g in gpus),
            gpu_used_bytes=sum(g.used_bytes for g in gpus),
            gpu_util_percent=max(g.util_percent for g in gpus),
            gpu_power_percent=max(g.power_percent for g in gpus),
            gpu_temp_c=max(g.temp_c for g in gpus),
            ram_total_bytes=ram_total,
            ram_used_bytes=ram_used,
            loaded_models=self._loaded_models(),
            gpus=gpus,
        )

    def estimate_model_bytes(self, model: str) -> int:
        if self._model_size_probe_override is not None:
            return max(1, int(self._model_size_probe_override(model)))
        payload = self._ollama_json("/api/tags")
        for item in payload.get("models", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            if name == model or name.split(":", 1)[0] == model.split(":", 1)[0]:
                try:
                    disk_size = int(item.get("size", 0) or 0)
                except (TypeError, ValueError):
                    disk_size = 0
                if disk_size > 0:
                    return int(disk_size * max(1.0, self.config.model_size_safety_factor))
        raise ResourceAdmissionError(f"Cannot estimate memory for model {model}; model metadata is unavailable")

    def _ram_overhead_bytes(self, model_bytes: int) -> int:
        factor = max(0.0, min(1.0, float(self.config.model_ram_overhead_factor)))
        return int(max(0, model_bytes) * factor)

    def _read_reservations(self) -> dict[str, dict[str, Any]]:
        if not self.state_path.exists():
            return {}
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict):
            return {}
        now = time.time()
        ttl = max(30, self.config.reservation_ttl_seconds)
        result: dict[str, dict[str, Any]] = {}
        for model, item in raw.items():
            if not isinstance(item, dict):
                continue
            try:
                created = float(item.get("created_at", 0))
                size = int(item.get("bytes", 0))
                count = int(item.get("count", 0))
            except (TypeError, ValueError):
                continue
            if size > 0 and count > 0 and now - created <= ttl:
                result[str(model)] = {"bytes": size, "count": count, "created_at": created}
        return result

    def _write_reservations(self, reservations: dict[str, dict[str, Any]]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(reservations, sort_keys=True), encoding="utf-8")
        tmp.replace(self.state_path)

    def _balanced_projection(
        self,
        gpus: tuple[GPUResourceState, ...],
        candidate_bytes: int,
        reserved_bytes: int,
    ) -> tuple[tuple[float, ...], tuple[int, ...], float] | None:
        if not gpus:
            return None
        limit = self._clamp_percent(self.config.max_vram_percent, high=90.0) / 100.0
        projected = [float(g.used_bytes) for g in gpus]
        totals = [float(g.total_bytes) for g in gpus]
        remaining = max(0, candidate_bytes + reserved_bytes)
        chunk = max(64 * 1024 * 1024, remaining // 128 if remaining else 0)
        while remaining > 0:
            eligible = [i for i in range(len(gpus)) if projected[i] < totals[i] * limit]
            if not eligible:
                return None
            idx = min(eligible, key=lambda i: projected[i] / max(1.0, totals[i]))
            capacity = max(0.0, totals[idx] * limit - projected[idx])
            take = min(float(remaining), float(chunk or remaining), capacity)
            if take <= 0:
                return None
            projected[idx] += take
            remaining -= int(take)
        percents = tuple((projected[i] / max(1.0, totals[i])) * 100.0 for i in range(len(gpus)))
        selected = tuple(gpus[i].index for i in range(len(gpus)) if projected[i] > gpus[i].used_bytes)
        skew = max(percents) - min(percents) if len(percents) > 1 else 0.0
        return percents, selected, skew

    def _decision(
        self,
        model: str,
        snapshot: ResourceSnapshot,
        reservations: dict[str, dict[str, Any]],
    ) -> AdmissionDecision:
        ram_limit = self._clamp_percent(self.config.max_ram_percent, high=95.0)
        util_limit = self._clamp_percent(self.config.max_gpu_util_percent, high=100.0)
        power_limit = self._clamp_percent(self.config.max_gpu_power_percent, high=100.0)
        skew_limit = self._clamp_percent(self.config.max_balance_skew_percent, low=0.0, high=100.0)
        healthy: list[GPUResourceState] = []
        busy: list[GPUResourceState] = []
        rejected: list[str] = []
        for gpu in snapshot.gpus:
            if gpu.vram_percent >= min(90.0, self.config.max_vram_percent):
                rejected.append(f"GPU{gpu.index} VRAM is {gpu.vram_percent:.1f}%")
                continue
            if gpu.power_percent >= power_limit:
                rejected.append(f"GPU{gpu.index} power is {gpu.power_percent:.1f}% of limit")
                continue
            if gpu.temp_c >= self.config.max_gpu_temp_c:
                rejected.append(f"GPU{gpu.index} temperature is {gpu.temp_c:.1f}C")
                continue
            healthy.append(gpu)
            if gpu.util_percent >= util_limit:
                busy.append(gpu)
        if not healthy:
            return AdmissionDecision(
                False,
                model,
                0,
                0.0,
                0.0,
                "; ".join(rejected) or "no healthy GPU is available",
            )

        candidate_loaded = model in snapshot.loaded_models
        candidate_reserved = model in reservations
        candidate_bytes = 0 if (candidate_loaded or candidate_reserved) else self.estimate_model_bytes(model)
        reserved_bytes = sum(
            int(item.get("bytes", 0))
            for name, item in reservations.items()
            if name not in snapshot.loaded_models
        )
        projected_ram = (
            snapshot.ram_used_bytes
            + self._ram_overhead_bytes(reserved_bytes)
            + self._ram_overhead_bytes(candidate_bytes)
        )
        projected_ram_percent = (projected_ram / max(1, snapshot.ram_total_bytes)) * 100.0
        if projected_ram_percent > ram_limit:
            return AdmissionDecision(
                False,
                model,
                candidate_bytes,
                0.0,
                projected_ram_percent,
                f"projected RAM {projected_ram_percent:.1f}% exceeds {ram_limit:.1f}% budget",
            )

        projection = self._balanced_projection(tuple(healthy), candidate_bytes, reserved_bytes)
        if projection is None:
            detail = ", ".join(f"GPU{g.index}={g.vram_percent:.1f}%" for g in snapshot.gpus)
            return AdmissionDecision(
                False,
                model,
                candidate_bytes,
                0.0,
                projected_ram_percent,
                f"per-GPU projected VRAM would exceed 90.0% ({detail})",
            )
        projected_gpu, selected, skew = projection
        projected_vram_percent = max(projected_gpu) if projected_gpu else 0.0

        if healthy and len(busy) == len(healthy):
            detail = ", ".join(f"GPU{g.index}={g.util_percent:.1f}%" for g in healthy)
            return AdmissionDecision(
                False,
                model,
                candidate_bytes,
                projected_vram_percent,
                projected_ram_percent,
                f"all healthy GPUs are busy ({detail})",
                selected,
                projected_gpu,
                skew,
                True,
            )

        reason = ""
        if len(projected_gpu) > 1 and skew > skew_limit:
            reason = (
                f"projected GPU balance skew {skew:.1f}% exceeds target {skew_limit:.1f}%; "
                "allowed because per-GPU safety limits remain satisfied"
            )
        return AdmissionDecision(
            True,
            model,
            candidate_bytes,
            projected_vram_percent,
            projected_ram_percent,
            reason,
            selected,
            projected_gpu,
            skew,
            False,
        )

    def _wait_for_decision(self, model: str) -> tuple[AdmissionDecision, ResourceSnapshot]:
        deadline = time.monotonic() + max(0.0, float(self.config.queue_wait_seconds))
        poll = max(0.05, float(self.config.queue_poll_seconds))
        while True:
            with self._file_lock(self.lock_path):
                reservations = self._read_reservations()
                snapshot = self.snapshot()
                decision = self._decision(model, snapshot, reservations)
            if decision.allowed:
                return decision, snapshot
            if not decision.busy:
                raise ResourceAdmissionError(f"Resource admission denied for {model}: {decision.reason}")
            if time.monotonic() >= deadline:
                raise ResourceBusyError(
                    f"Resource admission timed out waiting for {model}: {decision.reason}"
                )
            time.sleep(poll)

    @contextmanager
    def admit(self, model: str) -> Iterator[AdmissionDecision]:
        if not self.config.enabled:
            yield AdmissionDecision(True, model, 0, 0.0, 0.0)
            return

        generation_lock = self._file_lock(self.generation_lock_path) if self.config.serialize_generation else None
        if generation_lock is not None:
            generation_lock.__enter__()
        try:
            decision, snapshot = self._wait_for_decision(model)
            with self._file_lock(self.lock_path):
                reservations = self._read_reservations()
                if model not in snapshot.loaded_models:
                    existing = reservations.get(model)
                    if existing:
                        existing["count"] = int(existing.get("count", 0)) + 1
                        existing["created_at"] = time.time()
                    else:
                        reservations[model] = {
                            "bytes": max(1, decision.estimated_model_bytes),
                            "count": 1,
                            "created_at": time.time(),
                        }
                    self._write_reservations(reservations)
            yield decision
        finally:
            with self._file_lock(self.lock_path):
                reservations = self._read_reservations()
                existing = reservations.get(model)
                if existing:
                    count = int(existing.get("count", 1)) - 1
                    if count <= 0:
                        reservations.pop(model, None)
                    else:
                        existing["count"] = count
                        existing["created_at"] = time.time()
                    self._write_reservations(reservations)
            if generation_lock is not None:
                generation_lock.__exit__(None, None, None)
