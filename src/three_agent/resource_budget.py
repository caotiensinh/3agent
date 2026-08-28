from __future__ import annotations

import json
import os
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


@dataclass(frozen=True)
class ResourceBudgetConfig:
    enabled: bool = True
    max_vram_percent: float = 90.0
    max_ram_percent: float = 90.0
    max_gpu_util_percent: float = 95.0
    max_gpu_power_percent: float = 95.0
    max_gpu_temp_c: float = 85.0
    model_size_safety_factor: float = 1.15
    serialize_generation: bool = True
    reservation_ttl_seconds: int = 900


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


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    model: str
    estimated_model_bytes: int
    projected_vram_percent: float
    projected_ram_percent: float
    reason: str = ""


class ResourceBudgetManager:
    """Cross-process admission control for local Ollama models.

    Model residency is not limited by a fixed count. Admission is based on the
    projected memory footprint and live GPU/RAM health. A short reservation is
    recorded before a model starts loading so concurrent requests cannot both
    pass the same stale memory check.
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
    ):
        self.base_url = base_url.rstrip("/")
        self.config = config
        runtime_dir = Path(os.getenv("THREE_AGENT_RUNTIME_DIR", "/tmp"))
        self.state_path = state_path or runtime_dir / "3agent-model-reservations.json"
        self.lock_path = lock_path or runtime_dir / "3agent-model-admission.lock"
        self.generation_lock_path = runtime_dir / "3agent-generation.lock"
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
        try:
            try:
                import fcntl  # Linux/Unix; target AI server is Ubuntu.

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except (ImportError, OSError):
                self._thread_lock.acquire()
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except (ImportError, OSError):
                if self._thread_lock._is_owned():  # type: ignore[attr-defined]
                    self._thread_lock.release()
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

    def _nvidia_snapshot(self) -> tuple[int, int, float, float, float]:
        cmd = [
            "nvidia-smi",
            "--query-gpu=memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw,power.limit",
            "--format=csv,noheader,nounits",
        ]
        completed = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
        total_mib = used_mib = 0.0
        max_util = max_temp = max_power_ratio = 0.0
        rows = 0
        for line in completed.stdout.splitlines():
            parts = [part.strip() for part in line.split(",")]
            if len(parts) != 6:
                continue
            try:
                total, used, util, temp, power, limit = [float(value) for value in parts]
            except ValueError:
                continue
            rows += 1
            total_mib += total
            used_mib += used
            max_util = max(max_util, util)
            max_temp = max(max_temp, temp)
            if limit > 0:
                max_power_ratio = max(max_power_ratio, (power / limit) * 100.0)
        if rows == 0:
            raise ResourceAdmissionError("Unable to read NVIDIA GPU resource state")
        mib = 1024 * 1024
        return (
            int(total_mib * mib),
            int(used_mib * mib),
            max_util,
            max_power_ratio,
            max_temp,
        )

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

    def snapshot(self) -> ResourceSnapshot:
        if self._probe_override is not None:
            return self._probe_override()
        gpu_total, gpu_used, gpu_util, gpu_power, gpu_temp = self._nvidia_snapshot()
        ram_total, ram_used = self._ram_snapshot()
        return ResourceSnapshot(
            gpu_total_bytes=gpu_total,
            gpu_used_bytes=gpu_used,
            gpu_util_percent=gpu_util,
            gpu_power_percent=gpu_power,
            gpu_temp_c=gpu_temp,
            ram_total_bytes=ram_total,
            ram_used_bytes=ram_used,
            loaded_models=self._loaded_models(),
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
        raise ResourceAdmissionError(
            f"Cannot estimate memory for model {model}; model metadata is unavailable"
        )

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

    def _decision(self, model: str, snapshot: ResourceSnapshot, reservations: dict[str, dict[str, Any]]) -> AdmissionDecision:
        vram_limit = self._clamp_percent(self.config.max_vram_percent, high=95.0)
        ram_limit = self._clamp_percent(self.config.max_ram_percent, high=95.0)
        util_limit = self._clamp_percent(self.config.max_gpu_util_percent, high=100.0)
        power_limit = self._clamp_percent(self.config.max_gpu_power_percent, high=100.0)

        if snapshot.gpu_util_percent >= util_limit:
            return AdmissionDecision(False, model, 0, 0.0, 0.0, f"GPU utilization is already {snapshot.gpu_util_percent:.1f}%")
        if snapshot.gpu_power_percent >= power_limit:
            return AdmissionDecision(False, model, 0, 0.0, 0.0, f"GPU power is already {snapshot.gpu_power_percent:.1f}% of limit")
        if snapshot.gpu_temp_c >= self.config.max_gpu_temp_c:
            return AdmissionDecision(False, model, 0, 0.0, 0.0, f"GPU temperature is already {snapshot.gpu_temp_c:.1f}C")

        loaded_bytes = sum(max(0, value) for value in snapshot.loaded_models.values())
        candidate_loaded = model in snapshot.loaded_models
        candidate_reserved = model in reservations
        candidate_bytes = 0 if (candidate_loaded or candidate_reserved) else self.estimate_model_bytes(model)
        reserved_bytes = sum(
            int(item.get("bytes", 0))
            for name, item in reservations.items()
            if name not in snapshot.loaded_models
        )
        projected_gpu = max(snapshot.gpu_used_bytes, loaded_bytes) + reserved_bytes + candidate_bytes
        projected_ram = snapshot.ram_used_bytes + candidate_bytes
        projected_vram_percent = (projected_gpu / max(1, snapshot.gpu_total_bytes)) * 100.0
        projected_ram_percent = (projected_ram / max(1, snapshot.ram_total_bytes)) * 100.0

        if projected_vram_percent > vram_limit:
            return AdmissionDecision(
                False,
                model,
                candidate_bytes,
                projected_vram_percent,
                projected_ram_percent,
                f"projected VRAM {projected_vram_percent:.1f}% exceeds {vram_limit:.1f}% budget",
            )
        if projected_ram_percent > ram_limit:
            return AdmissionDecision(
                False,
                model,
                candidate_bytes,
                projected_vram_percent,
                projected_ram_percent,
                f"projected RAM {projected_ram_percent:.1f}% exceeds {ram_limit:.1f}% budget",
            )
        return AdmissionDecision(
            True,
            model,
            candidate_bytes,
            projected_vram_percent,
            projected_ram_percent,
        )

    @contextmanager
    def admit(self, model: str) -> Iterator[AdmissionDecision]:
        if not self.config.enabled:
            yield AdmissionDecision(True, model, 0, 0.0, 0.0)
            return

        with self._file_lock(self.lock_path):
            reservations = self._read_reservations()
            snapshot = self.snapshot()
            decision = self._decision(model, snapshot, reservations)
            if not decision.allowed:
                raise ResourceAdmissionError(f"Resource admission denied for {model}: {decision.reason}")
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

        generation_lock = self._file_lock(self.generation_lock_path) if self.config.serialize_generation else None
        try:
            if generation_lock is not None:
                generation_lock.__enter__()
            yield decision
        finally:
            if generation_lock is not None:
                generation_lock.__exit__(None, None, None)
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
