import unittest
from types import SimpleNamespace

from three_agent.config import LLMConfig
from three_agent.model_residency import ModelResidencyConfig, ModelResidencyManager
from three_agent.resource_budget import (
    GPUResourceState,
    ResourceAdmissionError,
    ResourceBudgetConfig,
    ResourceSnapshot,
)
from three_agent.worker_pool import OllamaWorkerPool

GIB = 1024**3


def snapshot(
    index: int,
    *,
    used: int,
    util: float,
    temp: float = 50,
    power: float = 30,
    loaded=None,
):
    gpu = GPUResourceState(
        index=index,
        uuid=f"GPU-{index}",
        total_bytes=32 * GIB,
        used_bytes=used * GIB,
        util_percent=util,
        power_percent=power,
        temp_c=temp,
    )
    return ResourceSnapshot(
        gpu_total_bytes=32 * GIB,
        gpu_used_bytes=used * GIB,
        gpu_util_percent=util,
        gpu_power_percent=power,
        gpu_temp_c=temp,
        ram_total_bytes=32 * GIB,
        ram_used_bytes=6 * GIB,
        loaded_models=loaded or {},
        gpus=(gpu,),
    )


class FakeManager:
    def __init__(self, snap, size):
        self.snap = snap
        self.size = size

    def snapshot(self):
        return self.snap

    def estimate_model_bytes(self, model):
        return self.size


class FakeClient:
    def __init__(self, name, failure=None):
        self.name = name
        self.failure = failure
        self.unloaded = False
        self.config = SimpleNamespace(model="qwen-test")

    def generate(self, *args, **kwargs):
        if self.failure:
            raise self.failure
        return self.name

    def generate_json(self, *args, **kwargs):
        if self.failure:
            raise self.failure
        return {"worker": self.name}

    def unload(self):
        self.unloaded = True


class FakeResidencyBackend:
    def __init__(self):
        self.resident = set()
        self.unloaded = []

    def resident_models(self):
        return set(self.resident)

    def unload(self, model):
        self.unloaded.append(model)
        self.resident.discard(model)
        return True


class WorkerPoolTests(unittest.TestCase):
    def make_pool(self, snaps, size=8 * GIB, failures=None, residency=False):
        failures = failures or {}
        llm = LLMConfig(
            provider="ollama",
            base_url="http://127.0.0.1:11434",
            model="qwen-test",
            timeout_seconds=30,
            keep_alive="2m",
        )
        budget = ResourceBudgetConfig(max_vram_percent=90.0, max_gpu_util_percent=95.0)

        def manager_factory(worker):
            if worker.name == "dual":
                g0 = snaps["gpu0"].gpus[0]
                g1 = snaps["gpu1"].gpus[0]
                dual = ResourceSnapshot(
                    gpu_total_bytes=g0.total_bytes + g1.total_bytes,
                    gpu_used_bytes=g0.used_bytes + g1.used_bytes,
                    gpu_util_percent=max(g0.util_percent, g1.util_percent),
                    gpu_power_percent=max(g0.power_percent, g1.power_percent),
                    gpu_temp_c=max(g0.temp_c, g1.temp_c),
                    ram_total_bytes=32 * GIB,
                    ram_used_bytes=6 * GIB,
                    loaded_models={},
                    gpus=(g0, g1),
                )
                return FakeManager(dual, size)
            return FakeManager(snaps[worker.name], size)

        def client_factory(worker, manager):
            return FakeClient(worker.name, failures.get(worker.name))

        backends = {}

        def residency_factory(worker):
            backend = FakeResidencyBackend()
            backends[worker.name] = backend
            return ModelResidencyManager(
                backend,
                ModelResidencyConfig(idle_ttl_seconds=120),
            )

        pool = OllamaWorkerPool(
            llm,
            budget,
            manager_factory=manager_factory,
            client_factory=client_factory,
            residency_config=(
                ModelResidencyConfig(idle_ttl_seconds=120) if residency else None
            ),
            residency_factory=residency_factory if residency else None,
        )
        pool._test_residency_backends = backends
        return pool

    def test_routes_to_less_loaded_single_gpu(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=18, util=70),
                "gpu1": snapshot(1, used=6, util=20),
            }
        )
        self.assertEqual(pool.route_order("qwen-test")[0].name, "gpu1")
        self.assertEqual(pool.generate("sys", "user"), "gpu1")

    def test_busy_gpu_is_deprioritized_when_other_gpu_can_fit(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=4, util=96),
                "gpu1": snapshot(1, used=20, util=10),
            }
        )
        self.assertEqual(pool.route_order("qwen-test")[0].name, "gpu1")

    def test_single_gpu_that_would_cross_90_percent_is_excluded(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=24, util=10),
                "gpu1": snapshot(1, used=6, util=20),
            },
            size=8 * GIB,
        )
        names = [worker.name for worker in pool.route_order("qwen-test")]
        self.assertEqual(names, ["gpu1"])

    def test_resident_model_is_reused_without_double_counting_worker_vram(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(
                    0,
                    used=28,
                    util=10,
                    loaded={"qwen-test": 8 * GIB},
                ),
                "gpu1": snapshot(1, used=24, util=20),
            },
            size=8 * GIB,
        )
        names = [worker.name for worker in pool.route_order("qwen-test")]
        self.assertIn("gpu0", names)

    def test_large_model_uses_dual_worker_when_no_single_gpu_can_fit(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=4, util=10),
                "gpu1": snapshot(1, used=5, util=15),
            },
            size=30 * GIB,
        )
        self.assertEqual([w.name for w in pool.route_order("qwen-test")], ["dual"])
        self.assertEqual(pool.generate("sys", "user"), "dual")

    def test_worker_local_failure_falls_back_to_other_single_gpu(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=4, util=10),
                "gpu1": snapshot(1, used=6, util=20),
            },
            failures={"gpu0": ResourceAdmissionError("became busy")},
        )
        self.assertEqual(pool.generate("sys", "user"), "gpu1")

    def test_residency_is_scoped_to_each_worker_and_does_not_preload(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=4, util=10),
                "gpu1": snapshot(1, used=6, util=20),
            },
            residency=True,
        )
        self.assertEqual(set(pool._residency), {"gpu0", "gpu1", "dual"})
        self.assertEqual(
            {name: backend.resident for name, backend in pool._test_residency_backends.items()},
            {"gpu0": set(), "gpu1": set(), "dual": set()},
        )
        self.assertEqual(pool.generate("sys", "user"), "gpu0")
        self.assertTrue(all(not backend.unloaded for backend in pool._test_residency_backends.values()))


if __name__ == "__main__":
    unittest.main()
