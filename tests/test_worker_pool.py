import unittest

from three_agent.config import LLMConfig
from three_agent.resource_budget import (
    GPUResourceState,
    ResourceAdmissionError,
    ResourceBudgetConfig,
    ResourceSnapshot,
)
from three_agent.worker_pool import OllamaWorkerPool

GIB = 1024**3


def snapshot(index: int, *, used: int, util: float, temp: float = 50, power: float = 30):
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
        loaded_models={},
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


class WorkerPoolTests(unittest.TestCase):
    def make_pool(self, snaps, size=8 * GIB, failures=None):
        failures = failures or {}
        llm = LLMConfig(
            provider="ollama",
            base_url="http://127.0.0.1:11434",
            model="qwen-test",
            timeout_seconds=30,
            keep_alive="2m",
        )
        budget = ResourceBudgetConfig(max_vram_percent=90.0)

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

        return OllamaWorkerPool(
            llm,
            budget,
            manager_factory=manager_factory,
            client_factory=client_factory,
        )

    def test_routes_to_less_loaded_single_gpu(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=18, util=70),
                "gpu1": snapshot(1, used=6, util=20),
            }
        )
        self.assertEqual(pool.route_order("qwen-test")[0].name, "gpu1")
        self.assertEqual(pool.generate("sys", "user"), "gpu1")

    def test_high_compute_does_not_override_much_lower_vram_pressure(self):
        pool = self.make_pool(
            {
                "gpu0": snapshot(0, used=4, util=96),
                "gpu1": snapshot(1, used=20, util=10),
            }
        )
        self.assertEqual(pool.route_order("qwen-test")[0].name, "gpu0")

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


if __name__ == "__main__":
    unittest.main()
