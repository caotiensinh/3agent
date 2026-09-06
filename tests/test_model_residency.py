import unittest
from types import SimpleNamespace

from three_agent.model_residency import (
    ModelResidencyConfig,
    ModelResidencyManager,
    ResidencyManagedClient,
)
from three_agent.resource_budget import ResourceAdmissionError, ResourceBusyError


class FakeBackend:
    def __init__(self, resident=()):
        self.resident = set(resident)
        self.unloaded = []

    def resident_models(self):
        return set(self.resident)

    def unload(self, model):
        self.unloaded.append(model)
        self.resident.discard(model)
        return True


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeClient:
    def __init__(self, model="model-a", failures=()):
        self.config = SimpleNamespace(model=model)
        self.failures = list(failures)
        self.calls = 0
        self.unload_calls = 0

    def generate(self, *_args, **_kwargs):
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return "READY"

    def generate_json(self, *_args, **_kwargs):
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return {"status": "READY"}

    def unload(self):
        self.unload_calls += 1


class ModelResidencyTests(unittest.TestCase):
    def manager(self, backend, clock, **overrides):
        return ModelResidencyManager(
            backend,
            ModelResidencyConfig(
                enabled=True,
                strategy="on_demand",
                idle_ttl_seconds=overrides.get("idle_ttl_seconds", 60.0),
                eviction_policy="idle_lru",
                runtime_download=False,
            ),
            clock=clock,
            active_probe=overrides.get("active_probe"),
        )

    def test_acquire_never_loads_or_downloads_a_model(self):
        backend = FakeBackend()
        clock = FakeClock()
        manager = self.manager(backend, clock)

        with manager.lease("model-a"):
            self.assertEqual(manager.active_leases("model-a"), 1)
            self.assertEqual(backend.resident, set())
            self.assertEqual(backend.unloaded, [])

        self.assertEqual(manager.active_leases("model-a"), 0)

    def test_resident_model_is_counted_as_reuse(self):
        backend = FakeBackend({"model-a"})
        clock = FakeClock()
        manager = self.manager(backend, clock)

        with manager.lease("model-a"):
            pass

        snapshot = manager.snapshot()
        self.assertEqual(snapshot["acquisitions"], 1)
        self.assertEqual(snapshot["reuse_hits"], 1)

    def test_idle_model_is_evicted_after_ttl(self):
        backend = FakeBackend({"model-a"})
        clock = FakeClock()
        manager = self.manager(backend, clock, idle_ttl_seconds=30.0)

        with manager.lease("model-a"):
            pass
        clock.advance(31.0)

        self.assertEqual(manager.evict_idle(), ("model-a",))
        self.assertEqual(backend.unloaded, ["model-a"])

    def test_active_lease_is_never_evicted(self):
        backend = FakeBackend({"model-a"})
        clock = FakeClock()
        manager = self.manager(backend, clock, idle_ttl_seconds=0.0)

        manager.acquire("model-a")
        self.assertEqual(manager.evict_inactive(), ())
        self.assertEqual(backend.unloaded, [])
        manager.release("model-a")

    def test_cross_process_active_model_is_never_evicted(self):
        backend = FakeBackend({"model-a"})
        clock = FakeClock()
        manager = self.manager(
            backend,
            clock,
            idle_ttl_seconds=0.0,
            active_probe=lambda: {"model-a"},
        )

        # Observe first; a second pass would normally make it eligible.
        self.assertEqual(manager.evict_idle(), ())
        clock.advance(1.0)
        self.assertEqual(manager.evict_inactive(), ())
        self.assertEqual(backend.unloaded, [])

    def test_lru_pressure_eviction_is_deterministic(self):
        backend = FakeBackend({"model-a", "model-b", "model-c"})
        clock = FakeClock()
        manager = self.manager(backend, clock)

        with manager.lease("model-a"):
            pass
        clock.advance(10.0)
        with manager.lease("model-b"):
            pass
        clock.advance(10.0)
        with manager.lease("model-c"):
            pass

        evicted = manager.evict_inactive(limit=2)
        self.assertEqual(evicted, ("model-a", "model-b"))
        self.assertEqual(backend.unloaded, ["model-a", "model-b"])
        self.assertIn("model-c", backend.resident)

    def test_unknown_resident_model_is_observed_before_eviction(self):
        backend = FakeBackend({"external-model"})
        clock = FakeClock()
        manager = self.manager(backend, clock, idle_ttl_seconds=0.0)

        self.assertEqual(manager.evict_inactive(), ())
        self.assertEqual(backend.unloaded, [])
        clock.advance(1.0)
        self.assertEqual(manager.evict_inactive(), ("external-model",))

    def test_there_is_no_fixed_resident_model_count(self):
        backend = FakeBackend({f"model-{index}" for index in range(20)})
        clock = FakeClock()
        manager = self.manager(backend, clock, idle_ttl_seconds=9999.0)

        for index in range(20):
            with manager.lease(f"model-{index}"):
                pass

        snapshot = manager.snapshot()
        self.assertFalse(snapshot["fixed_model_count_limit"])
        self.assertEqual(snapshot["evictions"], 0)

    def test_runtime_download_cannot_be_enabled(self):
        with self.assertRaisesRegex(ValueError, "runtime model download is forbidden"):
            ModelResidencyConfig(runtime_download=True)

    def test_memory_pressure_reclaims_inactive_model_then_retries_once(self):
        backend = FakeBackend({"model-b"})
        clock = FakeClock()
        manager = self.manager(backend, clock, idle_ttl_seconds=9999.0)
        # Observe model-b so a pressure pass may reclaim it.
        self.assertEqual(manager.evict_inactive(), ())
        client = FakeClient(
            failures=(ResourceAdmissionError("projected VRAM exceeds budget"),)
        )
        wrapped = ResidencyManagedClient(client, manager)

        self.assertEqual(wrapped.generate("system", "user"), "READY")
        self.assertEqual(client.calls, 2)
        self.assertEqual(backend.unloaded, ["model-b"])

    def test_non_memory_admission_failure_does_not_trigger_eviction(self):
        backend = FakeBackend({"model-b"})
        clock = FakeClock()
        manager = self.manager(backend, clock)
        self.assertEqual(manager.evict_inactive(), ())
        client = FakeClient(
            failures=(ResourceAdmissionError("GPU0 temperature is 86.0C"),)
        )
        wrapped = ResidencyManagedClient(client, manager)

        with self.assertRaises(ResourceAdmissionError):
            wrapped.generate("system", "user")
        self.assertEqual(client.calls, 1)
        self.assertEqual(backend.unloaded, [])

    def test_busy_admission_failure_does_not_trigger_eviction(self):
        backend = FakeBackend({"model-b"})
        clock = FakeClock()
        manager = self.manager(backend, clock)
        self.assertEqual(manager.evict_inactive(), ())
        client = FakeClient(
            failures=(ResourceBusyError("timed out waiting for GPU"),)
        )
        wrapped = ResidencyManagedClient(client, manager)

        with self.assertRaises(ResourceBusyError):
            wrapped.generate("system", "user")
        self.assertEqual(client.calls, 1)
        self.assertEqual(backend.unloaded, [])


if __name__ == "__main__":
    unittest.main()
