import tempfile
import unittest
from pathlib import Path

from three_agent.resource_budget import (
    GPUResourceState,
    ResourceAdmissionError,
    ResourceBudgetConfig,
    ResourceBudgetManager,
    ResourceBusyError,
    ResourceSnapshot,
)

GIB = 1024**3


class ResourceBudgetTests(unittest.TestCase):
    def manager(self, root: Path, snapshot, sizes, **overrides):
        config = ResourceBudgetConfig(
            enabled=True,
            max_vram_percent=overrides.get("max_vram_percent", 90.0),
            max_ram_percent=overrides.get("max_ram_percent", 90.0),
            max_gpu_util_percent=overrides.get("max_gpu_util_percent", 95.0),
            max_gpu_power_percent=overrides.get("max_gpu_power_percent", 95.0),
            max_gpu_temp_c=overrides.get("max_gpu_temp_c", 85.0),
            max_balance_skew_percent=overrides.get("max_balance_skew_percent", 10.0),
            queue_wait_seconds=overrides.get("queue_wait_seconds", 0.0),
            queue_poll_seconds=0.01,
            model_size_safety_factor=1.0,
            serialize_generation=False,
            reservation_ttl_seconds=900,
        )
        return ResourceBudgetManager(
            "http://127.0.0.1:11434",
            config,
            state_path=root / "reservations.json",
            lock_path=root / "admission.lock",
            probe=lambda: snapshot,
            model_size_probe=lambda model: sizes[model],
            gpu_indices=overrides.get("gpu_indices"),
        )

    def base_snapshot(self, *, loaded=None, used=4, util=20, power=30, temp=50):
        return ResourceSnapshot(
            gpu_total_bytes=64 * GIB,
            gpu_used_bytes=used * GIB,
            gpu_util_percent=util,
            gpu_power_percent=power,
            gpu_temp_c=temp,
            ram_total_bytes=32 * GIB,
            ram_used_bytes=6 * GIB,
            loaded_models=loaded or {},
        )

    def dual_snapshot(self, gpu0, gpu1, *, loaded=None):
        gpus = (
            GPUResourceState(0, "GPU-0", 32 * GIB, gpu0[0] * GIB, gpu0[1], gpu0[2], gpu0[3]),
            GPUResourceState(1, "GPU-1", 32 * GIB, gpu1[0] * GIB, gpu1[1], gpu1[2], gpu1[3]),
        )
        return ResourceSnapshot(
            gpu_total_bytes=64 * GIB,
            gpu_used_bytes=(gpu0[0] + gpu1[0]) * GIB,
            gpu_util_percent=max(gpu0[1], gpu1[1]),
            gpu_power_percent=max(gpu0[2], gpu1[2]),
            gpu_temp_c=max(gpu0[3], gpu1[3]),
            ram_total_bytes=32 * GIB,
            ram_used_bytes=6 * GIB,
            loaded_models=loaded or {},
            gpus=gpus,
        )

    def test_two_models_are_allowed_when_projected_budget_stays_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(root, self.base_snapshot(), {"model-a": 18 * GIB, "model-b": 18 * GIB})
            with manager.admit("model-a") as first:
                self.assertTrue(first.allowed)
                with manager.admit("model-b") as second:
                    self.assertTrue(second.allowed)
                    self.assertLess(second.projected_vram_percent, 90.0)

    def test_second_model_is_denied_when_combined_projection_exceeds_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(root, self.base_snapshot(), {"model-a": 30 * GIB, "model-b": 30 * GIB})
            with manager.admit("model-a"):
                with self.assertRaisesRegex(ResourceAdmissionError, "projected VRAM"):
                    with manager.admit("model-b"):
                        pass

    def test_already_loaded_model_does_not_double_count_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.base_snapshot(loaded={"model-a": 20 * GIB}, used=22)
            manager = self.manager(root, snapshot, {"model-a": 20 * GIB})
            with manager.admit("model-a") as decision:
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.estimated_model_bytes, 0)

    def test_one_busy_gpu_does_not_block_idle_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.dual_snapshot(gpu0=(8, 96, 50, 60), gpu1=(6, 10, 30, 50))
            manager = self.manager(root, snapshot, {"model-a": 8 * GIB})
            with manager.admit("model-a") as decision:
                self.assertTrue(decision.allowed)
                self.assertIn(1, decision.selected_gpu_indices)

    def test_all_busy_gpus_queue_then_timeout_instead_of_generic_denial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.dual_snapshot(gpu0=(8, 96, 50, 60), gpu1=(8, 97, 50, 60))
            manager = self.manager(root, snapshot, {"model-a": 4 * GIB}, queue_wait_seconds=0.0)
            with self.assertRaisesRegex(ResourceBusyError, "timed out waiting"):
                with manager.admit("model-a"):
                    pass

    def test_per_gpu_vram_cap_is_hard_90_percent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.dual_snapshot(gpu0=(29, 20, 30, 50), gpu1=(29, 20, 30, 50))
            manager = self.manager(root, snapshot, {"model-a": 2 * GIB})
            with self.assertRaisesRegex(ResourceAdmissionError, "VRAM"):
                with manager.admit("model-a"):
                    pass

    def test_balanced_projection_targets_no_more_than_ten_percent_skew(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.dual_snapshot(gpu0=(4, 20, 30, 50), gpu1=(10, 20, 30, 50))
            manager = self.manager(root, snapshot, {"model-a": 12 * GIB})
            with manager.admit("model-a") as decision:
                self.assertTrue(decision.allowed)
                self.assertLessEqual(decision.projected_balance_skew_percent, 10.0)

    def test_gpu_scoped_manager_only_sees_requested_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.dual_snapshot(gpu0=(4, 96, 30, 50), gpu1=(6, 10, 30, 50))
            manager = self.manager(root, snapshot, {"model-a": 4 * GIB}, gpu_indices=(1,))
            scoped = manager.snapshot()
            self.assertEqual([gpu.index for gpu in scoped.gpus], [1])
            with manager.admit("model-a") as decision:
                self.assertEqual(decision.selected_gpu_indices, (1,))

    def test_worker_generation_locks_are_scoped_per_gpu(self):
        config = ResourceBudgetConfig()
        gpu0 = ResourceBudgetManager("http://127.0.0.1:11435", config, gpu_indices=(0,))
        gpu1 = ResourceBudgetManager("http://127.0.0.1:11436", config, gpu_indices=(1,))
        dual = ResourceBudgetManager("http://127.0.0.1:11434", config, gpu_indices=(0, 1))
        self.assertNotEqual(gpu0.generation_lock_path, gpu1.generation_lock_path)
        self.assertNotEqual(gpu0.generation_lock_path, dual.generation_lock_path)
        self.assertNotEqual(gpu1.generation_lock_path, dual.generation_lock_path)

    def test_hot_gpu_is_excluded_but_healthy_peer_can_accept_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.dual_snapshot(gpu0=(8, 10, 30, 86), gpu1=(6, 10, 30, 50))
            manager = self.manager(root, snapshot, {"model-a": 6 * GIB})
            with manager.admit("model-a") as decision:
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.selected_gpu_indices, (1,))

    def test_thermal_guard_blocks_when_no_healthy_gpu_remains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(root, self.base_snapshot(temp=86), {"model-a": 4 * GIB})
            with self.assertRaisesRegex(ResourceAdmissionError, "temperature"):
                with manager.admit("model-a"):
                    pass

    def test_power_guard_blocks_when_no_healthy_gpu_remains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(root, self.base_snapshot(power=96), {"model-a": 4 * GIB})
            with self.assertRaisesRegex(ResourceAdmissionError, "power"):
                with manager.admit("model-a"):
                    pass


if __name__ == "__main__":
    unittest.main()
