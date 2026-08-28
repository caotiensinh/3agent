import tempfile
import unittest
from pathlib import Path

from three_agent.resource_budget import (
    ResourceAdmissionError,
    ResourceBudgetConfig,
    ResourceBudgetManager,
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

    def test_two_models_are_allowed_when_projected_budget_stays_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(
                root,
                self.base_snapshot(),
                {"model-a": 18 * GIB, "model-b": 18 * GIB},
            )
            with manager.admit("model-a") as first:
                self.assertTrue(first.allowed)
                with manager.admit("model-b") as second:
                    self.assertTrue(second.allowed)
                    self.assertLess(second.projected_vram_percent, 90.0)

    def test_second_model_is_denied_when_combined_projection_exceeds_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(
                root,
                self.base_snapshot(),
                {"model-a": 30 * GIB, "model-b": 30 * GIB},
            )
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

    def test_thermal_guard_blocks_new_work_before_memory_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(
                root,
                self.base_snapshot(temp=86),
                {"model-a": 4 * GIB},
            )
            with self.assertRaisesRegex(ResourceAdmissionError, "temperature"):
                with manager.admit("model-a"):
                    pass

    def test_power_guard_blocks_new_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self.manager(
                root,
                self.base_snapshot(power=96),
                {"model-a": 4 * GIB},
            )
            with self.assertRaisesRegex(ResourceAdmissionError, "power"):
                with manager.admit("model-a"):
                    pass


if __name__ == "__main__":
    unittest.main()
