import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.model_residency import ModelResidencyManager, _default_runtime_dir


class _Backend:
    def resident_models(self):
        return set()

    def unload(self, _model):
        return True


class ModelResidencyRuntimePathTests(unittest.TestCase):
    def test_explicit_runtime_override_remains_authoritative(self):
        with tempfile.TemporaryDirectory() as tmp:
            explicit = Path(tmp) / "operator-runtime"
            with patch.dict(
                os.environ,
                {
                    "THREE_AGENT_RUNTIME_DIR": str(explicit),
                    "XDG_RUNTIME_DIR": str(Path(tmp) / "xdg-runtime"),
                },
                clear=False,
            ):
                self.assertEqual(_default_runtime_dir(), explicit)

    def test_xdg_runtime_is_used_instead_of_process_global_tmp(self):
        with tempfile.TemporaryDirectory() as tmp:
            xdg_runtime = Path(tmp) / "run-user"
            xdg_runtime.mkdir()
            with patch.dict(
                os.environ,
                {
                    "THREE_AGENT_RUNTIME_DIR": "",
                    "XDG_RUNTIME_DIR": str(xdg_runtime),
                },
                clear=False,
            ):
                manager = ModelResidencyManager(_Backend())
                with manager.lease("model-a"):
                    pass

                self.assertEqual(
                    manager._lock_root,
                    xdg_runtime / "workspace-model-residency",
                )
                self.assertNotEqual(
                    manager._lock_root,
                    Path("/tmp") / "workspace-model-residency",
                )

    def test_missing_or_relative_xdg_falls_back_to_user_home_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            with patch.dict(
                os.environ,
                {
                    "THREE_AGENT_RUNTIME_DIR": "",
                    "XDG_RUNTIME_DIR": "relative-runtime",
                },
                clear=False,
            ), patch("three_agent.model_residency.Path.home", return_value=home):
                expected = home / ".cache" / "workspace" / "runtime"
                self.assertEqual(_default_runtime_dir(), expected)

                manager = ModelResidencyManager(_Backend())
                with manager.lease("model-a"):
                    pass

                self.assertEqual(
                    manager._lock_root,
                    expected / "workspace-model-residency",
                )


if __name__ == "__main__":
    unittest.main()
