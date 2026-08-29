import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.runtime_validation import RuntimeValidatorBridge
from three_agent.store import TaskStore


class RuntimeValidatorModeCompatibilityTests(unittest.TestCase):
    def _bridge(self, mode: str, *, public_web: bool = False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        store = TaskStore(root / "tasks.db")
        store.initialize()
        return RuntimeValidatorBridge(
            store,
            ArtifactManager(root / "data"),
            confidentiality_mode=mode,
            public_web=public_web,
        )

    def test_development_test_maps_to_internal_without_web_authority(self):
        bridge = self._bridge("development-test")
        self.assertEqual(bridge.sensitivity, "internal")
        self.assertFalse(bridge.public_web)

    def test_development_test_cannot_self_enable_public_web(self):
        with self.assertRaisesRegex(ValueError, "public_web runtime validation"):
            self._bridge("development-test", public_web=True)

    def test_unknown_mode_still_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported confidentiality_mode"):
            self._bridge("unexpected-mode")


if __name__ == "__main__":
    unittest.main()
