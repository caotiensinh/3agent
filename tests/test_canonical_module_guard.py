from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "canonical_module_guard.py"
SPEC = importlib.util.spec_from_file_location("canonical_module_guard", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)


class CanonicalModuleGuardTests(unittest.TestCase):
    def _write(self, root: Path, relative: str, text: str) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_version_family_points_to_existing_canonical_module(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "src/pkg/cache.py", "class Cache:\n    def get(self): return 1\n")
            self._write(
                root,
                "src/pkg/cache_v2.py",
                "class CacheV2:\n    def get(self): return 2\n    def put(self): return 3\n",
            )
            report = GUARD.scan(root)
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["version_family_count"], 1)
            finding = next(
                item
                for item in report["findings"]
                if item["kind"] == "implementation_generation_file"
            )
            self.assertEqual(finding["canonical_target"], "src/pkg/cache.py")
            self.assertEqual(finding["action"], "semantic_merge_required")

    def test_same_api_different_behavior_requires_comparison(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(
                root,
                "src/pkg/cache.py",
                "class Cache:\n    def get(self): return 'canonical'\n",
            )
            self._write(
                root,
                "src/pkg/cache_v2.py",
                "class Cache:\n    def get(self):\n        value = 'variant'\n        return value\n",
            )
            report = GUARD.scan(root)
            finding = next(
                item
                for item in report["findings"]
                if item["kind"] == "implementation_generation_file"
            )
            self.assertEqual(finding["missing_from_canonical"], ())
            self.assertEqual(finding["action"], "compare_behavior_then_merge_or_delete")

    def test_safe_reexport_is_removed_and_references_are_rewritten(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "src/pkg/gateway.py", "class Gateway:\n    pass\n")
            self._write(
                root,
                "src/pkg/gateway_v2.py",
                "from .gateway import Gateway\n\n__all__ = ['Gateway']\n",
            )
            self._write(root, "tests/test_use.py", "from pkg.gateway_v2 import Gateway\n")

            result = GUARD.fix_safe(root, GUARD.scan(root))
            after = GUARD.scan(root)

            self.assertEqual(result["count"], 1)
            self.assertFalse((root / "src/pkg/gateway_v2.py").exists())
            self.assertIn(
                "pkg.gateway import",
                (root / "tests/test_use.py").read_text(encoding="utf-8"),
            )
            self.assertEqual(after["status"], "PASS")

    def test_functional_duplicate_with_different_filename_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(
                root,
                "src/pkg/cache_store.py",
                "class Store:\n"
                "    def get(self, key): return key\n"
                "    def put(self, key, value): return value\n"
                "    def delete(self, key): return key\n",
            )
            self._write(
                root,
                "src/pkg/state_store.py",
                "class StoreV2:\n"
                "    def get(self, key): return key\n"
                "    def put(self, key, value): return value\n"
                "    def delete(self, key): return key\n",
            )
            report = GUARD.scan(root)
            self.assertTrue(
                any(item["kind"] == "functional_duplicate" for item in report["findings"])
            )

    def test_unrelated_modules_are_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "src/pkg/cache.py", "class Cache:\n    def get(self): return 1\n")
            self._write(root, "src/pkg/router.py", "def route(value):\n    return value\n")
            self.assertEqual(GUARD.scan(root)["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
