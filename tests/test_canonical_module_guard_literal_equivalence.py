from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "canonical_module_guard.py"
SPEC = importlib.util.spec_from_file_location("canonical_module_guard_literal_equivalence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)


class CanonicalModuleGuardLiteralEquivalenceTests(unittest.TestCase):
    def _write(self, root: Path, relative: str, text: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_behavior_bearing_literals_prevent_false_equivalence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "src/pkg/view.py", 'HTML = "canonical UI"\n')
            self._write(root, "src/pkg/view_v2.py", 'HTML = "different UI behavior"\n')

            report = GUARD.scan(root)
            finding = next(
                item
                for item in report["findings"]
                if item["kind"] == "implementation_generation_file"
            )

            self.assertEqual(finding["canonical_target"], "src/pkg/view.py")
            self.assertEqual(finding["missing_from_canonical"], ())
            self.assertEqual(finding["action"], "compare_behavior_then_merge_or_delete")


if __name__ == "__main__":
    unittest.main()
