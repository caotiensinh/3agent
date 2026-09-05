from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


class PackagingCheckoutHygieneTests(unittest.TestCase):
    def test_generated_egg_info_is_not_tracked(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        if not (repo_root / ".git").is_dir():
            self.skipTest("Git metadata is unavailable")
        result = subprocess.run(
            ["git", "ls-files", "--", "src/workspace_local_ai.egg-info"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
