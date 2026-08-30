from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


SCRIPT = Path("scripts/update_workspace_linux.sh")


class LinuxUpdateContractTests(unittest.TestCase):
    @unittest.skipIf(
        os.name == "nt",
        "Linux updater bash syntax is exercised by Linux harness/portable-deploy lanes",
    )
    def test_linux_update_script_has_valid_bash_syntax(self) -> None:
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_linux_update_is_application_only_and_runner_safe(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("git merge --ff-only", text)
        self.assertIn('python" -m pip install -e .', text)
        self.assertIn('systemctl --user restart "$CHAT_SERVICE"', text)
        self.assertIn("nvidia-smi --query-gpu=name,uuid", text)
        self.assertIn("actions.runner.*", text)
        self.assertNotIn("apt install", text)
        self.assertNotIn("apt-get", text)
        self.assertNotIn("nvidia-driver", text)
        self.assertNotIn("update-grub", text)
        self.assertNotIn("reboot", text)
        self.assertNotIn("restart actions.runner", text)
        self.assertNotIn("stop actions.runner", text)


if __name__ == "__main__":
    unittest.main()
