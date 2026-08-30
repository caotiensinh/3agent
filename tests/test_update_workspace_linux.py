from __future__ import annotations

import subprocess
from pathlib import Path


SCRIPT = Path("scripts/update_workspace_linux.sh")


def test_linux_update_script_has_valid_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_linux_update_is_application_only_and_runner_safe() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "git merge --ff-only" in text
    assert 'python" -m pip install -e .' in text
    assert "systemctl --user restart \"$CHAT_SERVICE\"" in text
    assert "nvidia-smi --query-gpu=name,uuid" in text
    assert "actions.runner.*" in text
    assert "apt install" not in text
    assert "apt-get" not in text
    assert "nvidia-driver" not in text
    assert "update-grub" not in text
    assert "reboot" not in text
    assert "restart actions.runner" not in text
    assert "stop actions.runner" not in text
