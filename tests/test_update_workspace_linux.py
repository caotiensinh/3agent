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

    def test_updater_is_ubuntu_dual_gpu_application_only(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('WORKSPACE_EXPECTED_GPU_COUNT:-2', text)
        self.assertIn('VERSION_ID:-}" == "24.04"', text)
        self.assertIn("nvidia-smi --query-gpu=name,driver_version", text)
        self.assertNotIn("name,uuid", text)
        self.assertIn('OLLAMA_URL="${WORKSPACE_OLLAMA_URL:-http://127.0.0.1:11434}"', text)
        self.assertIn('"$OLLAMA_URL/api/tags"', text)
        self.assertNotIn("apt install", text)
        self.assertNotIn("apt-get", text)
        self.assertNotIn("nvidia-driver", text)
        self.assertNotIn("update-grub", text)
        self.assertNotIn("reboot", text)
        self.assertNotIn("ollama pull", text)
        self.assertNotIn("docker ", text.lower())

    def test_updater_resolves_exact_trusted_fast_forward_target(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("https://github.com/caotiensinh/3agent.git", text)
        self.assertIn('git fetch --no-tags --prune origin "$TARGET_REF"', text)
        self.assertIn('TARGET_SHA_OVERRIDE="${WORKSPACE_TARGET_SHA:-}"', text)
        self.assertIn("^[0-9a-f]{40}$", text)
        self.assertIn('git merge-base --is-ancestor "$BEFORE_SHA" "$TARGET_SHA"', text)
        self.assertIn('git merge --ff-only "$TARGET_SHA"', text)
        self.assertIn('"$(git rev-parse HEAD)" == "$TARGET_SHA"', text)
        self.assertIn("Refusing untrusted origin", text)
        self.assertIn("Tracked WorkSpace files are modified", text)

    def test_dependency_change_detection_uses_dependency_contract_not_whole_pyproject(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("dependency_contract_sha()", text)
        self.assertIn("tomllib", text)
        self.assertIn('"requires-python"', text)
        self.assertIn('"dependencies"', text)
        self.assertIn('"build_requires"', text)
        self.assertIn('"build_backend"', text)
        self.assertIn('[[ "$CURRENT_DEP_SHA" == "$TARGET_DEP_SHA" ]] || DEPS_CHANGED=1', text)
        self.assertIn('[[ "$CURRENT_PYPROJECT_SHA" == "$TARGET_PYPROJECT_SHA" ]] || PYPROJECT_CHANGED=1', text)
        self.assertNotIn(
            'if [[ "$CURRENT_PYPROJECT_SHA" != "$TARGET_PYPROJECT_SHA" ]]; then\n  DEPS_CHANGED=1',
            text,
        )

    def test_updater_reuses_git_objects_and_existing_venv_when_possible(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('git worktree add --detach "$STAGE_ROOT" "$TARGET_SHA"', text)
        self.assertNotIn("git clone", text)
        self.assertIn("Dependency and package contracts unchanged: reusing existing .venv", text)
        self.assertIn('PYTHONPATH="$STAGE_ROOT/src" "$ROOT/.venv/bin/python"', text)
        self.assertIn('python3 -m venv "$NEXT_VENV"', text)
        self.assertIn('cp -a --reflink=auto "$ROOT/.venv" "$NEXT_VENV"', text)
        self.assertIn('"$ROOT/.venv/bin/python" -m pip install --no-deps --force-reinstall -e "$ROOT"', text)

    def test_replacement_venv_is_rebound_only_after_final_path_swap(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        swap = text.index('mv "$NEXT_VENV" "$ROOT/.venv"')
        rebind = text.index(
            '"$ROOT/.venv/bin/python" -m pip install --no-deps --force-reinstall -e "$ROOT"'
        )
        entrypoint_check = text.index(
            '[[ "$first_line" == "#!$ROOT/.venv/bin/python" ]]'
        )
        self.assertLess(swap, rebind)
        self.assertLess(rebind, entrypoint_check)
        self.assertNotIn(
            '"$NEXT_VENV/bin/python" -m pip install --no-deps -e "$ROOT"',
            text,
        )
        self.assertNotIn(
            'UPDATE_STAGE="existing_venv_rebind"',
            text,
        )

    def test_update_is_transactional_and_records_failure_stage(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("flock -n 9", text)
        self.assertIn("rollback()", text)
        self.assertIn('git reset --hard "$BEFORE_SHA"', text)
        self.assertIn('mv "$OLD_VENV" "$ROOT/.venv"', text)
        self.assertIn('systemctl --user restart "$CHAT_SERVICE"', text)
        self.assertIn("VENV_SWAPPED=1", text)
        self.assertIn("COMMITTED=1", text)
        self.assertIn("workspace-linux-update/v3", text)
        self.assertIn('"failure_stage": sys.argv[11] or None', text)
        self.assertIn('failed_stage="$UPDATE_STAGE"', text)
        self.assertIn('"driver_or_kernel_mutated": False', text)
        self.assertIn('"runner_service_mutated": False', text)

    def test_runner_and_existing_service_topology_are_preserved(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("actions.runner.*", text)
        self.assertIn('"$RUNNERS_AFTER" == "$RUNNERS_BEFORE"', text)
        self.assertIn("CHAT_WAS_ACTIVE", text)
        self.assertIn("preserving inactive state", text)
        self.assertNotIn("restart actions.runner", text)
        self.assertNotIn("stop actions.runner", text)
        self.assertNotIn("enable actions.runner", text)


if __name__ == "__main__":
    unittest.main()
