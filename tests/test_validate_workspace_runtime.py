from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import validate_workspace_runtime as validator


class WorkspaceRuntimeValidatorTests(unittest.TestCase):
    def test_required_runtime_modules_include_security_and_multimodal_surface(self) -> None:
        self.assertIn("three_agent.chat_gateway", validator.REQUIRED_MODULES)
        self.assertIn("three_agent.knowledge_gateway", validator.REQUIRED_MODULES)
        self.assertIn("three_agent.vision", validator.REQUIRED_MODULES)
        self.assertIn("three_agent.security_monitoring_cli", validator.REQUIRED_MODULES)
        self.assertIn("three_agent.security_reporting_cli", validator.REQUIRED_MODULES)
        self.assertIn("three_agent.security_pcap_runner", validator.REQUIRED_MODULES)

    def test_required_entrypoints_include_security_commands(self) -> None:
        self.assertEqual(
            validator.REQUIRED_ENTRYPOINTS,
            (
                "workspace-chat",
                "workspace-security-monitor",
                "workspace-security-report",
                "workspace-security-pcap",
            ),
        )

    def test_module_validation_imports_every_required_module(self) -> None:
        seen: list[str] = []
        with patch.object(validator.importlib, "import_module", side_effect=lambda name: seen.append(name)):
            validator.validate_modules()
        self.assertEqual(tuple(seen), validator.REQUIRED_MODULES)

    def test_entrypoint_validation_requires_exact_venv_python_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            venv = Path(tmp) / ".venv"
            bin_dir = venv / "bin"
            bin_dir.mkdir(parents=True)
            python = bin_dir / "python"
            python.write_text("", encoding="utf-8")
            python.chmod(0o700)
            expected = f"#!{python}\n"
            for command in validator.REQUIRED_ENTRYPOINTS:
                path = bin_dir / command
                path.write_text(expected + "pass\n", encoding="utf-8")
                path.chmod(0o700)
            validator.validate_entrypoints(venv)

            broken = bin_dir / "workspace-security-report"
            broken.write_text("#!/usr/bin/python3\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "WORKSPACE_ENTRYPOINT_BINDING_INVALID"):
                validator.validate_entrypoints(venv)

    @unittest.skipUnless(os.name == "posix", "venv Python symlink contract is POSIX-specific")
    def test_entrypoint_validation_preserves_venv_symlink_path_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv = root / ".venv"
            bin_dir = venv / "bin"
            bin_dir.mkdir(parents=True)
            system_python = root / "system-python"
            system_python.write_text("", encoding="utf-8")
            system_python.chmod(0o700)
            python = bin_dir / "python"
            python.symlink_to(system_python)

            expected = f"#!{python}\n"
            self.assertNotEqual(str(python), str(python.resolve()))
            for command in validator.REQUIRED_ENTRYPOINTS:
                path = bin_dir / command
                path.write_text(expected + "pass\n", encoding="utf-8")
                path.chmod(0o700)

            validator.validate_entrypoints(venv)


if __name__ == "__main__":
    unittest.main()
