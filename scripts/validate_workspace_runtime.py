from __future__ import annotations

import importlib
import os
from pathlib import Path


REQUIRED_MODULES = (
    "three_agent",
    "three_agent.chat_gateway_v18",
    "three_agent.security_monitoring_cli",
    "three_agent.security_reporting_cli",
    "three_agent.security_pcap_runner",
)

REQUIRED_ENTRYPOINTS = (
    "workspace-chat",
    "workspace-security-monitor",
    "workspace-security-report",
    "workspace-security-pcap",
)


def validate_modules() -> None:
    for module_name in REQUIRED_MODULES:
        importlib.import_module(module_name)


def validate_entrypoints(venv: Path) -> None:
    # Console-script shebangs must point to the venv path exactly. Do not resolve
    # this path: on POSIX venv/bin/python is commonly a symlink to the system
    # interpreter, while pip intentionally writes the stable venv path.
    python_path = venv / "bin" / "python"
    if not python_path.is_file():
        raise RuntimeError("WORKSPACE_VENV_PYTHON_MISSING")

    expected_shebang = f"#!{python_path}"
    for command in REQUIRED_ENTRYPOINTS:
        path = venv / "bin" / command
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f"WORKSPACE_ENTRYPOINT_MISSING:{command}")
        first_line = path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        if first_line != expected_shebang:
            raise RuntimeError(f"WORKSPACE_ENTRYPOINT_BINDING_INVALID:{command}")


def main() -> int:
    root = Path(os.environ.get("THREE_AGENT_ROOT", Path.home() / "3agent")).resolve()
    venv = root / ".venv"
    validate_modules()
    validate_entrypoints(venv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
