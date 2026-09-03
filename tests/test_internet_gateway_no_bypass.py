from __future__ import annotations

import ast
import unittest
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "three_agent"
PROTECTED_TOP_LEVEL = {"agents", "plugins", "connectors", "browser", "tools"}
PROTECTED_FILES = {
    "knowledge_gateway.py",
    "privacy.py",
    "public_query_compiler.py",
    "task_contract.py",
    "web_research.py",
}
FORBIDDEN_NETWORK_MODULES = {
    "aiohttp",
    "ftplib",
    "http.client",
    "httpx",
    "requests",
    "smtplib",
    "socket",
    "urllib.request",
    "urllib3",
    "websocket",
    "websockets",
}
NETWORK_CLI = {"curl", "ftp", "nc", "netcat", "scp", "sftp", "ssh", "telnet", "wget"}


def _protected(path: Path) -> bool:
    relative = path.relative_to(SRC_ROOT)
    if relative.name in PROTECTED_FILES:
        return True
    return bool(relative.parts and relative.parts[0] in PROTECTED_TOP_LEVEL)


def _import_root(name: str) -> str:
    parts = name.split(".")
    if len(parts) >= 2 and ".".join(parts[:2]) in FORBIDDEN_NETWORK_MODULES:
        return ".".join(parts[:2])
    return parts[0]


def _literal_command(node: ast.Call) -> str | None:
    if not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value.strip().split(" ", 1)[0].rsplit("/", 1)[-1].casefold()
    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
        head = first.elts[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            return head.value.strip().rsplit("/", 1)[-1].casefold()
    return None


class InternetGatewayNoBypassTests(unittest.TestCase):
    def test_agents_tools_plugins_connectors_and_research_stack_have_no_direct_network_primitives(self) -> None:
        violations: list[str] = []
        scanned = 0
        for path in sorted(SRC_ROOT.rglob("*.py")):
            if not _protected(path):
                continue
            scanned += 1
            relative = path.relative_to(SRC_ROOT).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module = _import_root(alias.name)
                        if module in FORBIDDEN_NETWORK_MODULES:
                            violations.append(f"{relative}:{node.lineno}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    module = _import_root(node.module)
                    if module in FORBIDDEN_NETWORK_MODULES:
                        violations.append(f"{relative}:{node.lineno}: from {node.module} import ...")
                elif isinstance(node, ast.Call):
                    command = _literal_command(node)
                    if command in NETWORK_CLI:
                        violations.append(f"{relative}:{node.lineno}: network CLI {command}")

        self.assertGreater(scanned, 0, "security scan unexpectedly covered zero protected modules")
        self.assertEqual(
            violations,
            [],
            "Public-capable agents/tools/plugins/connectors must use InternetGateway; "
            "direct network primitives are forbidden:\n" + "\n".join(violations),
        )

    def test_network_authority_is_confined_to_explicit_gateway_modules(self) -> None:
        gateway = (SRC_ROOT / "gateways.py").read_text(encoding="utf-8")
        broker = (SRC_ROOT / "egress_broker.py").read_text(encoding="utf-8")
        web = (SRC_ROOT / "web_research.py").read_text(encoding="utf-8")

        self.assertIn("class InternetGateway", gateway)
        self.assertIn("InternetGateway", broker)
        self.assertIn("InternetGateway", web)
        self.assertNotIn("urllib.request", web)
        self.assertNotIn("requests.", web)
        self.assertNotIn("httpx.", web)


if __name__ == "__main__":
    unittest.main()
