#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PKG = SRC / "three_agent"
CANONICAL = PKG / "workspace_frontend.py"
TEST_FILE = ROOT / "tests" / "test_workspace_frontend_canonicalization.py"
FINAL_MODULE = "three_agent.workspace_frontend_v18"
FINAL_SYMBOL = "WORKSPACE_HTML_V18"
VERSION_MODULE_RE = re.compile(r"(?:three_agent\.)?workspace_frontend_v\d+(?:_part\d+)?$")
VERSION_REF_RE = re.compile(r"workspace_frontend_v\d+(?:_part\d+)?")
VERSION_FILE_RE = re.compile(r"workspace_frontend_v\d+(?:_part\d+)?\.py")
VERSION_HTML_RE = re.compile(r"WORKSPACE_HTML_V\d+")
PRESERVED_SYMBOLS = {"_replace_once", "_insert_after_workflow_description", "config_js", "config_markup", "html"}


def _variant_files() -> list[Path]:
    return sorted(PKG.glob("workspace_frontend_v*.py"), key=lambda p: p.name)


def _external_python_files(variants: set[Path]) -> list[Path]:
    paths: list[Path] = []
    for base in (SRC, ROOT / "tests", ROOT / "scripts"):
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            resolved = path.resolve()
            if resolved in variants or resolved == Path(__file__).resolve():
                continue
            paths.append(path)
    return sorted(paths)


def _validate_import_contract(paths: list[Path]) -> None:
    violations: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if "workspace_frontend_v" not in text:
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            raise RuntimeError(f"cannot parse {path}: {exc}") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if VERSION_MODULE_RE.search(module):
                    for alias in node.names:
                        name = alias.name
                        if name in PRESERVED_SYMBOLS or VERSION_HTML_RE.fullmatch(name):
                            continue
                        violations.append(f"{path}: unsupported import {module}.{name}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if VERSION_MODULE_RE.search(alias.name):
                        violations.append(
                            f"{path}: module-style import {alias.name} requires manual semantic review"
                        )
    if violations:
        raise RuntimeError("unsafe workspace frontend imports:\n" + "\n".join(violations))


def _load_authority() -> tuple[str, str, str]:
    """Resolve current V18 exactly without restoring deleted security generation files.

    V16 historically imports workspace_frontend_security_v3. That physical module was
    already consolidated. Build its exact expected HTML from the canonical security
    builder and expose it only as an in-memory module while evaluating the historical
    frontend chain. Nothing versioned is written back to production source.
    """

    shim_name = "three_agent.workspace_frontend_security_v3"
    sys.path.insert(0, str(SRC))
    previous_shim = sys.modules.get(shim_name)
    try:
        v15 = importlib.import_module("three_agent.workspace_frontend_v15")
        security = importlib.import_module("three_agent.workspace_frontend_security")
        shim = types.ModuleType(shim_name)
        shim.WORKSPACE_HTML_SECURITY_V3 = security.build_security_v3(v15.WORKSPACE_HTML_V15)
        sys.modules[shim_name] = shim

        final_module = importlib.import_module(FINAL_MODULE)
        html = getattr(final_module, FINAL_SYMBOL)
        config_markup = getattr(v15, "config_markup")
        config_js = getattr(v15, "config_js")
    finally:
        if previous_shim is None:
            sys.modules.pop(shim_name, None)
        else:
            sys.modules[shim_name] = previous_shim
        try:
            sys.path.remove(str(SRC))
        except ValueError:
            pass
    for label, value in (("final HTML", html), ("config markup", config_markup), ("config JS", config_js)):
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"workspace frontend {label} did not resolve to a non-empty string")
    return html, config_markup, config_js


def _literal(value: str) -> str:
    lines = value.splitlines(keepends=True)
    if not lines:
        return "''"
    return "(\n" + "\n".join(f"    {line!r}" for line in lines) + "\n)"


def _canonical_source(html: str, config_markup: str, config_js: str) -> str:
    return (
        "from __future__ import annotations\n\n"
        "\n"
        "def _replace_once(source: str, old: str, new: str, label: str) -> str:\n"
        "    count = source.count(old)\n"
        "    if count != 1:\n"
        "        raise RuntimeError(\n"
        "            f\"WorkSpace frontend canonical patch '{label}' expected exactly one match, got {count}\"\n"
        "        )\n"
        "    return source.replace(old, new, 1)\n\n\n"
        "def _insert_after_workflow_description(document: str, markup: str) -> str:\n"
        "    \"\"\"Insert workflow-draft markup after the stable workflowDescription textarea.\"\"\"\n"
        "    token = 'id=\"workflowDescription\"'\n"
        "    count = document.count(token)\n"
        "    if count != 1:\n"
        "        raise RuntimeError(\n"
        "            \"workflow-draft-library-markup: expected exactly one workflowDescription id, \"\n"
        "            f\"found {count}\"\n"
        "        )\n"
        "    token_at = document.index(token)\n"
        "    open_at = document.rfind(\"<textarea\", 0, token_at + 1)\n"
        "    close_at = document.find(\"</textarea>\", token_at)\n"
        "    if open_at < 0 or close_at < 0 or open_at > token_at:\n"
        "        raise RuntimeError(\n"
        "            \"workflow-draft-library-markup: workflowDescription must remain a textarea\"\n"
        "        )\n"
        "    insert_at = close_at + len(\"</textarea>\")\n"
        "    return document[:insert_at] + \"\\n\" + markup + document[insert_at:]\n\n\n"
        "config_markup = "
        + _literal(config_markup)
        + "\n\n"
        "config_js = "
        + _literal(config_js)
        + "\n\n"
        "WORKSPACE_HTML = "
        + _literal(html)
        + "\n\n"
        "# Compatibility for code that treats the rendered document as a working value.\n"
        "html = WORKSPACE_HTML\n"
    )


def _rewrite_references(paths: list[Path]) -> list[Path]:
    changed: list[Path] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        updated = VERSION_REF_RE.sub("workspace_frontend", text)
        updated = VERSION_FILE_RE.sub("workspace_frontend.py", updated)
        updated = VERSION_HTML_RE.sub("WORKSPACE_HTML", updated)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed.append(path)
    return changed


def _test_source(expected_sha256: str) -> str:
    return f'''from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

from three_agent.workspace_frontend import WORKSPACE_HTML, _insert_after_workflow_description, config_js, config_markup

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SHA256 = "{expected_sha256}"


class WorkspaceFrontendCanonicalizationTests(unittest.TestCase):
    def test_rendered_frontend_is_byte_equivalent_to_preconsolidation_v18(self) -> None:
        actual = hashlib.sha256(WORKSPACE_HTML.encode("utf-8")).hexdigest()
        self.assertEqual(actual, EXPECTED_SHA256)

    def test_preserved_composition_contract_symbols_are_available(self) -> None:
        self.assertIn("securityConfigView", config_markup)
        self.assertIn("secCfgStatus", config_js)
        sample = '<textarea id="workflowDescription"></textarea><div>tail</div>'
        rendered = _insert_after_workflow_description(sample, '<div id="draft">draft</div>')
        self.assertIn('</textarea>\\n<div id="draft">draft</div><div>tail</div>', rendered)

    def test_no_physical_frontend_generation_modules_remain(self) -> None:
        package = ROOT / "src" / "three_agent"
        self.assertEqual(list(package.glob("workspace_frontend_v*.py")), [])

    def test_runtime_code_has_no_stale_frontend_generation_references(self) -> None:
        pattern = re.compile("workspace_frontend_" + r"v\\d")
        stale = []
        migration = (ROOT / "scripts" / "consolidate_workspace_frontend.py").resolve()
        for base in (ROOT / "src", ROOT / "tests", ROOT / "scripts"):
            for path in base.rglob("*.py"):
                if path.resolve() == migration:
                    continue
                text = path.read_text(encoding="utf-8")
                if pattern.search(text):
                    stale.append(str(path.relative_to(ROOT)))
        self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
'''


def apply() -> dict[str, object]:
    variants = _variant_files()
    if not variants:
        return {"status": "noop", "reason": "no workspace frontend variants remain"}
    final_variant = PKG / "workspace_frontend_v18.py"
    if final_variant not in variants:
        raise RuntimeError("workspace_frontend_v18.py is required as the current final behavior authority")

    variant_set = {path.resolve() for path in variants}
    external = _external_python_files(variant_set)
    _validate_import_contract(external)

    final_html, config_markup, config_js = _load_authority()
    digest = hashlib.sha256(final_html.encode("utf-8")).hexdigest()

    CANONICAL.write_text(_canonical_source(final_html, config_markup, config_js), encoding="utf-8")
    changed_refs = _rewrite_references(external)
    TEST_FILE.write_text(_test_source(digest), encoding="utf-8")

    for path in variants:
        path.unlink()

    stale = []
    for path in _external_python_files(set()):
        if path.resolve() == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8")
        if VERSION_REF_RE.search(text):
            stale.append(str(path.relative_to(ROOT)))
    if stale:
        raise RuntimeError("stale workspace frontend generation references remain: " + ", ".join(stale))

    return {
        "status": "applied",
        "final_html_sha256": digest,
        "removed_variants": len(variants),
        "rewritten_files": [str(path.relative_to(ROOT)) for path in changed_refs],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Consolidate WorkSpace frontend generations into one canonical module")
    parser.add_argument("--apply", action="store_true", help="apply the canonicalization")
    args = parser.parse_args()
    if not args.apply:
        print({"status": "ready", "variants": [p.name for p in _variant_files()]})
        return 0
    print(apply())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
