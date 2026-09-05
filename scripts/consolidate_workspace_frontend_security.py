from __future__ import annotations

import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "src/three_agent/workspace_frontend_security.py"
VARIANT = ROOT / "src/three_agent/workspace_frontend_security_v1.py"
SOURCES = ROOT / "src/workspace_local_ai.egg-info/SOURCES.txt"
HISTORY = ROOT / "docs/history_error.md"
TEST = ROOT / "tests/test_workspace_frontend_security_canonicalization.py"

VARIANT_MODULE = "workspace_frontend_security_v1"
CANONICAL_MODULE = "workspace_frontend_security"
HISTORY_MARKER = "workspace_frontend_security circular-version chain"


def _assignment_source(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            segment = ast.get_source_segment(source, node)
            if segment:
                return segment
    raise RuntimeError(f"missing canonical assignment: {name}")


def _v1_body(source: str) -> str:
    start_marker = "html = WORKSPACE_HTML"
    end_marker = "WORKSPACE_HTML = html"
    start = source.find(start_marker)
    end = source.find(end_marker)
    if start < 0 or end < 0 or end < start:
        raise RuntimeError("workspace_frontend_security_v1 shape is not recognized")
    return source[start : end + len(end_marker)].strip()


def _build_canonical(current: str, variant: str) -> str:
    required = {
        name: _assignment_source(current, name)
        for name in (
            "SOC_SECURITY_CSS",
            "SOC_SECURITY_MARKUP",
            "SOC_SECURITY_JS",
            "SECURITY_BOUNDARY_CSS",
            "SECURITY_BOUNDARY_MARKUP",
        )
    }
    parts = [
        "from __future__ import annotations",
        "",
        "from .workspace_frontend import _replace_once",
        "from .workspace_frontend import WORKSPACE_HTML",
        "",
        "",
        "# Canonical Security Analyst base overlay (formerly the physical V1 module).",
        _v1_body(variant),
        "",
        "",
        "# Later security overlays are version-independent builders.  They intentionally",
        "# avoid importing V15 during module import so V14 can consume V13 without a cycle.",
        required["SOC_SECURITY_CSS"],
        "",
        required["SOC_SECURITY_MARKUP"],
        "",
        required["SOC_SECURITY_JS"],
        "",
        required["SECURITY_BOUNDARY_CSS"],
        "",
        required["SECURITY_BOUNDARY_MARKUP"],
        "",
        "",
        "def build_security_v2(base_html: str) -> str:",
        "    html = base_html",
        "    html = _replace_once(html, \"</style>\", SOC_SECURITY_CSS + \"</style>\", \"security-soc-css\")",
        "    html = _replace_once(",
        "        html,",
        "        '        <button class=\"security-tab hidden\" data-security-tab=\"configuration\" id=\"securityConfigTab\" type=\"button\">Configuration</button>',",
        "        '        <button class=\"security-tab\" data-security-tab=\"soc\" id=\"securitySocTab\" type=\"button\">SOC</button>\\n        <button class=\"security-tab hidden\" data-security-tab=\"configuration\" id=\"securityConfigTab\" type=\"button\">Configuration</button>',",
        "        \"security-soc-tab\",",
        "    )",
        "    html = _replace_once(",
        "        html,",
        "        '      <div class=\"security-view\" data-security-view=\"configuration\" id=\"securityConfigView\">',",
        "        SOC_SECURITY_MARKUP + '      <div class=\"security-view\" data-security-view=\"configuration\" id=\"securityConfigView\">',",
        "        \"security-soc-view\",",
        "    )",
        "    html = _replace_once(html, \"</body>\", \"<script>\" + SOC_SECURITY_JS + \"</script>\\n</body>\", \"security-soc-js\")",
        "    return html",
        "",
        "",
        "def build_security_v3(base_html: str) -> str:",
        "    html = build_security_v2(base_html)",
        "    html = _replace_once(html, \"</style>\", SECURITY_BOUNDARY_CSS + \"</style>\", \"security-boundary-css\")",
        "    html = _replace_once(",
        "        html,",
        "        '        <button class=\"security-tab hidden\" data-security-tab=\"configuration\" id=\"securityConfigTab\" type=\"button\">Configuration</button>',",
        "        '        <button class=\"security-tab\" data-security-tab=\"boundaries\" id=\"securityBoundaryTab\" type=\"button\">Boundaries</button>\\n        <button class=\"security-tab hidden\" data-security-tab=\"configuration\" id=\"securityConfigTab\" type=\"button\">Configuration</button>',",
        "        \"security-boundary-tab\",",
        "    )",
        "    html = _replace_once(",
        "        html,",
        "        '      <div class=\"security-view\" data-security-view=\"configuration\" id=\"securityConfigView\">',",
        "        SECURITY_BOUNDARY_MARKUP + '      <div class=\"security-view\" data-security-view=\"configuration\" id=\"securityConfigView\">',",
        "        \"security-boundary-view\",",
        "    )",
        "    return html",
        "",
        "",
        "def _ensure_compatibility_html() -> None:",
        "    if \"WORKSPACE_HTML_SECURITY_V2\" in globals() and \"WORKSPACE_HTML_SECURITY_V3\" in globals():",
        "        return",
        "    from .workspace_frontend import WORKSPACE_HTML",
        "",
        "    globals()[\"WORKSPACE_HTML_SECURITY_V2\"] = build_security_v2(WORKSPACE_HTML)",
        "    globals()[\"WORKSPACE_HTML_SECURITY_V3\"] = build_security_v3(WORKSPACE_HTML)",
        "",
        "",
        "def __getattr__(name: str):",
        "    if name in {\"WORKSPACE_HTML_SECURITY_V2\", \"WORKSPACE_HTML_SECURITY_V3\"}:",
        "        _ensure_compatibility_html()",
        "        return globals()[name]",
        "    raise AttributeError(name)",
        "",
    ]
    return "\n".join(parts).rstrip() + "\n"


def _rewrite_references() -> list[str]:
    changed: list[str] = []
    extensions = {".py", ".toml", ".yml", ".yaml"}
    self_path = Path(__file__).resolve()
    variant_path = VARIANT.resolve()
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        if path.resolve() in {self_path, variant_path}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rewritten = text.replace(VARIANT_MODULE, CANONICAL_MODULE)
        if rewritten != text:
            path.write_text(rewritten, encoding="utf-8")
            changed.append(path.relative_to(ROOT).as_posix())
    if SOURCES.exists():
        text = SOURCES.read_text(encoding="utf-8")
        rewritten = text.replace("src/three_agent/workspace_frontend_security_v1.py\n", "")
        if rewritten != text:
            SOURCES.write_text(rewritten, encoding="utf-8")
            changed.append(SOURCES.relative_to(ROOT).as_posix())
    return changed


def _write_regression_test() -> None:
    TEST.write_text(
        '''from __future__ import annotations\n\nimport unittest\nfrom pathlib import Path\n\n\nclass CanonicalFrontendSecurityTest(unittest.TestCase):\n    def test_versioned_security_module_is_removed(self):\n        root = Path(__file__).resolve().parents[1]\n        self.assertFalse((root / "src/three_agent/workspace_frontend_security_v1.py").exists())\n\n    def test_frontend_security_chain_is_acyclic_and_preserves_overlays(self):\n        from three_agent.workspace_frontend_security import WORKSPACE_HTML\n        from three_agent.workspace_frontend import WORKSPACE_HTML\n        from three_agent.workspace_frontend import WORKSPACE_HTML\n        from three_agent.workspace_frontend_security import (\n            WORKSPACE_HTML_SECURITY_V2,\n            WORKSPACE_HTML_SECURITY_V3,\n        )\n\n        self.assertIn('id="securityAnalystSurface"', WORKSPACE_HTML)\n        self.assertIn('id="securityAnalystSurface"', WORKSPACE_HTML)\n        self.assertIn('id="securityConfigView"', WORKSPACE_HTML)\n        self.assertIn('id="securitySocView"', WORKSPACE_HTML_SECURITY_V2)\n        self.assertIn('id="securityConfigView"', WORKSPACE_HTML_SECURITY_V2)\n        self.assertIn('id="securityBoundaryView"', WORKSPACE_HTML_SECURITY_V3)\n        self.assertIn('id="securitySocView"', WORKSPACE_HTML_SECURITY_V3)\n\n\nif __name__ == "__main__":\n    unittest.main()\n''',
        encoding="utf-8",
    )


def _record_history() -> None:
    if not HISTORY.exists():
        return
    text = HISTORY.read_text(encoding="utf-8")
    if HISTORY_MARKER in text:
        return
    entry = f'''\n\n### 2026-09-04 — {HISTORY_MARKER}\n\n- Observed failure mode: `workspace_frontend.py` consumed `workspace_frontend_security_v1.py`, while the canonical security module consumed `workspace_frontend.py`. Repointing V14 directly to the old canonical implementation would therefore create a V14 → canonical-security → V15 → V14 circular import.\n- Root cause: security UI generations carried both frontend-version dependency and implementation authority instead of exposing version-independent canonical overlay builders.\n- Fix: move the V1 Security Analyst overlay into `workspace_frontend_security.py`, expose V2/V3 SOC and boundary behavior as canonical builder functions, lazily materialize compatibility HTML only after V15 is available, rewrite consumers to the canonical module, and remove the physical V1 module.\n- Regression protection: `tests/test_workspace_frontend_security_canonicalization.py` verifies the physical V1 module is absent, the V13→V15 chain imports without a cycle, and Security Analyst/configuration/SOC/boundary markers are preserved.\n'''
    HISTORY.write_text(text.rstrip() + entry, encoding="utf-8")


def consolidate(*, apply: bool) -> bool:
    if not VARIANT.exists():
        print("workspace_frontend_security already canonicalized")
        return False
    current = CANONICAL.read_text(encoding="utf-8")
    variant = VARIANT.read_text(encoding="utf-8")
    merged = _build_canonical(current, variant)
    if not apply:
        print("workspace_frontend_security semantic consolidation required")
        return True
    CANONICAL.write_text(merged, encoding="utf-8")
    rewritten = _rewrite_references()
    VARIANT.unlink()
    _write_regression_test()
    _record_history()
    print("workspace_frontend_security consolidated into canonical module")
    print(f"rewritten_references={len(rewritten)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Consolidate the legacy frontend security generation into the canonical module")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    consolidate(apply=args.apply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
