#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "src" / "three_agent" / "chat_gateway.py"
TARGET_NAME = "HTML_V17"
BASE_HTML_NAME = "WORKSPACE_HTML"
SECURITY_HTML_NAME = "WORKSPACE_HTML_SECURITY_V3"


def _binding_assignments(tree: ast.Module) -> list[ast.Assign]:
    assignments: list[ast.Assign] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == TARGET_NAME
            for target in node.targets
        ):
            assignments.append(node)
    return assignments


def repair_source(source: str) -> tuple[str, bool]:
    tree = ast.parse(source)
    imported_security_html = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "workspace_frontend_security"
        and any(alias.name == SECURITY_HTML_NAME for alias in node.names)
        for node in tree.body
    )
    if not imported_security_html:
        raise RuntimeError(
            "canonical chat gateway must import WORKSPACE_HTML_SECURITY_V3 "
            "from workspace_frontend_security"
        )

    assignments = _binding_assignments(tree)
    if not assignments:
        raise RuntimeError("canonical chat gateway has no HTML_V17 binding")

    final = assignments[-1]
    if not isinstance(final.value, ast.Name):
        raise RuntimeError("final HTML_V17 binding must be a direct canonical name")

    if final.value.id == SECURITY_HTML_NAME:
        return source, False
    if final.value.id != BASE_HTML_NAME:
        raise RuntimeError(
            f"unexpected final HTML_V17 binding: {ast.unparse(final.value)}"
        )
    if final.lineno != final.end_lineno:
        raise RuntimeError("final HTML_V17 binding must remain a single-line assignment")

    lines = source.splitlines(keepends=True)
    newline = "\r\n" if lines[final.lineno - 1].endswith("\r\n") else "\n"
    lines[final.lineno - 1] = f"{TARGET_NAME} = {SECURITY_HTML_NAME}{newline}"
    repaired = "".join(lines)

    repaired_tree = ast.parse(repaired)
    rebound = _binding_assignments(repaired_tree)[-1]
    if not (
        isinstance(rebound.value, ast.Name)
        and rebound.value.id == SECURITY_HTML_NAME
    ):
        raise RuntimeError("canonical security UI binding repair did not persist")
    return repaired, True


def apply() -> dict[str, object]:
    source = CANONICAL.read_text(encoding="utf-8")
    repaired, changed = repair_source(source)
    if changed:
        CANONICAL.write_text(repaired, encoding="utf-8")
    return {
        "status": "repaired" if changed else "noop",
        "binding": f"{TARGET_NAME}={SECURITY_HTML_NAME}",
        "path": str(CANONICAL.relative_to(ROOT)),
    }


def main() -> int:
    print(apply())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
