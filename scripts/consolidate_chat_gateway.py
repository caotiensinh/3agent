#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PKG = SRC / "three_agent"
CANONICAL = PKG / "chat_gateway.py"
TEST_FILE = ROOT / "tests" / "test_chat_gateway_canonicalization.py"
PYPROJECT = ROOT / "pyproject.toml"
CHAIN_RE = re.compile(r"chat_gateway(?:_v\d+)?$")
VARIANT_RE = re.compile(r"chat_gateway_v(\d+)\.py$")
MODULE_REF_RE = re.compile(r"(?:three_agent\.)?chat_gateway_v\d+")
FRONTEND_SECURITY_REF_RE = re.compile(r"(?:three_agent\.)?workspace_frontend_security_v\d+")
IDENTITY_REWRITES = (
    (re.compile(r"three_agent\.chat_gateway_v\d+"), "three_agent.chat_gateway"),
    (re.compile(r"chat_gateway_v\d+\.py"), "chat_gateway.py"),
    (re.compile(r"chat_gateway_v\d+"), "chat_gateway"),
    (re.compile(r"three_agent\.workspace_frontend_security_v\d+"), "three_agent.workspace_frontend_security"),
    (re.compile(r"workspace_frontend_security_v\d+\.py"), "workspace_frontend_security.py"),
    (re.compile(r"workspace_frontend_security_v\d+"), "workspace_frontend_security"),
)


def _canonicalize_identity(value: str) -> str:
    updated = value
    for pattern, replacement in IDENTITY_REWRITES:
        updated = pattern.sub(replacement, updated)
    return updated


def _variants() -> list[Path]:
    def key(path: Path) -> int:
        match = VARIANT_RE.fullmatch(path.name)
        if not match:
            raise RuntimeError(f"unexpected chat gateway variant name: {path.name}")
        return int(match.group(1))

    return sorted(PKG.glob("chat_gateway_v*.py"), key=key)


def _is_chain_module(module: str | None) -> bool:
    return bool(module and CHAIN_RE.fullmatch(module))


def _collect_chain_imports(tree: ast.Module) -> tuple[set[str], dict[str, str]]:
    module_aliases: set[str] = set()
    symbol_aliases: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.level != 1:
            continue
        if node.module is None:
            for alias in node.names:
                if _is_chain_module(alias.name):
                    module_aliases.add(alias.asname or alias.name)
        elif _is_chain_module(node.module):
            for alias in node.names:
                bound = alias.asname or alias.name
                if bound != alias.name:
                    symbol_aliases[bound] = alias.name
    return module_aliases, symbol_aliases


def _cross_version_patch(node: ast.stmt, module_aliases: set[str]) -> bool:
    targets: list[ast.expr] = []
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        else:
            targets = [node.target]
    for target in targets:
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in module_aliases
        ):
            return True
    return False


class _ChainReferenceTransformer(ast.NodeTransformer):
    def __init__(self, module_aliases: set[str], symbol_aliases: dict[str, str]) -> None:
        self.module_aliases = module_aliases
        self.symbol_aliases = symbol_aliases

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.level == 1 and _is_chain_module(node.module):
            return None
        if node.level == 1 and node.module is None:
            kept = [alias for alias in node.names if not _is_chain_module(alias.name)]
            if not kept:
                return None
            node.names = kept
            return node
        return node

    def visit_Attribute(self, node: ast.Attribute):
        node = self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id in self.module_aliases:
            return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
        return node

    def visit_Name(self, node: ast.Name):
        replacement = self.symbol_aliases.get(node.id)
        if replacement:
            return ast.copy_location(ast.Name(id=replacement, ctx=node.ctx), node)
        return node

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            updated = _canonicalize_identity(node.value)
            if updated != node.value:
                return ast.copy_location(ast.Constant(value=updated), node)
        return node


def _is_dunder_main(node: ast.stmt) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
    )


def _transform_module(path: Path, *, keep_main: bool = False) -> list[ast.stmt]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module_aliases, symbol_aliases = _collect_chain_imports(tree)
    transformer = _ChainReferenceTransformer(module_aliases, symbol_aliases)
    output: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        if _is_dunder_main(node):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main" and not keep_main:
            continue
        if _cross_version_patch(node, module_aliases):
            continue
        transformed = transformer.visit(node)
        if transformed is None:
            continue
        if isinstance(transformed, list):
            output.extend(transformed)
        else:
            output.append(transformed)

    probe = ast.Module(body=output, type_ignores=[])
    unresolved = sorted(
        {
            item.id
            for item in ast.walk(probe)
            if isinstance(item, ast.Name) and item.id in module_aliases
        }
    )
    if unresolved:
        raise RuntimeError(
            f"{path.name}: unresolved cross-version module aliases after flatten: {', '.join(unresolved)}"
        )
    return output


def _public_definitions(paths: list[Path]) -> list[str]:
    names: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name != "main" and not node.name.startswith("_"):
                    names.add(node.name)
    return sorted(names)


def _base_name(expr: ast.expr, module_aliases: set[str], symbol_aliases: dict[str, str]) -> str | None:
    transformer = _ChainReferenceTransformer(module_aliases, symbol_aliases)
    transformed = transformer.visit(ast.fix_missing_locations(ast.parse(ast.unparse(expr), mode="eval").body))
    if isinstance(transformed, ast.Name):
        return transformed.id
    if isinstance(transformed, ast.Attribute):
        return ast.unparse(transformed)
    return None


def _class_graph(paths: list[Path]) -> dict[str, list[str]]:
    graph: dict[str, list[str]] = {}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module_aliases, symbol_aliases = _collect_chain_imports(tree)
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases: list[str] = []
            for base in node.bases:
                name = _base_name(base, module_aliases, symbol_aliases)
                if name:
                    bases.append(name)
            graph[node.name] = bases
    return graph


def _inheritance_chain(paths: list[Path], root: str) -> list[str]:
    graph = _class_graph(paths)
    if root not in graph:
        raise RuntimeError(f"missing final chat service class: {root}")
    chain = [root]
    seen = {root}
    current = root
    while current in graph and graph[current]:
        bases = graph[current]
        if len(bases) != 1:
            raise RuntimeError(
                f"{current}: expected one semantic base for deterministic flatten, got {bases}"
            )
        parent = bases[0]
        chain.append(parent)
        if parent in seen:
            raise RuntimeError(f"inheritance cycle detected at {parent}")
        seen.add(parent)
        if parent not in graph:
            break
        current = parent
    return chain


class _FinalMainBindingTransformer(ast.NodeTransformer):
    RENAME = {
        "ContractAwareProjectChatService": "ContinuitySecurityAwareProjectChatService",
        "WorkflowV4ContextApplication": "SecurityE2EApplication",
        "WorkflowV4ContextHTTPHandler": "SecurityE2EHTTPHandler",
    }

    def visit_Name(self, node: ast.Name):
        replacement = self.RENAME.get(node.id)
        if replacement:
            return ast.copy_location(ast.Name(id=replacement, ctx=node.ctx), node)
        return node

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            updated = _canonicalize_identity(node.value)
            if updated != node.value:
                return ast.copy_location(ast.Constant(value=updated), node)
        return node


def _final_main() -> ast.FunctionDef:
    path = PKG / "chat_gateway_v17.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module_aliases, symbol_aliases = _collect_chain_imports(tree)
    chain_transformer = _ChainReferenceTransformer(module_aliases, symbol_aliases)
    source_main = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    main_node = chain_transformer.visit(source_main)
    assert isinstance(main_node, ast.FunctionDef)
    main_node = _FinalMainBindingTransformer().visit(main_node)
    assert isinstance(main_node, ast.FunctionDef)
    patch = ast.parse("_orchestrator.KnowledgeGateway = KnowledgeGatewayV2").body[0]
    main_node.body.insert(0, patch)
    return main_node


def _canonical_module_source(paths: list[Path]) -> str:
    body: list[ast.stmt] = []
    for path in paths:
        body.extend(_transform_module(path))
    body.append(ast.parse("HTML_V17 = WORKSPACE_HTML").body[0])
    body.append(_final_main())
    module = ast.Module(body=body, type_ignores=[])
    ast.fix_missing_locations(module)
    source = ast.unparse(module) + "\n"
    source = _canonicalize_identity(source)
    if re.search(r"(?:from|import)\s+[^\n]*chat_gateway_v\d+", source):
        raise RuntimeError("generated canonical source still imports a versioned chat gateway module")
    if MODULE_REF_RE.search(source):
        raise RuntimeError("generated canonical source still contains a versioned chat gateway identity")
    if FRONTEND_SECURITY_REF_RE.search(source):
        raise RuntimeError("generated canonical source still contains a versioned frontend security identity")
    return source


def _rewrite_external_references(paths: list[Path]) -> list[Path]:
    changed: list[Path] = []
    patterns = [
        (re.compile(r"from\s+three_agent\.chat_gateway_v\d+\s+import"), "from three_agent.chat_gateway import"),
        (re.compile(r"from\s+\.chat_gateway_v\d+\s+import"), "from .chat_gateway import"),
        (re.compile(r"import\s+three_agent\.chat_gateway_v\d+(?=\s+as\s+|\s|$)"), "import three_agent.chat_gateway"),
        (re.compile(r"from\s+three_agent\s+import\s+chat_gateway_v\d+"), "from three_agent import chat_gateway"),
        (re.compile(r"from\s+\.\s+import\s+chat_gateway_v\d+"), "from . import chat_gateway"),
        (re.compile(r"three_agent\.chat_gateway_v\d+"), "three_agent.chat_gateway"),
        (re.compile(r"chat_gateway_v\d+\.py"), "chat_gateway.py"),
        (re.compile(r"chat_gateway_v\d+"), "chat_gateway"),
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        updated = text
        for pattern, replacement in patterns:
            updated = pattern.sub(replacement, updated)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed.append(path)
    return changed


def _rewrite_pyproject() -> bool:
    text = PYPROJECT.read_text(encoding="utf-8")
    updated = re.sub(r"three_agent\.chat_gateway_v\d+:main", "three_agent.chat_gateway:main", text)
    if updated == text:
        return False
    PYPROJECT.write_text(updated, encoding="utf-8")
    return True


def _test_source(public_defs: list[str], expected_chain: list[str]) -> str:
    return f'''from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "src" / "three_agent" / "chat_gateway.py"
PYPROJECT = ROOT / "pyproject.toml"
EXPECTED_PUBLIC = {public_defs!r}
EXPECTED_CHAIN = {expected_chain!r}


def class_graph(tree: ast.Module) -> dict[str, list[str]]:
    graph: dict[str, list[str]] = {{}}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        graph[node.name] = [ast.unparse(base) for base in node.bases]
    return graph


def inheritance_chain(graph: dict[str, list[str]], root: str) -> list[str]:
    chain = [root]
    current = root
    seen = {{root}}
    while current in graph and graph[current]:
        bases = graph[current]
        if len(bases) != 1:
            raise AssertionError(f"{{current}} has non-deterministic bases: {{bases}}")
        parent = bases[0]
        chain.append(parent)
        if parent in seen:
            raise AssertionError(f"inheritance cycle at {{parent}}")
        seen.add(parent)
        if parent not in graph:
            break
        current = parent
    return chain


class ChatGatewayCanonicalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = CANONICAL.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(CANONICAL))

    def test_all_semantic_public_definitions_are_preserved(self) -> None:
        actual = {{
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name != "main"
            and not node.name.startswith("_")
        }}
        self.assertEqual(sorted(set(EXPECTED_PUBLIC) - actual), [])

    def test_final_chat_service_inheritance_chain_is_preserved(self) -> None:
        actual = inheritance_chain(class_graph(self.tree), "ContinuitySecurityAwareProjectChatService")
        self.assertEqual(actual, EXPECTED_CHAIN)

    def test_final_main_binds_current_service_and_security_surface(self) -> None:
        main_node = next(
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        names = {{node.id for node in ast.walk(main_node) if isinstance(node, ast.Name)}}
        for required in (
            "ContinuitySecurityAwareProjectChatService",
            "SecurityE2EApplication",
            "SecurityE2EHTTPHandler",
            "KnowledgeGatewayV2",
        ):
            self.assertIn(required, names)
        assignments = [
            node for node in ast.walk(main_node)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "_orchestrator"
                and target.attr == "KnowledgeGateway"
                for target in node.targets
            )
        ]
        self.assertEqual(len(assignments), 1)

    def test_no_physical_chat_gateway_generations_remain(self) -> None:
        package = ROOT / "src" / "three_agent"
        self.assertEqual(list(package.glob("chat_gateway_v*.py")), [])

    def test_canonical_chat_has_no_versioned_frontend_security_reference(self) -> None:
        self.assertIsNone(
            re.search(r"(?:three_agent\\.)?workspace_frontend_security_v\\d+", self.source)
        )
        self.assertIn(
            "from .workspace_frontend_security import WORKSPACE_HTML_SECURITY_V3",
            self.source,
        )

    def test_production_source_and_entrypoints_have_no_versioned_chat_gateway_reference(self) -> None:
        pattern = re.compile(r"(?:three_agent\\.)?chat_gateway_v\\d+")
        stale = []
        migration = (ROOT / "scripts" / "consolidate_chat_gateway.py").resolve()
        for base in (ROOT / "src", ROOT / "scripts"):
            for path in base.rglob("*.py"):
                if path.resolve() == migration:
                    continue
                if pattern.search(path.read_text(encoding="utf-8")):
                    stale.append(str(path.relative_to(ROOT)))
        if pattern.search(PYPROJECT.read_text(encoding="utf-8")):
            stale.append("pyproject.toml")
        self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
'''


def apply() -> dict[str, object]:
    variants = _variants()
    if not variants:
        return {"status": "noop", "reason": "no chat gateway variants remain"}
    expected = list(range(2, 23))
    actual = [int(VARIANT_RE.fullmatch(path.name).group(1)) for path in variants]  # type: ignore[union-attr]
    if actual != expected:
        raise RuntimeError(f"chat gateway chain is incomplete: expected {expected}, got {actual}")

    sources = [CANONICAL, *variants]
    public_defs = _public_definitions(sources)
    expected_chain = _inheritance_chain(sources, "ContinuitySecurityAwareProjectChatService")
    source = _canonical_module_source(sources)

    variant_set = {path.resolve() for path in variants}
    external: list[Path] = []
    for base in (SRC, ROOT / "tests", ROOT / "scripts"):
        for path in base.rglob("*.py"):
            if path.resolve() in variant_set or path.resolve() == Path(__file__).resolve():
                continue
            external.append(path)

    CANONICAL.write_text(source, encoding="utf-8")
    changed = _rewrite_external_references(sorted(external))
    pyproject_changed = _rewrite_pyproject()
    TEST_FILE.write_text(_test_source(public_defs, expected_chain), encoding="utf-8")
    for path in variants:
        path.unlink()

    stale: list[str] = []
    for base in (SRC, ROOT / "scripts"):
        for path in base.rglob("*.py"):
            if path.resolve() == Path(__file__).resolve():
                continue
            if MODULE_REF_RE.search(path.read_text(encoding="utf-8")):
                stale.append(str(path.relative_to(ROOT)))
    if MODULE_REF_RE.search(PYPROJECT.read_text(encoding="utf-8")):
        stale.append("pyproject.toml")
    if stale:
        raise RuntimeError("stale versioned chat gateway references remain: " + ", ".join(sorted(stale)))

    return {
        "status": "applied",
        "removed_variants": len(variants),
        "public_definitions": len(public_defs),
        "expected_inheritance_chain": expected_chain,
        "pyproject_rewritten": pyproject_changed,
        "rewritten_files": [str(path.relative_to(ROOT)) for path in changed],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Flatten the WorkSpace chat gateway generation chain into one canonical module")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        print({"status": "ready", "variants": [path.name for path in _variants()]})
        return 0
    print(apply())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
