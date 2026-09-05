from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SCHEMA = "workspace-canonical-module-guard/v1"
FORBIDDEN_SUFFIX_RE = re.compile(
    r"(?i)(?:_v\d+|_ver\d+|_part\d+|_new\d*|_final\d*|_old\d*|_backup\d*|_bak\d*|_copy\d*|_budgeted\d*)+$"
)
SYMBOL_VERSION_RE = re.compile(r"(?i)(?:V\d+|Version\d+)$")
TEXT_EXTENSIONS = {".py", ".toml", ".yml", ".yaml", ".sh", ".ps1", ".md"}


@dataclass(frozen=True)
class ModuleInfo:
    path: str
    stem: str
    canonical_stem: str
    public_symbols: tuple[str, ...]
    normalized_symbols: tuple[str, ...]
    structural_hash: str
    parse_error: str | None = None


@dataclass(frozen=True)
class Finding:
    severity: str
    kind: str
    path: str
    canonical_target: str | None
    confidence: float
    reason: str
    action: str
    shared_symbols: tuple[str, ...] = ()
    missing_from_canonical: tuple[str, ...] = ()
    conflicting_symbols: tuple[str, ...] = ()


def canonical_stem(stem: str) -> str:
    current = stem
    while True:
        stripped = FORBIDDEN_SUFFIX_RE.sub("", current)
        if stripped == current:
            return current
        current = stripped


def normalize_symbol(name: str) -> str:
    return ".".join(SYMBOL_VERSION_RE.sub("", part).lower() for part in name.split("."))


class _ShapeNormalizer(ast.NodeTransformer):
    """Normalize identifiers while preserving behavior-bearing literal values."""

    def visit_FunctionDef(self, node: ast.FunctionDef):  # noqa: N802
        node = self.generic_visit(node)
        node.name = "<function>"
        node.decorator_list = []
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):  # noqa: N802
        node = self.generic_visit(node)
        node.name = "<async-function>"
        node.decorator_list = []
        return node

    def visit_ClassDef(self, node: ast.ClassDef):  # noqa: N802
        node = self.generic_visit(node)
        node.name = "<class>"
        node.decorator_list = []
        return node

    def visit_arg(self, node: ast.arg):
        node.arg = "_"
        node.annotation = None
        return node

    def visit_Name(self, node: ast.Name):  # noqa: N802
        node.id = "_"
        return node

    def visit_Attribute(self, node: ast.Attribute):  # noqa: N802
        node = self.generic_visit(node)
        node.attr = "_"
        return node


def _public_symbols(tree: ast.Module) -> set[str]:
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not node.name.startswith("_"):
                symbols.add(node.name)
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and not child.name.startswith("_"):
                        symbols.add(f"{node.name}.{child.name}")
    return symbols


def _shape_hash(tree: ast.Module) -> str:
    body = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        body.append(node)
    normalized = ast.Module(body=body, type_ignores=[])
    normalized = _ShapeNormalizer().visit(normalized)
    ast.fix_missing_locations(normalized)
    payload = ast.dump(normalized, annotate_fields=True, include_attributes=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def analyze_module(path: Path, root: Path) -> ModuleInfo:
    rel = path.relative_to(root).as_posix()
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel)
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        return ModuleInfo(
            path=rel,
            stem=path.stem,
            canonical_stem=canonical_stem(path.stem),
            public_symbols=(),
            normalized_symbols=(),
            structural_hash="",
            parse_error=f"{type(exc).__name__}: {exc}",
        )
    public = sorted(_public_symbols(tree))
    normalized = sorted({normalize_symbol(item) for item in public})
    return ModuleInfo(
        path=rel,
        stem=path.stem,
        canonical_stem=canonical_stem(path.stem),
        public_symbols=tuple(public),
        normalized_symbols=tuple(normalized),
        structural_hash=_shape_hash(tree),
    )


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    a, b = set(left), set(right)
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _top_level_names(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return set()
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _safe_reexport_variant(variant: Path, canonical: Path) -> bool:
    if not canonical.exists():
        return False
    try:
        tree = ast.parse(variant.read_text(encoding="utf-8"), filename=str(variant))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    canonical_names = _top_level_names(canonical)
    saw_reexport = False
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        if isinstance(node, ast.ImportFrom):
            imported_leaf = (node.module or "").split(".")[-1]
            if imported_leaf != canonical.stem:
                return False
            for alias in node.names:
                if alias.name == "*":
                    saw_reexport = True
                    continue
                if alias.name not in canonical_names:
                    return False
                saw_reexport = True
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if all(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                continue
        return False
    return saw_reexport


def _rewrite_module_references(root: Path, variant_rel: Path, canonical_rel: Path) -> int:
    variant_abs = (root / variant_rel).resolve()
    variant_dotted = variant_rel.with_suffix("").as_posix().replace("/", ".")
    canonical_dotted = canonical_rel.with_suffix("").as_posix().replace("/", ".")
    variant_leaf = variant_rel.stem
    canonical_leaf = canonical_rel.stem
    changed = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        if path.resolve() == variant_abs:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        new = text.replace(variant_dotted, canonical_dotted)
        new = new.replace(f".{variant_leaf}", f".{canonical_leaf}")
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed += 1
    return changed


def scan(root: Path, production_roots: tuple[str, ...] = ("src",)) -> dict:
    root = root.resolve()
    modules: list[ModuleInfo] = []
    for production_root in production_roots:
        base = root / production_root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" not in path.parts:
                modules.append(analyze_module(path, root))

    by_rel = {module.path: module for module in modules}
    findings: list[Finding] = []
    version_families: dict[str, list[str]] = {}

    for module in modules:
        if module.parse_error:
            findings.append(Finding(
                severity="error", kind="parse_error", path=module.path,
                canonical_target=None, confidence=1.0, reason=module.parse_error,
                action="fix_parse_error",
            ))
            continue
        if module.canonical_stem != module.stem:
            rel = Path(module.path)
            canonical_rel = rel.with_name(module.canonical_stem + rel.suffix).as_posix()
            version_families.setdefault(canonical_rel, []).append(module.path)
            canonical = by_rel.get(canonical_rel)
            shared: tuple[str, ...] = ()
            missing: tuple[str, ...] = ()
            conflicts: tuple[str, ...] = ()
            action = "create_or_merge_into_canonical"
            if canonical:
                shared_set = set(module.normalized_symbols) & set(canonical.normalized_symbols)
                missing_set = set(module.normalized_symbols) - set(canonical.normalized_symbols)
                shared = tuple(sorted(shared_set))
                missing = tuple(sorted(missing_set))
                exact_behavior_shape = bool(
                    module.structural_hash and module.structural_hash == canonical.structural_hash
                )
                if missing_set:
                    action = "semantic_merge_required"
                elif exact_behavior_shape:
                    action = "equivalent_variant_rewrite_references_and_delete"
                else:
                    action = "compare_behavior_then_merge_or_delete"
                conflicts = tuple(sorted(
                    normalize_symbol(name)
                    for name in set(module.public_symbols) & set(canonical.public_symbols)
                ))
            findings.append(Finding(
                severity="error",
                kind="implementation_generation_file",
                path=module.path,
                canonical_target=canonical_rel,
                confidence=1.0,
                reason="production implementation filename uses a forbidden generation/version suffix",
                action=action,
                shared_symbols=shared,
                missing_from_canonical=missing,
                conflicting_symbols=conflicts,
            ))

    for index, left in enumerate(modules):
        if left.parse_error:
            continue
        for right in modules[index + 1:]:
            if right.parse_error:
                continue
            if Path(left.path).parent != Path(right.path).parent:
                continue
            if left.canonical_stem == right.canonical_stem:
                continue
            surface = _jaccard(left.normalized_symbols, right.normalized_symbols)
            symbol_floor = min(len(left.normalized_symbols), len(right.normalized_symbols))
            exact_shape = bool(left.structural_hash and left.structural_hash == right.structural_hash)
            if surface >= 0.85 and symbol_floor >= 3:
                confidence = round(surface, 3)
                reason = f"normalized public API overlap is {surface:.0%}"
            elif exact_shape and surface >= 0.80 and symbol_floor >= 2:
                confidence = 1.0
                reason = "public API and normalized AST structure are effectively identical"
            else:
                continue
            canonical_rel, duplicate_rel = sorted((left.path, right.path))
            shared = tuple(sorted(set(left.normalized_symbols) & set(right.normalized_symbols)))
            findings.append(Finding(
                severity="error",
                kind="functional_duplicate",
                path=duplicate_rel,
                canonical_target=canonical_rel,
                confidence=confidence,
                reason=reason,
                action="compare_behavior_then_merge_into_one_canonical_module",
                shared_symbols=shared,
            ))

    findings.sort(key=lambda item: (item.kind, item.path, item.canonical_target or ""))
    return {
        "schema": SCHEMA,
        "status": "FAIL" if findings else "PASS",
        "production_file_count": len(modules),
        "version_family_count": len(version_families),
        "prohibited_file_count": sum(1 for item in findings if item.kind == "implementation_generation_file"),
        "high_confidence_duplicate_count": sum(1 for item in findings if item.kind == "functional_duplicate"),
        "parse_error_count": sum(1 for item in findings if item.kind == "parse_error"),
        "version_families": [
            {"canonical": canonical, "variants": sorted(variants)}
            for canonical, variants in sorted(version_families.items())
        ],
        "findings": [asdict(item) for item in findings],
    }


def fix_safe(root: Path, report: dict) -> dict:
    root = root.resolve()
    actions = []
    for finding in report.get("findings", []):
        if finding.get("kind") != "implementation_generation_file":
            continue
        canonical_target = finding.get("canonical_target")
        if not canonical_target:
            continue
        variant_rel = Path(finding["path"])
        canonical_rel = Path(canonical_target)
        variant = root / variant_rel
        canonical = root / canonical_rel
        if not variant.exists() or not _safe_reexport_variant(variant, canonical):
            continue
        rewrites = _rewrite_module_references(root, variant_rel, canonical_rel)
        variant.unlink()
        actions.append({
            "action": "safe_reexport_consolidation",
            "removed": variant_rel.as_posix(),
            "canonical": canonical_rel.as_posix(),
            "rewritten_files": rewrites,
        })
    return {"actions": actions, "count": len(actions)}


def markdown(report: dict) -> str:
    lines = [
        "## Canonical Module Guard",
        "",
        f"- Status: **{report['status']}**",
        f"- Production Python files: **{report['production_file_count']}**",
        f"- Version/copy families: **{report['version_family_count']}**",
        f"- Prohibited implementation files: **{report['prohibited_file_count']}**",
        f"- High-confidence functional duplicates: **{report['high_confidence_duplicate_count']}**",
        f"- Parse errors: **{report['parse_error_count']}**",
        "",
    ]
    if report["findings"]:
        lines.extend(["| Kind | File | Canonical | Action |", "|---|---|---|---|"])
        for item in report["findings"][:100]:
            lines.append(
                f"| {item['kind']} | `{item['path']}` | `{item.get('canonical_target') or '-'}` | {item['action']} |"
            )
    else:
        lines.append("No canonical-module violations detected.")
    return "\n".join(lines) + "\n"


def _print_summary(report: dict) -> None:
    print(
        "canonical-module-guard "
        f"status={report['status']} "
        f"files={report['production_file_count']} "
        f"families={report['version_family_count']} "
        f"prohibited={report['prohibited_file_count']} "
        f"duplicates={report['high_confidence_duplicate_count']} "
        f"parse_errors={report['parse_error_count']}"
    )
    for finding in report["findings"]:
        target = f" -> {finding['canonical_target']}" if finding.get("canonical_target") else ""
        print(
            f"[ERROR] {finding['kind']}: {finding['path']}{target}; "
            f"action={finding['action']}; reason={finding['reason']}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enforce one canonical production module per function family.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--production-root", action="append", dest="production_roots")
    parser.add_argument("--json-output")
    parser.add_argument("--markdown-output")
    parser.add_argument("--fix-safe", action="store_true")
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve()
    roots = tuple(args.production_roots or ["src"])
    report = scan(root, roots)

    if args.fix_safe:
        fix = fix_safe(root, report)
        report = scan(root, roots)
        report["safe_fix"] = fix

    if args.json_output:
        output = Path(args.json_output)
        if not output.is_absolute():
            output = root / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        output = Path(args.markdown_output)
        if not output.is_absolute():
            output = root / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(markdown(report), encoding="utf-8")

    _print_summary(report)
    if args.report_only:
        return 0
    return 0 if report["status"] == "PASS" else 64


if __name__ == "__main__":
    raise SystemExit(main())
