from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .benchmark_suite import DEFAULT_VARIANTS, SUITE_SCHEMA

CANONICALIZATION_SCHEMA = "workspace-benchmark-artifact-canonicalization/v1"


class BenchmarkArtifactCanonicalizationError(ValueError):
    """Benchmark suite path metadata cannot be safely canonicalized."""


def canonicalize_suite_manifest_paths(root: Path) -> dict[str, Any]:
    """Replace only verified absolute benchmark manifest paths with relative paths.

    The benchmark runner historically records its local absolute manifest path in
    `suite.json`. Before the suite is logged or uploaded, this function verifies
    each path resolves to the expected file inside the benchmark root and then
    rewrites only that `manifest_path` field to `<variant>/benchmark.json`.
    """
    artifact_root = Path(root).expanduser().resolve()
    suite_path = artifact_root / "suite.json"
    if not suite_path.is_file():
        raise BenchmarkArtifactCanonicalizationError("SUITE_MISSING")
    try:
        payload = json.loads(suite_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkArtifactCanonicalizationError("SUITE_JSON_INVALID") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SUITE_SCHEMA:
        raise BenchmarkArtifactCanonicalizationError("SUITE_SCHEMA_INVALID")
    variants = payload.get("variants")
    expected_labels = {spec.label for spec in DEFAULT_VARIANTS}
    if not isinstance(variants, dict) or set(variants) != expected_labels:
        raise BenchmarkArtifactCanonicalizationError("VARIANT_SET_MISMATCH")

    changed = 0
    for label in sorted(expected_labels):
        row = variants.get(label)
        if not isinstance(row, dict):
            raise BenchmarkArtifactCanonicalizationError("VARIANT_ROW_INVALID")
        raw_path = str(row.get("manifest_path") or "").strip()
        if not raw_path:
            raise BenchmarkArtifactCanonicalizationError("MANIFEST_PATH_MISSING")
        expected = (artifact_root / label / "benchmark.json").resolve()
        supplied = Path(raw_path)
        resolved = (
            supplied.resolve()
            if supplied.is_absolute()
            else (artifact_root / supplied).resolve()
        )
        if resolved != expected or not expected.is_file():
            raise BenchmarkArtifactCanonicalizationError("MANIFEST_PATH_OUTSIDE_EXPECTED_FILE")
        relative = f"{label}/benchmark.json"
        if raw_path.replace("\\", "/") != relative:
            row["manifest_path"] = relative
            changed += 1

    temporary = suite_path.with_name(suite_path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(suite_path)
    return {
        "schema_version": CANONICALIZATION_SCHEMA,
        "completed": True,
        "variant_count": len(expected_labels),
        "manifest_paths_rewritten": changed,
        "only_manifest_path_fields_mutated": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-benchmark-canonicalize",
        description="Canonicalize fixed benchmark local manifest paths before publication.",
    )
    parser.add_argument("--root", required=True, help="Benchmark artifact root containing suite.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = canonicalize_suite_manifest_paths(Path(args.root))
    except BenchmarkArtifactCanonicalizationError as exc:
        print(
            json.dumps(
                {
                    "schema_version": CANONICALIZATION_SCHEMA,
                    "completed": False,
                    "failure_code": str(exc),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
