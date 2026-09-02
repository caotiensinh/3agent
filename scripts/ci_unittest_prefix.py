#!/usr/bin/env python3
"""Run cumulative unittest prefixes and targeted suffix probes for CI localization.

The production unittest gate stays unchanged. This helper exists only to isolate
order/import contamination with observable PASS/FAIL boundaries.
"""

from __future__ import annotations

import argparse
import importlib
import math
import sys
import unittest
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=int, required=True)
    parser.add_argument("--parts", type=int, required=True)
    parser.add_argument(
        "--append",
        action="append",
        default=[],
        metavar="TEST_MODULE",
        help="append an exact tests/test_*.py filename after the prefix; repeatable",
    )
    parser.add_argument(
        "--append-suffix-index",
        type=int,
        default=None,
        metavar="INDEX",
        help="append one zero-based module from the excluded suffix after the prefix",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.parts < 1 or not 1 <= args.prefix <= args.parts:
        raise SystemExit("--prefix must be between 1 and --parts")

    repo_root = Path(__file__).resolve().parents[1]
    tests_dir = repo_root / "tests"
    files = sorted(tests_dir.glob("test_*.py"))
    if not files:
        raise SystemExit("no tests/test_*.py files found")

    end = max(1, math.ceil(len(files) * args.prefix / args.parts))
    selected = list(files[:end])
    suffix = list(files[end:])
    files_by_name = {path.name: path for path in files}
    appended: list[str] = []

    for name in args.append:
        target = files_by_name.get(name)
        if target is None:
            raise SystemExit(f"unknown test module for --append: {name}")
        if target not in selected:
            selected.append(target)
            appended.append(name)

    if args.append_suffix_index is not None:
        index = args.append_suffix_index
        if index < 0 or index >= len(suffix):
            raise SystemExit(
                f"--append-suffix-index {index} outside excluded suffix of {len(suffix)} modules"
            )
        target = suffix[index]
        if target not in selected:
            selected.append(target)
            appended.append(target.name)

    print(
        f"CI unittest prefix {args.prefix}/{args.parts}: "
        f"{len(selected)}/{len(files)} selected; "
        f"prefix_boundary={files[end - 1].name}; "
        f"excluded_suffix={[path.name for path in suffix]}; "
        f"appended={appended or ['<none>']}",
        flush=True,
    )

    # unittest discovery imports tests by stem while project tests also import
    # top-level project packages such as ``scripts``. Reproduce both import
    # roots explicitly so the localization helper does not create path-only
    # failures that the real ``python -m unittest discover -s tests`` gate
    # would never see.
    repo_root_text = str(repo_root)
    tests_dir_text = str(tests_dir)
    for import_root in (repo_root_text, tests_dir_text):
        try:
            sys.path.remove(import_root)
        except ValueError:
            pass
    sys.path[:0] = [repo_root_text, tests_dir_text]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for path in selected:
        module = importlib.import_module(path.stem)
        suite.addTests(loader.loadTestsFromModule(module))

    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
