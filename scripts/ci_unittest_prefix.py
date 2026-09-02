#!/usr/bin/env python3
"""Run a cumulative prefix of unittest modules for CI fault localization.

This keeps the production gate unchanged while turning order/import contamination
into a small number of observable PASS/FAIL boundaries. Optional appended modules
allow a suspected victim to run after the cumulative prefix in the same process.
"""

from __future__ import annotations

import argparse
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.parts < 1 or not 1 <= args.prefix <= args.parts:
        raise SystemExit("--prefix must be between 1 and --parts")

    files = sorted(Path("tests").glob("test_*.py"))
    if not files:
        raise SystemExit("no tests/test_*.py files found")

    end = max(1, math.ceil(len(files) * args.prefix / args.parts))
    selected = list(files[:end])
    files_by_name = {path.name: path for path in files}
    appended: list[str] = []

    for name in args.append:
        target = files_by_name.get(name)
        if target is None:
            raise SystemExit(f"unknown test module for --append: {name}")
        if target not in selected:
            selected.append(target)
            appended.append(name)

    print(
        f"CI unittest prefix {args.prefix}/{args.parts}: "
        f"{len(selected)}/{len(files)} modules; "
        f"prefix_boundary={files[end - 1].name}; "
        f"appended={appended or ['<none>']}",
        flush=True,
    )

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for path in selected:
        suite.addTests(
            loader.discover(
                start_dir="tests",
                pattern=path.name,
                top_level_dir=".",
            )
        )

    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
