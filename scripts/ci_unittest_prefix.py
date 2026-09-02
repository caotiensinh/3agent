#!/usr/bin/env python3
"""Run cumulative unittest prefixes and targeted suffix probes for CI localization.

The production unittest gate stays unchanged. This helper exists only to isolate
order/import contamination with observable PASS/FAIL boundaries.
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

    files = sorted(Path("tests").glob("test_*.py"))
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

    suite = unittest.TestSuite()
    for path in selected:
        # unittest.TestLoader.discover() retains top-level discovery state. A fresh
        # loader per module prevents the diagnostic helper itself from creating
        # cross-discovery state that the production one-shot discovery does not.
        loader = unittest.TestLoader()
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
