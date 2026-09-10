#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "src" / "three_agent" / "chat_simple_e2e_acceptance.py"

OLD = '''        ("node.dataset.uiRoute!==\'direct_chat\'", "frontend_stage_suppression_missing"),\n'''
NEW = '''        ("function shouldShowAnswerStages(job,route)", "frontend_stage_suppression_helper_missing"),\n        ("return route!==\'direct_chat\'", "frontend_stage_suppression_route_missing"),\n        ("shouldShowAnswerStages(job,d.dataset.uiRoute)", "frontend_initial_stage_suppression_missing"),\n        ("shouldShowAnswerStages(j,node.dataset.uiRoute)", "frontend_stage_suppression_missing"),\n'''


def main() -> int:
    source = TARGET.read_text(encoding="utf-8")
    if NEW in source:
        print("simple-chat acceptance already uses canonical stage suppression contract")
        return 0
    count = source.count(OLD)
    if count != 1:
        raise RuntimeError(
            f"simple-chat suppression migration expected exactly one stale marker, got {count}"
        )
    updated = source.replace(OLD, NEW, 1)
    TARGET.write_text(updated, encoding="utf-8")
    print("migrated simple-chat stage suppression acceptance to canonical helper semantics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
