from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .network_lanl_publisher_access import (
    FAIL_SCHEMA,
    FAIL_SECURITY,
    LANLPublisherAccessError,
    NOT_ENOUGH,
    READY,
    SOURCE_BINDINGS,
    SOURCE_FAMILIES,
    evaluate_access_handles,
)

PHASE = "V3-02E-LANL-OPERATOR-HANDOFF"
HANDOFF_CANCELLED = "LANL_OPERATOR_HANDOFF_CANCELLED"
HANDOFF_TTY_REQUIRED = "LANL_OPERATOR_HANDOFF_TTY_REQUIRED"
DEFAULT_ACCESS_PROFILE = "evaluation/network_v3_02e_lanl_publisher_access_v1.json"


@dataclass(frozen=True)
class LANLOperatorHandoffDecision:
    readiness: str
    failed_gate_ids: tuple[str, ...]
    receipt: dict[str, Any] | None


def _cancelled() -> LANLOperatorHandoffDecision:
    return LANLOperatorHandoffDecision(
        readiness=NOT_ENOUGH,
        failed_gate_ids=(HANDOFF_CANCELLED,),
        receipt=None,
    )


def collect_and_validate_handles(
    profile: Mapping[str, Any],
    *,
    interactive_tty: bool,
    prompt_secret: Callable[[str], str],
) -> LANLOperatorHandoffDecision:
    """Collect five publisher handles in process memory and validate them offline.

    The caller supplies the no-echo prompt function so the security behavior can be
    tested without a terminal. Production binds this parameter to getpass.getpass.
    """

    if not interactive_tty:
        raise LANLPublisherAccessError(
            FAIL_SECURITY,
            HANDOFF_TTY_REQUIRED,
            "interactive local terminal required",
        )

    handles: dict[str, str] = {}
    current_handle: str | None = None
    try:
        for family in SOURCE_FAMILIES:
            filename = str(SOURCE_BINDINGS[family]["filename"])
            try:
                current_handle = prompt_secret(
                    f"LANL {family} ({filename}) publisher access URL: "
                )
            except (EOFError, KeyboardInterrupt):
                return _cancelled()
            if not isinstance(current_handle, str) or not current_handle.strip():
                return _cancelled()
            handles[family] = current_handle
            current_handle = None

        access_decision = evaluate_access_handles(handles, profile=profile)
        return LANLOperatorHandoffDecision(
            readiness=access_decision.readiness,
            failed_gate_ids=access_decision.failed_gate_ids,
            receipt=dict(access_decision.receipt),
        )
    finally:
        handles.clear()
        current_handle = None


def _read_profile(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise LANLPublisherAccessError(
            FAIL_SECURITY,
            "LANL_HANDOFF_PROFILE_SYMLINK",
            "profile symlink forbidden",
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA,
            "LANL_HANDOFF_PROFILE_SCHEMA",
            "profile JSON invalid",
        ) from exc
    if not isinstance(value, dict):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA,
            "LANL_HANDOFF_PROFILE_SCHEMA",
            "profile must be an object",
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline no-echo LANL publisher-handle handoff validator"
    )
    parser.add_argument(
        "--profile",
        default=DEFAULT_ACCESS_PROFILE,
        help="Path to the non-secret LANL publisher-access contract profile",
    )
    return parser


def _safe_status(decision: LANLOperatorHandoffDecision) -> dict[str, Any]:
    if decision.receipt is not None:
        return dict(decision.receipt)
    return {
        "phase": PHASE,
        "readiness": decision.readiness,
        "failed_gate_ids": list(decision.failed_gate_ids),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = _read_profile(Path(args.profile))
        decision = collect_and_validate_handles(
            profile,
            interactive_tty=sys.stdin.isatty(),
            prompt_secret=getpass.getpass,
        )
    except LANLPublisherAccessError as exc:
        print(
            json.dumps(
                {"phase": PHASE, "readiness": exc.readiness, "gate_id": exc.gate_id},
                sort_keys=True,
            )
        )
        return 1

    print(json.dumps(_safe_status(decision), sort_keys=True))
    if decision.readiness == READY:
        return 0
    if decision.readiness == NOT_ENOUGH:
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
