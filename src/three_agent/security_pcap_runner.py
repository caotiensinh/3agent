from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from .security_monitoring.contracts import MonitoringContractError
from .security_monitoring.incident_capture import (
    CAPTURE_CONFIRMATION,
    IncidentCapturePolicy,
    execute_capture_approval,
)
from .security_monitoring.runtime_config import load_runtime_config

_APPROVAL_ID_RE = re.compile(r"^approval-[0-9a-f]{24}$", re.ASCII)


def run_capture(
    *,
    config_path: Path,
    approval_id: str,
    confirmation: str,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if os.name != "posix":
        raise RuntimeError("INCIDENT_CAPTURE_POSIX_ONLY")
    config_file = Path(config_path)
    if not config_file.is_absolute() or config_file.is_symlink() or not config_file.is_file():
        raise MonitoringContractError("monitoring config path is unavailable or unsafe")
    approval = str(approval_id or "").strip().lower()
    if not _APPROVAL_ID_RE.fullmatch(approval):
        raise MonitoringContractError("approval_id is invalid")
    if confirmation != CAPTURE_CONFIRMATION:
        raise PermissionError("CAPTURE_CONFIRMATION_REQUIRED")

    config = load_runtime_config(config_file)
    policy = IncidentCapturePolicy.from_environment(env)
    if not policy.enabled:
        raise PermissionError("INCIDENT_CAPTURE_DISABLED")
    approval_path = policy.approval_root / f"{approval}.json"
    receipt = execute_capture_approval(
        approval_path,
        confirmation=confirmation,
        policy=policy,
        config=config,
    )
    return {
        "schema_version": receipt.schema_version,
        "status": "completed",
        "capture_id": receipt.capture_id,
        "approval_id": receipt.approval_id,
        "pcap_sha256": receipt.pcap_sha256,
        "captured_bytes": receipt.captured_bytes,
        "completed_at": receipt.completed_at,
        "retention_expires_at": receipt.retention_expires_at,
        "stop_reason": receipt.stop_reason,
        "evidence_ref": receipt.evidence_ref,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-security-pcap",
        description="Execute one previously admin-approved bounded incident capture.",
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--approval-id", required=True)
    parser.add_argument("--confirmation", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = run_capture(
            config_path=Path(args.config),
            approval_id=args.approval_id,
            confirmation=args.confirmation,
        )
    except (MonitoringContractError, PermissionError, RuntimeError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "failure_type": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 3
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
