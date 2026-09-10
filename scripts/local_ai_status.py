#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys

from three_agent.config import load_config
from three_agent.local_ai_runtime import (
    LocalAIRuntimeError,
    local_ai_status_service_from_config,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Print the read-only status of trusted local AI runtimes and provisioned models"
    )
    parser.add_argument("--config", help="Optional WorkSpace config path")
    parser.add_argument(
        "--manifest",
        default="config/models.approved.json",
        help="Approved Hugging Face model manifest",
    )
    parser.add_argument(
        "--store",
        help="Verified local model store; defaults to WORKSPACE_MODEL_STORE or /var/lib/workspace/models",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Local runtime health timeout in seconds (0.1..10)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        service = local_ai_status_service_from_config(
            config,
            manifest_path=args.manifest,
            model_store=args.store,
            timeout_seconds=args.timeout,
        )
        print(json.dumps(service.snapshot(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, LocalAIRuntimeError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": "workspace-local-ai-status/v1",
                    "authority": "observation",
                    "completed": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
