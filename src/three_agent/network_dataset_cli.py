from __future__ import annotations

import argparse
import json
from pathlib import Path

from .network_dataset_policy import (
    NetworkDatasetDenied,
    NetworkDatasetManager,
    NetworkDatasetPolicyError,
)

DEFAULT_POLICY = Path("config/network-data-policy.json")
DEFAULT_REGISTRY = Path("config/network-datasets.registry.json")


def _manager(args: argparse.Namespace) -> NetworkDatasetManager:
    return NetworkDatasetManager.load(
        policy_path=args.policy,
        registry_path=args.registry,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-network-data",
        description="WorkSpace Network AI dataset admission/control plane (no network I/O).",
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List reviewed dataset registry entries.")
    sub.add_parser("fingerprint", help="Print policy and registry fingerprints.")

    plan = sub.add_parser("plan", help="Create a bounded acquisition plan.")
    plan.add_argument("dataset_id")
    plan.add_argument(
        "--purpose",
        choices=("training", "evaluation", "research"),
        required=True,
    )
    plan.add_argument("--estimated-bytes", type=int, required=True)
    plan.add_argument("--objects", type=int, default=1)
    plan.add_argument("--variant")
    plan.add_argument("--full", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        manager = _manager(args)
        if args.command == "list":
            payload = [
                {
                    "id": item.dataset_id,
                    "name": item.name,
                    "status": item.status,
                    "commercial_use": item.commercial_use,
                    "acquisition_mode": item.acquisition_mode,
                    "variants": sorted(item.variants),
                }
                for item in manager.list_datasets()
            ]
        elif args.command == "fingerprint":
            payload = {
                "policy_fingerprint": manager.policy_fingerprint,
                "registry_fingerprint": manager.registry_fingerprint,
            }
        else:
            payload = manager.plan(
                args.dataset_id,
                purpose=args.purpose,
                estimated_bytes=args.estimated_bytes,
                object_count=args.objects,
                variant=args.variant,
                full_sync=args.full,
            ).as_dict()
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (NetworkDatasetDenied, NetworkDatasetPolicyError, OSError, json.JSONDecodeError) as exc:
        reason = getattr(exc, "reason_code", exc.__class__.__name__)
        print(
            json.dumps(
                {"allowed": False, "reason_code": reason, "error": str(exc)},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
