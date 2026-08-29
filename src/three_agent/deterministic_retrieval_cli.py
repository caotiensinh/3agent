from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .artifacts import ArtifactManager
from .config import load_config
from .deterministic_retrieval import DeterministicRetrievalExecutor
from .store import TaskStore


def _default_knowledge_root(config) -> Path:
    configured = os.getenv("WORKSPACE_PUBLIC_KNOWLEDGE_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser()
    raw = config.raw.get("knowledge", {}) if isinstance(config.raw, dict) else {}
    value = raw.get("public_mirror_root") if isinstance(raw, dict) else None
    return Path(str(value or "/var/lib/workspace-knowledge-public")).expanduser()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-retrieval",
        description="Verified deterministic local retrieval with zero LLM inference",
    )
    parser.add_argument("--title", required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--config", help="Optional WorkSpace config path")
    parser.add_argument("--knowledge-root", help="Imported local public-knowledge mirror")
    parser.add_argument(
        "--sensitivity",
        choices=("public", "internal", "confidential", "restricted", "secret"),
        default="confidential",
    )
    parser.add_argument(
        "--risk-level",
        choices=("low", "medium", "high", "critical"),
        default="low",
    )
    parser.add_argument("--max-hits", type=int, default=8)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        store = TaskStore(config.database_path)
        store.initialize()
        knowledge_root = (
            Path(args.knowledge_root).expanduser()
            if args.knowledge_root
            else _default_knowledge_root(config)
        )
        result = DeterministicRetrievalExecutor(
            store,
            ArtifactManager(config.artifact_root),
            knowledge_root,
        ).run(
            args.title,
            args.query,
            sensitivity=args.sensitivity,
            risk_level=args.risk_level,
            max_hits=args.max_hits,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": "workspace-deterministic-retrieval/v1",
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3

    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    if result.status == "completed":
        return 0
    if result.status == "blocked":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
