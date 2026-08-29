from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .context_engine import ContextEngine
from .knowledge_plane import (
    InboundKnowledgeImporter,
    LocalKnowledgeIndex,
    PublicEvidenceExporter,
)
from .task_contract import TaskContractCompiler


def _default_outbox() -> Path:
    return Path(os.getenv("WORKSPACE_PUBLIC_EXPORT_ROOT", "/var/spool/workspace-public-export"))


def _default_knowledge_root() -> Path:
    return Path(os.getenv("WORKSPACE_PUBLIC_KNOWLEDGE_ROOT", "/var/lib/workspace-knowledge-public"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-knowledge",
        description="WorkSpace one-way public knowledge ingestion and deterministic context tooling",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export")
    export.add_argument("--research-json", required=True)
    export.add_argument("--outbox", default=str(_default_outbox()))

    ingest = sub.add_parser("import")
    ingest.add_argument("--bundle", required=True)
    ingest.add_argument("--knowledge-root", default=str(_default_knowledge_root()))

    mapping = sub.add_parser("map")
    mapping.add_argument("--knowledge-root", default=str(_default_knowledge_root()))

    search = sub.add_parser("search")
    search.add_argument("--query", required=True)
    search.add_argument("--knowledge-root", default=str(_default_knowledge_root()))
    search.add_argument("--max-hits", type=int, default=5)
    search.add_argument("--max-chars", type=int, default=20000)

    pack = sub.add_parser("pack")
    pack.add_argument("--query", required=True)
    pack.add_argument("--knowledge-root", default=str(_default_knowledge_root()))
    pack.add_argument("--task-id", default="task:knowledge:local")
    pack.add_argument(
        "--sensitivity",
        choices=("public", "internal", "confidential", "restricted", "secret"),
        default="confidential",
    )
    pack.add_argument("--risk-level", choices=("low", "medium", "high", "critical"), default="low")
    pack.add_argument("--max-hits", type=int, default=5)

    contract = sub.add_parser("contract")
    contract.add_argument("--task-id", required=True)
    contract.add_argument(
        "--task-type",
        choices=("code_fix", "code_review", "doc_summary", "sensitive_query", "retrieval", "classification", "analysis", "general"),
        default="general",
    )
    contract.add_argument(
        "--sensitivity",
        choices=("public", "internal", "confidential", "restricted", "secret"),
        default="internal",
    )
    contract.add_argument("--risk-level", choices=("low", "medium", "high", "critical"), default="low")
    contract.add_argument("--public-web", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "export":
        payload = json.loads(Path(args.research_json).read_text(encoding="utf-8"))
        path = PublicEvidenceExporter(Path(args.outbox)).export_research_payload(payload)
        print(path)
        return 0

    if args.command == "import":
        path = InboundKnowledgeImporter(Path(args.knowledge_root)).import_bundle(Path(args.bundle))
        print(path)
        return 0

    if args.command == "map":
        print(
            json.dumps(
                LocalKnowledgeIndex(Path(args.knowledge_root)).map(),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "search":
        hits = LocalKnowledgeIndex(Path(args.knowledge_root)).search(
            args.query,
            max_hits=max(1, min(20, args.max_hits)),
            max_chars=max(1, min(200_000, args.max_chars)),
        )
        print(json.dumps([hit.to_dict() for hit in hits], ensure_ascii=False, indent=2))
        return 0

    if args.command == "pack":
        contract = TaskContractCompiler().compile(
            task_id=args.task_id,
            task_type="retrieval",
            sensitivity=args.sensitivity,
            risk_level=args.risk_level,
        )
        packed = ContextEngine(LocalKnowledgeIndex(Path(args.knowledge_root))).build_public_evidence(
            args.query,
            contract,
            max_hits=max(1, min(20, args.max_hits)),
        )
        print(json.dumps(packed.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "contract":
        contract = TaskContractCompiler().compile(
            task_id=args.task_id,
            task_type=args.task_type,
            sensitivity=args.sensitivity,
            risk_level=args.risk_level,
            public_web=args.public_web,
        )
        print(json.dumps(contract.to_dict(), ensure_ascii=False, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
