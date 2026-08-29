from __future__ import annotations

import argparse
import json

from .config import load_config
from .orchestrator import Orchestrator


def _add_presentation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--audience", default="R&D internal")
    parser.add_argument("--purpose", default="inform")
    parser.add_argument("--language", choices=("ja", "en", "vi"), default="ja")
    parser.add_argument("--slides", type=int, default=6, help="Target narrative slide count before deterministic appendices")
    parser.add_argument("--format", choices=("source", "pptx", "pdf", "all"), default="pptx")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace",
        description="WorkSpace — local-first AI runtime for confidential internal business work",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("smoke")

    workflow = sub.add_parser(
        "workflow-run",
        help="Create one task and run Research -> Presentation -> Daily Report end to end",
    )
    workflow.add_argument("--title", required=True)
    workflow.add_argument("--request", required=True)
    workflow.add_argument(
        "--live",
        action="store_true",
        help="Enable configured local-model generation and, only when policy permits, public web research.",
    )
    workflow.add_argument("--date", help="Daily-report date (YYYY-MM-DD); defaults to today in Asia/Tokyo")
    _add_presentation_options(workflow)

    create = sub.add_parser("task-create")
    create.add_argument("--title", required=True)
    create.add_argument("--request", required=True)

    sub.add_parser("task-list")
    status = sub.add_parser("status")
    status.add_argument("task_id")

    research = sub.add_parser("research")
    research.add_argument("task_id")
    research.add_argument("--live", action="store_true")

    presentation = sub.add_parser("presentation")
    presentation.add_argument("task_id")
    presentation.add_argument("--live", action="store_true")
    _add_presentation_options(presentation)

    daily = sub.add_parser("daily-report")
    daily.add_argument("--date")
    daily.add_argument("--live", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    orchestrator = Orchestrator(load_config())
    orchestrator.initialize()

    if args.command == "init":
        print("WorkSpace initialized")
    elif args.command == "smoke":
        print(json.dumps(orchestrator.smoke(), ensure_ascii=False, indent=2))
    elif args.command == "workflow-run":
        result = orchestrator.run_workflow(
            args.title,
            args.request,
            live=args.live,
            audience=args.audience,
            purpose=args.purpose,
            language=args.language,
            slide_count=args.slides,
            output_format=args.format,
            report_date=args.date,
        )
        print(json.dumps(orchestrator.workflow.result_dict(result), ensure_ascii=False, indent=2))
        if result.status == "completed":
            return 0
        if result.status == "blocked":
            return 2
        return 1
    elif args.command == "task-create":
        task = orchestrator.store.create_task(args.title, args.request)
        print(task.task_id)
    elif args.command == "task-list":
        for task in orchestrator.store.list_tasks():
            print(f"{task.task_id}\t{task.status.value}\t{task.title}")
    elif args.command == "status":
        task = orchestrator.store.get_task(args.task_id)
        print(json.dumps(task.__dict__ | {"status": task.status.value}, ensure_ascii=False, indent=2))
    elif args.command == "research":
        paths = orchestrator.research_agent.run(
            args.task_id, orchestrator.store, orchestrator.artifacts, live=args.live
        )
        print("\n".join(str(path) for path in paths))
    elif args.command == "presentation":
        paths = orchestrator.presentation_agent.run(
            args.task_id,
            orchestrator.store,
            orchestrator.artifacts,
            live=args.live,
            audience=args.audience,
            purpose=args.purpose,
            language=args.language,
            slide_count=args.slides,
            output_format=args.format,
        )
        print("\n".join(str(path) for path in paths))
        presentation_payload = json.loads(paths[0].read_text(encoding="utf-8"))
        for artifact_path in presentation_payload.get("generated_artifacts", {}).values():
            print(artifact_path)
    elif args.command == "daily-report":
        paths = orchestrator.daily_report(args.date, live=args.live)
        print("\n".join(str(path) for path in paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
