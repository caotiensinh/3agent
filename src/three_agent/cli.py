from __future__ import annotations

import argparse
import json

from .config import load_config
from .orchestrator import Orchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="three-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("smoke")

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

    daily = sub.add_parser("daily-report")
    daily.add_argument("--date")
    daily.add_argument("--live", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    orchestrator = Orchestrator(load_config())
    orchestrator.initialize()

    if args.command == "init":
        print("3Agent initialized")
    elif args.command == "smoke":
        print(json.dumps(orchestrator.smoke(), ensure_ascii=False, indent=2))
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
        paths = orchestrator.research_agent.run(args.task_id, orchestrator.store, orchestrator.artifacts, live=args.live)
        print("\n".join(str(p) for p in paths))
    elif args.command == "presentation":
        paths = orchestrator.presentation_agent.run(args.task_id, orchestrator.store, orchestrator.artifacts, live=args.live)
        print("\n".join(str(p) for p in paths))
    elif args.command == "daily-report":
        paths = orchestrator.daily_report(args.date, live=args.live)
        print("\n".join(str(p) for p in paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
