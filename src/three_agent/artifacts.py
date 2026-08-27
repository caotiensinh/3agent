from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Tokyo")


class ArtifactManager:
    def __init__(self, root: Path):
        self.root = Path(root)

    @staticmethod
    def today() -> str:
        return datetime.now(TZ).strftime("%Y-%m-%d")

    def write_task_artifact(self, category: str, task_id: str, payload: dict, markdown: str) -> tuple[Path, Path]:
        folder = self.root / category / self.today()
        folder.mkdir(parents=True, exist_ok=True)
        json_path = folder / f"{task_id}.json"
        md_path = folder / f"{task_id}.md"
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        md_path.write_text(markdown.rstrip() + "\n", encoding="utf-8")
        return json_path, md_path

    def write_daily_report(self, date: str, payload: dict, markdown: str) -> tuple[Path, Path]:
        folder = self.root / "daily_reports"
        folder.mkdir(parents=True, exist_ok=True)
        json_path = folder / f"{date}.json"
        md_path = folder / f"{date}.md"
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        md_path.write_text(markdown.rstrip() + "\n", encoding="utf-8")
        return json_path, md_path
