from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from .agents import DailyReportAgent, PresentationAgent, ResearchAgent
from .artifacts import ArtifactManager
from .config import AppConfig
from .llm import OllamaClient
from .store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")


class Orchestrator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.store = TaskStore(config.database_path)
        self.artifacts = ArtifactManager(config.artifact_root)
        self.llm = OllamaClient(config.llm)
        self.research_agent = ResearchAgent(config.profile_root, self.llm)
        self.presentation_agent = PresentationAgent(config.profile_root, self.llm)
        self.daily_agent = DailyReportAgent(config.profile_root, self.llm)

    def initialize(self) -> None:
        self.store.initialize()
        for category in ("research", "presentations", "activity", "daily_reports"):
            (self.config.artifact_root / category).mkdir(parents=True, exist_ok=True)

    def smoke(self) -> dict:
        self.initialize()
        return {
            "database": str(self.config.database_path),
            "artifact_root": str(self.config.artifact_root),
            "test_mode_full_access": self.config.test_mode_full_access,
            "llm_provider": self.config.llm.provider,
            "llm_base_url": self.config.llm.base_url,
            "llm_model_configured": bool(self.config.llm.model),
        }

    def daily_report(self, date: str | None = None, live: bool = False):
        target = date or datetime.now(TZ).strftime("%Y-%m-%d")
        return self.daily_agent.run(target, self.store, self.artifacts, live=live)
