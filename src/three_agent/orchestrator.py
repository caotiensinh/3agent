from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from .agents import DailyReportAgent, PresentationAgent, ResearchAgent
from .artifacts import ArtifactManager
from .config import AppConfig
from .gateways import ExecutionGateway, InternetGateway
from .llm import OllamaClient
from .store import TaskStore
from .web_research import WebResearchClient
from .workflow import WorkflowRunner

TZ = ZoneInfo("Asia/Tokyo")


class Orchestrator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.store = TaskStore(config.database_path)
        self.artifacts = ArtifactManager(config.artifact_root)
        self.llm = OllamaClient(config.llm)
        self.internet_gateway = InternetGateway(config.internet_gateway, config.test_mode_full_access)
        self.execution_gateway = ExecutionGateway(config.execution_gateway, config.test_mode_full_access)
        self.web_research = WebResearchClient(self.internet_gateway)
        self.research_agent = ResearchAgent(config.profile_root, self.llm, self.web_research)
        self.presentation_agent = PresentationAgent(config.profile_root, self.llm)
        self.daily_agent = DailyReportAgent(config.profile_root, self.llm)
        self.workflow = WorkflowRunner(
            self.store,
            self.artifacts,
            self.research_agent,
            self.presentation_agent,
            self.daily_agent,
        )

    def initialize(self) -> None:
        self.store.initialize()
        for category in (
            "research",
            "presentations",
            "activity",
            "daily_reports",
            "workflow_runs",
        ):
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
            "research_web_enabled": self.config.internet_gateway.enabled,
            "e2e_workflow_enabled": True,
        }

    def run_workflow(
        self,
        title: str,
        request: str,
        *,
        live: bool = False,
        audience: str = "R&D internal",
        purpose: str = "inform",
        language: str = "ja",
        slide_count: int = 6,
        output_format: str = "pptx",
        report_date: str | None = None,
    ):
        return self.workflow.create_and_run(
            title,
            request,
            live=live,
            audience=audience,
            purpose=purpose,
            language=language,
            slide_count=slide_count,
            output_format=output_format,
            report_date=report_date,
        )

    def daily_report(self, date: str | None = None, live: bool = False):
        target = date or datetime.now(TZ).strftime("%Y-%m-%d")
        return self.daily_agent.run(target, self.store, self.artifacts, live=live)
