from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from zoneinfo import ZoneInfo

from .agents import DailyReportAgent, PresentationAgent, ResearchAgent
from .artifacts import ArtifactManager
from .config import AppConfig, legacy_model_policy
from .gateways import ExecutionGateway, InternetGateway
from .knowledge_gateway import KnowledgeGateway
from .llm import AdaptiveOllamaClient, OllamaClient
from .store import TaskStore
from .web_research import WebResearchClient
from .workflow import WorkflowRunner

TZ = ZoneInfo("Asia/Tokyo")


class Orchestrator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.store = TaskStore(config.database_path)
        self.artifacts = ArtifactManager(config.artifact_root)
        self.internet_gateway = InternetGateway(config.internet_gateway, config.test_mode_full_access)
        self.execution_gateway = ExecutionGateway(config.execution_gateway, config.test_mode_full_access)
        self.web_research = WebResearchClient(self.internet_gateway)
        self.knowledge_gateway = KnowledgeGateway(config.artifact_root, self.web_research)

        policy = config.model_policy or legacy_model_policy(config.llm)
        self.model_policy = policy
        if policy.enabled:
            research_primary = OllamaClient(replace(config.llm, model=policy.research_model))
            presentation_primary = OllamaClient(replace(config.llm, model=policy.presentation_model))
            report_primary = OllamaClient(replace(config.llm, model=policy.report_model))
            deep = OllamaClient(replace(config.llm, model=policy.deep_model)) if policy.deep_model else None
            self.research_llm = AdaptiveOllamaClient(
                research_primary,
                deep=deep,
                deep_escalation=policy.deep_escalation,
                deep_prompt_chars=policy.deep_prompt_chars,
                role="research",
            )
            self.presentation_llm = AdaptiveOllamaClient(
                presentation_primary,
                deep=deep,
                deep_escalation=policy.deep_escalation,
                deep_prompt_chars=policy.deep_prompt_chars,
                role="presentation",
            )
            self.report_llm = AdaptiveOllamaClient(
                report_primary,
                deep=None,
                deep_escalation=False,
                role="daily_report",
            )
        else:
            shared = OllamaClient(config.llm)
            self.research_llm = shared
            self.presentation_llm = shared
            self.report_llm = shared

        self.llm = self.research_llm
        self.research_agent = ResearchAgent(
            config.profile_root,
            self.research_llm,
            self.web_research,
            self.knowledge_gateway,
        )
        self.presentation_agent = PresentationAgent(config.profile_root, self.presentation_llm)
        self.daily_agent = DailyReportAgent(config.profile_root, self.report_llm)
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
            "reports",
            "uploads",
        ):
            (self.config.artifact_root / category).mkdir(parents=True, exist_ok=True)

    def smoke(self) -> dict:
        self.initialize()
        policy = self.model_policy
        return {
            "database": str(self.config.database_path),
            "artifact_root": str(self.config.artifact_root),
            "test_mode_full_access": self.config.test_mode_full_access,
            "llm_provider": self.config.llm.provider,
            "llm_base_url": self.config.llm.base_url,
            "llm_model_configured": bool(self.config.llm.model),
            "model_policy_enabled": policy.enabled,
            "model_keep_alive": self.config.llm.keep_alive,
            "research_model": policy.research_model if policy.enabled else self.config.llm.model,
            "presentation_model": policy.presentation_model if policy.enabled else self.config.llm.model,
            "report_model": policy.report_model if policy.enabled else self.config.llm.model,
            "deep_model": policy.deep_model if policy.enabled else self.config.llm.model,
            "deep_escalation": bool(policy.enabled and policy.deep_escalation),
            "research_web_enabled": self.config.internet_gateway.enabled,
            "knowledge_gateway_enabled": True,
            "upload_gateway_enabled": True,
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
