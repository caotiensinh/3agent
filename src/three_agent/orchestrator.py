from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime
from zoneinfo import ZoneInfo

from .agents import DailyReportAgent, PresentationAgent, ResearchAgent
from .artifacts import ArtifactManager
from .config import AppConfig, legacy_model_policy
from .gateways import ExecutionGateway, InternetGateway
from .knowledge_gateway import KnowledgeGateway
from .llm import AdaptiveOllamaClient, OllamaClient
from .resource_budget import ResourceBudgetConfig, ResourceBudgetManager
from .store import TaskStore
from .web_research import WebResearchClient
from .worker_pool import OllamaWorkerPool
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
        self.inference_telemetry_path = os.getenv(
            "WORKSPACE_INFERENCE_TELEMETRY",
            str(config.artifact_root / "activity" / "inference.jsonl"),
        )
        os.environ.setdefault("WORKSPACE_INFERENCE_TELEMETRY", self.inference_telemetry_path)

        policy = config.model_policy or legacy_model_policy(config.llm)
        self.model_policy = policy
        resource_config = ResourceBudgetConfig(
            enabled=True,
            max_vram_percent=policy.max_vram_percent,
            max_ram_percent=policy.max_ram_percent,
            max_gpu_util_percent=policy.max_gpu_util_percent,
            max_gpu_power_percent=policy.max_gpu_power_percent,
            max_gpu_temp_c=policy.max_gpu_temp_c,
            max_balance_skew_percent=policy.max_balance_skew_percent,
            queue_wait_seconds=policy.queue_wait_seconds,
            queue_poll_seconds=policy.queue_poll_seconds,
            model_size_safety_factor=policy.model_size_safety_factor,
            model_ram_overhead_factor=policy.model_ram_overhead_factor,
            serialize_generation=policy.serialize_generation,
            reservation_ttl_seconds=policy.reservation_ttl_seconds,
        )

        raw_policy = config.raw.get("model_policy", {}) if isinstance(config.raw, dict) else {}
        raw_workers = raw_policy.get("worker_pool", {}) if isinstance(raw_policy, dict) else {}
        self.worker_pool_enabled = bool(raw_workers.get("enabled", False)) and policy.enabled
        self.worker_urls = {
            "gpu0": os.getenv(
                "THREE_AGENT_GPU0_OLLAMA_URL",
                str(raw_workers.get("gpu0_url", "http://127.0.0.1:11435")),
            ).rstrip("/"),
            "gpu1": os.getenv(
                "THREE_AGENT_GPU1_OLLAMA_URL",
                str(raw_workers.get("gpu1_url", "http://127.0.0.1:11436")),
            ).rstrip("/"),
            "dual": os.getenv(
                "THREE_AGENT_DUAL_OLLAMA_URL",
                str(raw_workers.get("dual_url", config.llm.base_url)),
            ).rstrip("/"),
        }

        self.resource_manager = None
        if policy.enabled and policy.resource_control_enabled and not self.worker_pool_enabled:
            self.resource_manager = ResourceBudgetManager(config.llm.base_url, resource_config)

        if policy.enabled:
            if self.worker_pool_enabled:
                def routed(model: str):
                    return OllamaWorkerPool(
                        replace(config.llm, model=model),
                        resource_config,
                        gpu0_url=self.worker_urls["gpu0"],
                        gpu1_url=self.worker_urls["gpu1"],
                        dual_url=self.worker_urls["dual"],
                    )

                research_primary = routed(policy.research_model)
                presentation_primary = routed(policy.presentation_model)
                report_primary = routed(policy.report_model)
                deep = routed(policy.deep_model) if policy.deep_model else None
            else:
                research_primary = OllamaClient(
                    replace(config.llm, model=policy.research_model),
                    self.resource_manager,
                )
                presentation_primary = OllamaClient(
                    replace(config.llm, model=policy.presentation_model),
                    self.resource_manager,
                )
                report_primary = OllamaClient(
                    replace(config.llm, model=policy.report_model),
                    self.resource_manager,
                )
                deep = (
                    OllamaClient(
                        replace(config.llm, model=policy.deep_model),
                        self.resource_manager,
                    )
                    if policy.deep_model
                    else None
                )
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
            if policy.resource_control_enabled:
                self.research_llm.budget_managed_residency = True
                self.presentation_llm.budget_managed_residency = True
                self.report_llm.budget_managed_residency = True
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
            "resource_control_enabled": bool(policy.enabled and policy.resource_control_enabled),
            "resource_control_scope": "per_gpu",
            "max_vram_percent": policy.max_vram_percent,
            "max_vram_percent_per_gpu": policy.max_vram_percent,
            "max_ram_percent": policy.max_ram_percent,
            "max_gpu_util_percent": policy.max_gpu_util_percent,
            "gpu_busy_threshold_percent": policy.max_gpu_util_percent,
            "max_gpu_power_percent": policy.max_gpu_power_percent,
            "max_gpu_temp_c": policy.max_gpu_temp_c,
            "balance_skew_target_percent": policy.max_balance_skew_percent,
            "gpu_queue_wait_seconds": policy.queue_wait_seconds,
            "model_ram_overhead_factor": policy.model_ram_overhead_factor,
            "serialize_generation": policy.serialize_generation,
            "fixed_model_count_limit": False,
            "worker_pool_enabled": self.worker_pool_enabled,
            "worker_gpu0_url": self.worker_urls["gpu0"],
            "worker_gpu1_url": self.worker_urls["gpu1"],
            "worker_dual_url": self.worker_urls["dual"],
            "research_web_enabled": self.config.internet_gateway.enabled,
            "knowledge_gateway_enabled": True,
            "upload_gateway_enabled": True,
            "e2e_workflow_enabled": True,
            "structured_output_mode": "ollama_native_json_schema",
            "inference_telemetry": self.inference_telemetry_path,
            "inference_telemetry_raw_prompt": False,
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
