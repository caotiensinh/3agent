from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    base_url: str
    model: str
    timeout_seconds: int
    keep_alive: str = "2m"


@dataclass(frozen=True)
class ModelPolicyConfig:
    enabled: bool
    fast_model: str
    research_model: str
    presentation_model: str
    report_model: str
    deep_model: str
    deep_escalation: bool
    deep_prompt_chars: int


@dataclass(frozen=True)
class GatewayConfig:
    enabled: bool
    allow_all: bool
    audit_log: Path


@dataclass(frozen=True)
class AppConfig:
    environment: str
    test_mode_full_access: bool
    database_path: Path
    artifact_root: Path
    profile_root: Path
    llm: LLMConfig
    internet_gateway: GatewayConfig
    execution_gateway: GatewayConfig
    raw: dict[str, Any]
    model_policy: ModelPolicyConfig | None = None


def _expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path)))


def _model_env(name: str, configured: str, fallback: str) -> str:
    return os.getenv(name, configured or fallback).strip()


def legacy_model_policy(llm: LLMConfig) -> ModelPolicyConfig:
    """Single-model compatibility policy for older configs/test fixtures."""
    return ModelPolicyConfig(
        enabled=False,
        fast_model=llm.model,
        research_model=llm.model,
        presentation_model=llm.model,
        report_model=llm.model,
        deep_model=llm.model,
        deep_escalation=False,
        deep_prompt_chars=14000,
    )


def load_config(path: str | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("THREE_AGENT_CONFIG", "config/test.example.json"))
    data = json.loads(config_path.read_text(encoding="utf-8"))

    llm_raw = data.get("llm", {})
    base_model = os.getenv("LOCAL_LLM_MODEL", llm_raw.get("model", "")).strip()
    policy_raw = data.get("model_policy", {})
    internet_raw = data.get("internet_gateway", {})
    execution_raw = data.get("execution_gateway", {})

    fast_model = _model_env("THREE_AGENT_FAST_MODEL", str(policy_raw.get("fast_model", "")), base_model)
    research_model = _model_env(
        "THREE_AGENT_RESEARCH_MODEL", str(policy_raw.get("research_model", "")), base_model
    )
    presentation_model = _model_env(
        "THREE_AGENT_PRESENTATION_MODEL", str(policy_raw.get("presentation_model", "")), fast_model or base_model
    )
    report_model = _model_env(
        "THREE_AGENT_REPORT_MODEL", str(policy_raw.get("report_model", "")), fast_model or base_model
    )
    deep_model = _model_env("THREE_AGENT_DEEP_MODEL", str(policy_raw.get("deep_model", "")), research_model)

    llm = LLMConfig(
        provider=llm_raw.get("provider", "ollama"),
        base_url=llm_raw.get("base_url", "http://127.0.0.1:11434").rstrip("/"),
        model=base_model,
        timeout_seconds=int(llm_raw.get("timeout_seconds", 1200)),
        keep_alive=os.getenv("THREE_AGENT_MODEL_KEEP_ALIVE", str(llm_raw.get("keep_alive", "2m"))),
    )
    policy = ModelPolicyConfig(
        enabled=bool(policy_raw.get("enabled", False)),
        fast_model=fast_model,
        research_model=research_model,
        presentation_model=presentation_model,
        report_model=report_model,
        deep_model=deep_model,
        deep_escalation=bool(policy_raw.get("deep_escalation", True)),
        deep_prompt_chars=max(2000, int(policy_raw.get("deep_prompt_chars", 14000))),
    )

    return AppConfig(
        environment=data.get("environment", "test"),
        test_mode_full_access=bool(data.get("test_mode_full_access", False)),
        database_path=_expand(data.get("database_path", "data/tasks.db")),
        artifact_root=_expand(data.get("artifact_root", "data")),
        profile_root=_expand(data.get("profile_root", "profiles")),
        llm=llm,
        internet_gateway=GatewayConfig(
            enabled=bool(internet_raw.get("enabled", True)),
            allow_all=bool(internet_raw.get("allow_all_outbound_in_test", False)),
            audit_log=_expand(internet_raw.get("audit_log", "data/activity/internet.jsonl")),
        ),
        execution_gateway=GatewayConfig(
            enabled=bool(execution_raw.get("enabled", True)),
            allow_all=bool(execution_raw.get("allow_all_commands_in_test", False)),
            audit_log=_expand(execution_raw.get("audit_log", "data/activity/execution.jsonl")),
        ),
        raw=data,
        model_policy=policy,
    )
