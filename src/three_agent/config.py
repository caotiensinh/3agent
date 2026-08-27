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


def _expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path)))


def load_config(path: str | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("THREE_AGENT_CONFIG", "config/test.example.json"))
    data = json.loads(config_path.read_text(encoding="utf-8"))

    model = os.getenv("LOCAL_LLM_MODEL", data.get("llm", {}).get("model", ""))
    llm_raw = data.get("llm", {})
    internet_raw = data.get("internet_gateway", {})
    execution_raw = data.get("execution_gateway", {})

    return AppConfig(
        environment=data.get("environment", "test"),
        test_mode_full_access=bool(data.get("test_mode_full_access", False)),
        database_path=_expand(data.get("database_path", "data/tasks.db")),
        artifact_root=_expand(data.get("artifact_root", "data")),
        profile_root=_expand(data.get("profile_root", "profiles")),
        llm=LLMConfig(
            provider=llm_raw.get("provider", "ollama"),
            base_url=llm_raw.get("base_url", "http://127.0.0.1:11434").rstrip("/"),
            model=model,
            timeout_seconds=int(llm_raw.get("timeout_seconds", 1200)),
        ),
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
    )
