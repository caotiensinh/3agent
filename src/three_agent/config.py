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
    resource_control_enabled: bool = True
    max_vram_percent: float = 90.0
    max_ram_percent: float = 90.0
    max_gpu_util_percent: float = 95.0
    max_gpu_power_percent: float = 95.0
    max_gpu_temp_c: float = 85.0
    max_balance_skew_percent: float = 10.0
    queue_wait_seconds: float = 120.0
    queue_poll_seconds: float = 1.0
    model_size_safety_factor: float = 1.15
    model_ram_overhead_factor: float = 0.15
    serialize_generation: bool = True
    reservation_ttl_seconds: int = 900


@dataclass(frozen=True)
class GatewayConfig:
    enabled: bool
    allow_all: bool
    audit_log: Path
    mode: str = "legacy_test"
    public_search_enabled: bool = False
    allowed_search_hosts: tuple[str, ...] = (
        "html.duckduckgo.com",
        "lite.duckduckgo.com",
        "www.bing.com",
    )
    allowed_content_hosts: tuple[str, ...] = ()
    max_response_bytes: int = 4 * 1024 * 1024
    max_query_chars: int = 240
    grant_ttl_seconds: int = 120
    broker_socket: Path | None = None
    direct_egress: bool = True
    broker_timeout_seconds: int = 60


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
    product_name: str = "WorkSpace"
    confidentiality_mode: str = "confidential"


def _expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path)))


def _env(primary: str, legacy: str | None, configured: Any, fallback: str = "") -> str:
    value = os.getenv(primary)
    if value is None and legacy:
        value = os.getenv(legacy)
    if value is None:
        value = configured if configured not in {None, ""} else fallback
    return str(value).strip()


def _float_env(primary: str, legacy: str | None, configured: Any, fallback: float) -> float:
    return float(_env(primary, legacy, configured, str(fallback)))


def _bool_env(primary: str, legacy: str | None, configured: Any, fallback: bool) -> bool:
    raw = os.getenv(primary)
    if raw is None and legacy:
        raw = os.getenv(legacy)
    if raw is None:
        return bool(configured if configured is not None else fallback)
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def legacy_model_policy(llm: LLMConfig) -> ModelPolicyConfig:
    return ModelPolicyConfig(
        enabled=False,
        fast_model=llm.model,
        research_model=llm.model,
        presentation_model=llm.model,
        report_model=llm.model,
        deep_model=llm.model,
        deep_escalation=False,
        deep_prompt_chars=14000,
        resource_control_enabled=False,
    )


def _config_path(path: str | None) -> Path:
    if path:
        return Path(path)
    configured = os.getenv("WORKSPACE_CONFIG") or os.getenv("THREE_AGENT_CONFIG")
    return Path(configured or "config/workspace.secure.json")


def load_config(path: str | None = None) -> AppConfig:
    config_path = _config_path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))

    llm_raw = data.get("llm", {})
    base_model = _env("WORKSPACE_LLM_MODEL", "LOCAL_LLM_MODEL", llm_raw.get("model", ""))
    policy_raw = data.get("model_policy", {})
    resource_raw = policy_raw.get("resource_control", {})
    internet_raw = data.get("internet_gateway", {})
    execution_raw = data.get("execution_gateway", {})

    fast_model = _env("WORKSPACE_FAST_MODEL", "THREE_AGENT_FAST_MODEL", policy_raw.get("fast_model", ""), base_model)
    research_model = _env("WORKSPACE_RESEARCH_MODEL", "THREE_AGENT_RESEARCH_MODEL", policy_raw.get("research_model", ""), base_model)
    presentation_model = _env("WORKSPACE_PRESENTATION_MODEL", "THREE_AGENT_PRESENTATION_MODEL", policy_raw.get("presentation_model", ""), fast_model or base_model)
    report_model = _env("WORKSPACE_REPORT_MODEL", "THREE_AGENT_REPORT_MODEL", policy_raw.get("report_model", ""), fast_model or base_model)
    deep_model = _env("WORKSPACE_DEEP_MODEL", "THREE_AGENT_DEEP_MODEL", policy_raw.get("deep_model", ""), research_model)

    llm = LLMConfig(
        provider=llm_raw.get("provider", "ollama"),
        base_url=llm_raw.get("base_url", "http://127.0.0.1:11434").rstrip("/"),
        model=base_model,
        timeout_seconds=int(llm_raw.get("timeout_seconds", 1200)),
        keep_alive=_env("WORKSPACE_MODEL_KEEP_ALIVE", "THREE_AGENT_MODEL_KEEP_ALIVE", llm_raw.get("keep_alive", "2m"), "2m"),
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
        resource_control_enabled=_bool_env("WORKSPACE_RESOURCE_CONTROL", "THREE_AGENT_RESOURCE_CONTROL", resource_raw.get("enabled"), True),
        max_vram_percent=min(90.0, max(50.0, _float_env("WORKSPACE_MAX_VRAM_PERCENT", "THREE_AGENT_MAX_VRAM_PERCENT", resource_raw.get("max_vram_percent"), 90.0))),
        max_ram_percent=min(95.0, max(50.0, _float_env("WORKSPACE_MAX_RAM_PERCENT", "THREE_AGENT_MAX_RAM_PERCENT", resource_raw.get("max_ram_percent"), 90.0))),
        max_gpu_util_percent=min(100.0, max(50.0, _float_env("WORKSPACE_MAX_GPU_UTIL_PERCENT", "THREE_AGENT_MAX_GPU_UTIL_PERCENT", resource_raw.get("max_gpu_util_percent"), 95.0))),
        max_gpu_power_percent=min(100.0, max(50.0, _float_env("WORKSPACE_MAX_GPU_POWER_PERCENT", "THREE_AGENT_MAX_GPU_POWER_PERCENT", resource_raw.get("max_gpu_power_percent"), 95.0))),
        max_gpu_temp_c=max(60.0, _float_env("WORKSPACE_MAX_GPU_TEMP_C", "THREE_AGENT_MAX_GPU_TEMP_C", resource_raw.get("max_gpu_temp_c"), 85.0)),
        max_balance_skew_percent=min(50.0, max(0.0, _float_env("WORKSPACE_MAX_BALANCE_SKEW_PERCENT", "THREE_AGENT_MAX_BALANCE_SKEW_PERCENT", resource_raw.get("max_balance_skew_percent"), 10.0))),
        queue_wait_seconds=max(0.0, _float_env("WORKSPACE_GPU_QUEUE_WAIT_SECONDS", "THREE_AGENT_GPU_QUEUE_WAIT_SECONDS", resource_raw.get("queue_wait_seconds"), 120.0)),
        queue_poll_seconds=max(0.05, _float_env("WORKSPACE_GPU_QUEUE_POLL_SECONDS", "THREE_AGENT_GPU_QUEUE_POLL_SECONDS", resource_raw.get("queue_poll_seconds"), 1.0)),
        model_size_safety_factor=max(1.0, _float_env("WORKSPACE_MODEL_SIZE_SAFETY_FACTOR", "THREE_AGENT_MODEL_SIZE_SAFETY_FACTOR", resource_raw.get("model_size_safety_factor"), 1.15)),
        model_ram_overhead_factor=min(1.0, max(0.0, _float_env("WORKSPACE_MODEL_RAM_OVERHEAD_FACTOR", "THREE_AGENT_MODEL_RAM_OVERHEAD_FACTOR", resource_raw.get("model_ram_overhead_factor"), 0.15))),
        serialize_generation=_bool_env("WORKSPACE_SERIALIZE_GENERATION", "THREE_AGENT_SERIALIZE_GENERATION", resource_raw.get("serialize_generation"), True),
        reservation_ttl_seconds=max(30, int(resource_raw.get("reservation_ttl_seconds", 900))),
    )

    gateway_mode = str(internet_raw.get("mode", "strict")).strip().lower()
    if gateway_mode not in {"strict", "legacy_test"}:
        raise ValueError("internet_gateway.mode must be strict or legacy_test")

    return AppConfig(
        environment=data.get("environment", "secure-local"),
        test_mode_full_access=bool(data.get("test_mode_full_access", False)),
        database_path=_expand(data.get("database_path", "data/tasks.db")),
        artifact_root=_expand(data.get("artifact_root", "data")),
        profile_root=_expand(data.get("profile_root", "profiles")),
        llm=llm,
        internet_gateway=GatewayConfig(
            enabled=bool(internet_raw.get("enabled", True)),
            allow_all=bool(internet_raw.get("allow_all_outbound_in_test", False)),
            audit_log=_expand(internet_raw.get("audit_log", "data/activity/internet.jsonl")),
            mode=gateway_mode,
            public_search_enabled=bool(internet_raw.get("public_search_enabled", False)),
            allowed_search_hosts=tuple(str(x).casefold() for x in internet_raw.get("allowed_search_hosts", ["html.duckduckgo.com", "lite.duckduckgo.com", "www.bing.com"])),
            allowed_content_hosts=tuple(str(x).casefold() for x in internet_raw.get("allowed_content_hosts", [])),
            max_response_bytes=max(65536, min(8 * 1024 * 1024, int(internet_raw.get("max_response_bytes", 4 * 1024 * 1024)))),
            max_query_chars=max(32, min(512, int(internet_raw.get("max_query_chars", 240)))),
            grant_ttl_seconds=max(10, min(600, int(internet_raw.get("grant_ttl_seconds", 120)))),
            broker_socket=(
                _expand(str(internet_raw["broker_socket"]))
                if internet_raw.get("broker_socket")
                else None
            ),
            direct_egress=bool(internet_raw.get("direct_egress", False)),
            broker_timeout_seconds=max(5, min(300, int(internet_raw.get("broker_timeout_seconds", 60)))),
        ),
        execution_gateway=GatewayConfig(
            enabled=bool(execution_raw.get("enabled", True)),
            allow_all=bool(execution_raw.get("allow_all_commands_in_test", False)),
            audit_log=_expand(execution_raw.get("audit_log", "data/activity/execution.jsonl")),
        ),
        raw=data,
        model_policy=policy,
        product_name=str(data.get("product_name", "WorkSpace")),
        confidentiality_mode=str(data.get("confidentiality_mode", "confidential")),
    )
