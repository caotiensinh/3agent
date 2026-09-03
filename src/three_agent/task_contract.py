from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

TASK_TYPES = {
    "code_fix",
    "code_review",
    "doc_summary",
    "sensitive_query",
    "retrieval",
    "classification",
    "analysis",
    "general",
}
SENSITIVITIES = {"public", "internal", "confidential", "restricted", "secret"}
RISK_LEVELS = {"low", "medium", "high", "critical"}
MODEL_TIERS = {"none", "small", "specialist", "strong"}
TOOLS = {
    "read_file",
    "search_repo",
    "search_docs",
    "write_staging",
    "apply_patch",
    "run_linter",
    "run_tests",
    "query_db_readonly",
    "calculator",
    "web_gateway",
}
VALIDATORS = {
    "policy",
    "schema",
    "syntax",
    "lint",
    "unit_test",
    "integration_test",
    "evidence",
    "secondary_model",
    "human",
}


class TaskContractError(ValueError):
    """A request cannot be represented by the WorkSpace execution contract."""


@dataclass(frozen=True)
class ContextBudget:
    max_input_tokens: int
    max_retrieved_tokens: int
    max_tool_output_tokens: int
    reserve_tokens: int = 1024


@dataclass(frozen=True)
class GenerationBudget:
    max_output_tokens: int


@dataclass(frozen=True)
class ExecutionBudget:
    max_steps: int
    max_tool_calls: int
    max_retries: int
    max_escalations: int
    max_wall_time_ms: int


@dataclass(frozen=True)
class ModelPolicy:
    initial_tier: str
    max_tier: str
    escalation_allowed: bool
    confidence_floor: float
    trusted_local_only: bool = True


@dataclass(frozen=True)
class CachePolicy:
    mode: str
    trust_domain: str
    semantic_cache_allowed: bool
    ttl_seconds: int


@dataclass(frozen=True)
class LoggingPolicy:
    raw_prompt: str
    raw_tool_output: str
    retain_days: int


@dataclass(frozen=True)
class TaskContract:
    task_id: str
    task_type: str
    sensitivity: str
    risk_level: str
    allowed_sources: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    write_scope: str | tuple[str, ...]
    network_scope: str
    context_budget: ContextBudget
    generation_budget: GenerationBudget
    execution_budget: ExecutionBudget
    evidence_required: bool
    validators: tuple[str, ...]
    model_policy: ModelPolicy
    cache_policy: CachePolicy
    logging_policy: LoggingPolicy
    output_schema: dict | None = None
    schema_version: str = "workspace-task-contract/v1"
    policy_reason_codes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        payload = asdict(self)
        if isinstance(self.write_scope, tuple):
            payload["write_scope"] = list(self.write_scope)
        payload["allowed_sources"] = list(self.allowed_sources)
        payload["allowed_tools"] = list(self.allowed_tools)
        payload["validators"] = list(self.validators)
        payload["policy_reason_codes"] = list(self.policy_reason_codes)
        return payload

    def validate(self) -> "TaskContract":
        if not self.task_id or len(self.task_id) > 128:
            raise TaskContractError("task_id is required and must be <= 128 characters")
        if self.task_type not in TASK_TYPES:
            raise TaskContractError(f"unsupported task_type: {self.task_type}")
        if self.sensitivity not in SENSITIVITIES:
            raise TaskContractError(f"unsupported sensitivity: {self.sensitivity}")
        if self.risk_level not in RISK_LEVELS:
            raise TaskContractError(f"unsupported risk_level: {self.risk_level}")
        unknown_tools = set(self.allowed_tools) - TOOLS
        if unknown_tools:
            raise TaskContractError(f"unknown tools: {sorted(unknown_tools)}")
        unknown_validators = set(self.validators) - VALIDATORS
        if unknown_validators:
            raise TaskContractError(f"unknown validators: {sorted(unknown_validators)}")
        if self.network_scope not in {"deny", "internal_only", "allowlisted_egress"}:
            raise TaskContractError(f"unsupported network_scope: {self.network_scope}")
        if self.model_policy.initial_tier not in MODEL_TIERS or self.model_policy.max_tier not in MODEL_TIERS:
            raise TaskContractError("invalid model tier")
        tier_order = {"none": 0, "small": 1, "specialist": 2, "strong": 3}
        if tier_order[self.model_policy.initial_tier] > tier_order[self.model_policy.max_tier]:
            raise TaskContractError("initial model tier exceeds max tier")
        if not 0.0 <= self.model_policy.confidence_floor <= 1.0:
            raise TaskContractError("confidence_floor must be within [0,1]")
        if self.model_policy.initial_tier == "none":
            if self.model_policy.max_tier != "none":
                raise TaskContractError("NO_LLM tasks require max_tier=none")
            if self.model_policy.escalation_allowed:
                raise TaskContractError("NO_LLM tasks cannot allow model escalation")

        cb = self.context_budget
        if min(cb.max_input_tokens, cb.reserve_tokens) < 0:
            raise TaskContractError("context budgets must be non-negative")
        if cb.max_input_tokens < 256:
            raise TaskContractError("max_input_tokens must be >= 256")
        if cb.max_retrieved_tokens < 0 or cb.max_tool_output_tokens < 0:
            raise TaskContractError("retrieval/tool budgets cannot be negative")
        if self.generation_budget.max_output_tokens < 1:
            raise TaskContractError("max_output_tokens must be >= 1")

        eb = self.execution_budget
        if eb.max_steps < 1 or eb.max_tool_calls < 0 or eb.max_retries < 0 or eb.max_escalations < 0:
            raise TaskContractError("execution budgets are invalid")
        if eb.max_wall_time_ms < 100:
            raise TaskContractError("max_wall_time_ms must be >= 100")
        if self.model_policy.initial_tier == "none" and eb.max_escalations != 0:
            raise TaskContractError("NO_LLM tasks require max_escalations=0")

        if self.cache_policy.mode not in {"deny", "exact_only", "prefix_allowed", "kv_allowed"}:
            raise TaskContractError("invalid cache mode")
        if not self.cache_policy.trust_domain:
            raise TaskContractError("cache trust_domain is required")
        if self.logging_policy.raw_prompt not in {"deny", "redacted", "allow"}:
            raise TaskContractError("invalid raw_prompt logging policy")
        if self.logging_policy.raw_tool_output not in {"deny", "redacted", "allow"}:
            raise TaskContractError("invalid raw_tool_output logging policy")

        # Public Internet access is a capability, never a declassification. Internal,
        # confidential and restricted tasks may use it only through web_gateway with
        # allowlisted egress; the four-level Internet Egress Policy still decides the
        # actual outbound query. Secret tasks remain fully network denied in v1.
        if self.sensitivity == "secret" and self.network_scope != "deny":
            raise TaskContractError("secret tasks require network_scope=deny")
        if self.network_scope == "allowlisted_egress" and "web_gateway" not in self.allowed_tools:
            raise TaskContractError("allowlisted egress requires web_gateway")
        if "web_gateway" in self.allowed_tools and self.network_scope != "allowlisted_egress":
            raise TaskContractError("web_gateway requires network_scope=allowlisted_egress")
        if self.sensitivity == "secret" and "web_gateway" in self.allowed_tools:
            raise TaskContractError("secret tasks cannot use web_gateway")
        if self.sensitivity in {"restricted", "secret"}:
            if self.logging_policy.raw_prompt != "deny" or self.logging_policy.raw_tool_output != "deny":
                raise TaskContractError("restricted/secret tasks cannot log raw content")
            if self.cache_policy.semantic_cache_allowed:
                raise TaskContractError("restricted/secret tasks cannot use semantic answer cache")
        if self.sensitivity == "secret" and self.cache_policy.mode not in {"deny", "exact_only"}:
            raise TaskContractError("secret tasks cannot use shared prefix/KV cache")
        return self


class TaskContractCompiler:
    """Deterministic v1 compiler.

    This compiler intentionally uses auditable rules rather than an LLM. A learned
    classifier may later recommend a capability tier, but it cannot weaken these
    security or budget decisions.

    `deterministic_only=True` is deliberately narrow: v1 permits it only for local
    retrieval. It reduces model authority to `none`; it can never grant extra
    network/tool/write authority or bypass required evidence validation.
    """

    @staticmethod
    def _unique(values: Iterable[str]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(v).strip() for v in values if str(v).strip()))

    def compile(
        self,
        *,
        task_id: str,
        task_type: str = "general",
        sensitivity: str = "internal",
        risk_level: str = "low",
        allowed_sources: Iterable[str] = (),
        allowed_tools: Iterable[str] | None = None,
        write_scope: str | Iterable[str] = "none",
        public_web: bool = False,
        output_schema: dict | None = None,
        deterministic_only: bool = False,
    ) -> TaskContract:
        task_type = str(task_type).strip().lower()
        sensitivity = str(sensitivity).strip().lower()
        risk_level = str(risk_level).strip().lower()
        if task_type not in TASK_TYPES:
            raise TaskContractError(f"unsupported task_type: {task_type}")
        if sensitivity not in SENSITIVITIES:
            raise TaskContractError(f"unsupported sensitivity: {sensitivity}")
        if risk_level not in RISK_LEVELS:
            raise TaskContractError(f"unsupported risk_level: {risk_level}")
        if deterministic_only:
            if task_type != "retrieval":
                raise TaskContractError("NO_LLM v1 is supported only for task_type=retrieval")
            if public_web:
                raise TaskContractError("NO_LLM retrieval cannot enable public web egress")
            if output_schema is not None:
                raise TaskContractError("NO_LLM retrieval does not accept model output schemas")

        reasons: list[str] = [f"SENSITIVITY_{sensitivity.upper()}", f"TASK_{task_type.upper()}"]
        tools = list(allowed_tools or ())
        if not tools:
            if task_type in {"doc_summary", "retrieval", "analysis", "general"}:
                tools = ["search_docs", "read_file"]
            elif task_type in {"code_fix", "code_review"}:
                tools = ["search_repo", "read_file", "run_linter", "run_tests"]
                if task_type == "code_fix":
                    tools.extend(["write_staging", "apply_patch"])
            elif task_type == "classification":
                tools = []
            elif task_type == "sensitive_query":
                tools = ["search_docs", "query_db_readonly"]
        if deterministic_only:
            forbidden = set(tools) - {"search_docs", "read_file"}
            if forbidden:
                raise TaskContractError(
                    f"NO_LLM retrieval has unsupported tools: {sorted(forbidden)}"
                )

        # Network/data placement is resolved before capability/model selection.
        network_scope = "deny"
        if public_web:
            if sensitivity == "secret":
                raise TaskContractError(
                    "secret tasks remain network-denied; use restricted with sanitized research when abstraction is permitted"
                )
            network_scope = "allowlisted_egress"
            if "web_gateway" not in tools:
                tools.append("web_gateway")
            reasons.append(f"SANITIZED_{sensitivity.upper()}_ALLOWLISTED_EGRESS")
        elif sensitivity in {"restricted", "internal"}:
            network_scope = "internal_only"

        if deterministic_only:
            initial_tier, max_tier = "none", "none"
            reasons.append("NO_LLM_DETERMINISTIC_LOCAL_RETRIEVAL")
        elif task_type in {"classification"}:
            initial_tier, max_tier = "small", "specialist"
            reasons.append("SMALL_STRUCTURED_TASK")
        elif task_type in {"doc_summary", "retrieval"}:
            initial_tier, max_tier = "small", "specialist"
            reasons.append("SMALL_FIRST")
        elif task_type in {"code_fix", "code_review", "sensitive_query", "analysis"}:
            initial_tier, max_tier = "specialist", "strong"
            reasons.append("SPECIALIST_FIRST")
        else:
            initial_tier, max_tier = "small", "strong"
            reasons.append("SMALL_FIRST")

        evidence_required = task_type in {"doc_summary", "retrieval", "sensitive_query", "analysis"} or risk_level in {
            "high",
            "critical",
        }
        validators: list[str] = ["policy"]
        if output_schema:
            validators.append("schema")
        if task_type in {"code_fix", "code_review"}:
            validators.extend(["syntax", "lint", "unit_test"])
        if evidence_required:
            validators.append("evidence")
        if risk_level in {"high", "critical"}:
            validators.append("human")

        if sensitivity in {"restricted", "secret"}:
            cache = CachePolicy("deny", f"{sensitivity}:task:{task_id}", False, 0)
            logging = LoggingPolicy("deny", "deny", 90)
        elif sensitivity == "confidential":
            cache = CachePolicy("exact_only", f"task:{task_id}", False, 3600)
            logging = LoggingPolicy("deny", "redacted", 30)
        elif sensitivity == "internal":
            cache = CachePolicy("prefix_allowed", "workspace:internal", False, 3600)
            logging = LoggingPolicy("redacted", "redacted", 30)
        else:
            cache = CachePolicy("prefix_allowed", "system:public", False, 21600)
            logging = LoggingPolicy("deny", "redacted", 30)

        if isinstance(write_scope, str):
            normalized_write: str | tuple[str, ...] = write_scope
        else:
            normalized_write = self._unique(write_scope)

        # Hard budgets are conservative v1 defaults and must be tuned by evaluation.
        if deterministic_only:
            context = ContextBudget(12_000, 8_000, 4_000, 1_000)
            generation = GenerationBudget(1)
            execution = ExecutionBudget(4, 6, 0, 0, 120_000)
        elif task_type in {"doc_summary", "analysis", "sensitive_query"}:
            context = ContextBudget(16_000, 10_000, 4_000, 1_500)
            generation = GenerationBudget(2_000)
            execution = ExecutionBudget(8, 12, 2, 1, 600_000)
        else:
            context = ContextBudget(12_000, 8_000, 4_000, 1_000)
            generation = GenerationBudget(1_600)
            execution = ExecutionBudget(6, 10, 1, 1, 300_000)

        confidence = 0.85 if risk_level in {"high", "critical"} else 0.70
        contract = TaskContract(
            task_id=task_id,
            task_type=task_type,
            sensitivity=sensitivity,
            risk_level=risk_level,
            allowed_sources=self._unique(allowed_sources),
            allowed_tools=self._unique(tools),
            write_scope=normalized_write,
            network_scope=network_scope,
            context_budget=context,
            generation_budget=generation,
            execution_budget=execution,
            evidence_required=evidence_required,
            validators=self._unique(validators),
            model_policy=ModelPolicy(
                initial_tier=initial_tier,
                max_tier=max_tier,
                escalation_allowed=False if deterministic_only else True,
                confidence_floor=confidence,
                trusted_local_only=sensitivity != "public",
            ),
            cache_policy=cache,
            logging_policy=logging,
            output_schema=output_schema,
            policy_reason_codes=tuple(reasons),
        )
        return contract.validate()
