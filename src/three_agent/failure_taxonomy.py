from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

FAILURE_TAXONOMY_SCHEMA = "workspace-failure-taxonomy/v1"
FAILURE_DECISION_SCHEMA = "workspace-failure-decision/v1"
FAILURE_TAXONOMY_ID = "workspace-runtime-failure-taxonomy-v1"

_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


@dataclass(frozen=True)
class FailureDefinition:
    code: str
    family: str
    recovery_action: str
    terminal: bool
    retryable: bool
    permitted_operations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "family": self.family,
            "recovery_action": self.recovery_action,
            "terminal": self.terminal,
            "retryable": self.retryable,
            "permitted_operations": list(self.permitted_operations),
            "authority_may_expand": False,
        }


@dataclass(frozen=True)
class FailureDecision:
    definition: FailureDefinition
    observed_reason_code: str
    exception_type: str | None = None

    @property
    def code(self) -> str:
        return self.definition.code

    @property
    def family(self) -> str:
        return self.definition.family

    @property
    def recovery_action(self) -> str:
        return self.definition.recovery_action

    @property
    def terminal(self) -> bool:
        return self.definition.terminal

    @property
    def retryable(self) -> bool:
        return self.definition.retryable

    def permits(self, operation: str) -> bool:
        return str(operation).strip() in self.definition.permitted_operations

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": FAILURE_DECISION_SCHEMA,
            "taxonomy_id": FAILURE_TAXONOMY_ID,
            "failure_code": self.code,
            "observed_reason_code": self.observed_reason_code,
            "exception_type": self.exception_type,
            "family": self.family,
            "recovery_action": self.recovery_action,
            "terminal": self.terminal,
            "retryable": self.retryable,
            "permitted_operations": list(self.definition.permitted_operations),
            "authority_may_expand": False,
            "raw_message_logged": False,
        }


_DEFINITIONS = {
    "POLICY_DENIED": FailureDefinition("POLICY_DENIED", "policy", "hard_stop", True, False),
    "SECURITY_DENIED": FailureDefinition("SECURITY_DENIED", "security", "hard_stop", True, False),
    "CAPABILITY_DENIED": FailureDefinition("CAPABILITY_DENIED", "capability", "hard_stop", True, False),
    "CONTRACT_INVALID": FailureDefinition("CONTRACT_INVALID", "contract", "hard_stop", True, False),
    "EVIDENCE_MISSING": FailureDefinition(
        "EVIDENCE_MISSING", "evidence", "collect_evidence", False, False, ("collect_evidence",)
    ),
    "VALIDATION_FAILED": FailureDefinition("VALIDATION_FAILED", "validation", "hard_stop", True, False),
    "HUMAN_REVIEW_REQUIRED": FailureDefinition(
        "HUMAN_REVIEW_REQUIRED", "human_gate", "human_review", False, False, ("human_review",)
    ),
    "BUDGET_EXHAUSTED": FailureDefinition("BUDGET_EXHAUSTED", "budget", "hard_stop", True, False),
    "TOOL_TIMEOUT": FailureDefinition(
        "TOOL_TIMEOUT", "tool", "retry_within_budget", False, True, ("retry_tool",)
    ),
    "TOOL_FAILURE": FailureDefinition("TOOL_FAILURE", "tool", "hard_stop", True, False),
    "RESOURCE_BUSY": FailureDefinition(
        "RESOURCE_BUSY",
        "resource",
        "wait_or_fallback_within_authority",
        False,
        True,
        ("wait_resource", "fallback_worker", "fallback_model"),
    ),
    "RESOURCE_ADMISSION": FailureDefinition(
        "RESOURCE_ADMISSION",
        "resource",
        "fallback_within_authority",
        False,
        True,
        ("fallback_worker", "fallback_model"),
    ),
    "MODEL_FAILURE": FailureDefinition(
        "MODEL_FAILURE",
        "model",
        "retry_or_escalate_within_contract",
        False,
        True,
        ("retry_model", "fallback_worker", "fallback_model", "escalate_model"),
    ),
    "MODEL_OUTPUT_INVALID": FailureDefinition(
        "MODEL_OUTPUT_INVALID", "model_output", "regenerate_within_budget", False, True, ("retry_model",)
    ),
    "UNKNOWN_FAILURE": FailureDefinition("UNKNOWN_FAILURE", "unknown", "hard_stop", True, False),
}


def _normalize_reason_code(reason_code: object) -> str:
    value = str(reason_code or "").strip().upper()
    return value if _REASON_RE.fullmatch(value) else "UNKNOWN_FAILURE"


def _canonical_failure_code(reason_code: str) -> str:
    code = _normalize_reason_code(reason_code)
    if code in _DEFINITIONS:
        return code
    if "BUDGET_EXHAUSTED" in code:
        return "BUDGET_EXHAUSTED"
    if code.startswith("CAPABILITY_") or code.startswith("WRITE_SCOPE_") or code == "WRITE_RESOURCE_REQUIRED":
        return "CAPABILITY_DENIED"
    if code.startswith("POLICY_"):
        return "POLICY_DENIED"
    if code.startswith(("OUTBOUND_", "DLP_", "SECURITY_", "HANDOFF_SECURITY_")):
        return "SECURITY_DENIED"
    if code.startswith("TASK_CONTRACT_") or code.startswith("CONTRACT_"):
        return "CONTRACT_INVALID"
    if "EVIDENCE_MISSING" in code or code in {"EVIDENCE_HANDOFF_MISSING", "MISSING_EVIDENCE"}:
        return "EVIDENCE_MISSING"
    if code.startswith("HUMAN_") or code.endswith("_HUMAN_REQUIRED"):
        return "HUMAN_REVIEW_REQUIRED"
    if (
        code in {"PRESENTATION_VALIDATION_FAILED", "REQUIRED_VALIDATOR_NOT_PASSED"}
        or ("VALIDATION" in code and ("FAILED" in code or "INVALID" in code))
        or ("SCHEMA" in code and ("FAILED" in code or "INVALID" in code))
    ):
        return "VALIDATION_FAILED"
    if code == "RESOURCE_BUSY" or code.endswith("_RESOURCE_BUSY"):
        return "RESOURCE_BUSY"
    if code == "RESOURCE_ADMISSION" or "RESOURCE_ADMISSION" in code:
        return "RESOURCE_ADMISSION"
    if code in {"LOCAL_LLM_ERROR", "PRIMARY_MODEL_FAILED", "MODEL_FAILURE"}:
        return "MODEL_FAILURE"
    if "STRUCTURED_OUTPUT" in code or code == "MODEL_OUTPUT_INVALID":
        return "MODEL_OUTPUT_INVALID"
    if code == "TOOL_TIMEOUT" or code.startswith("TOOL_TIMEOUT_") or code.endswith("_TOOL_TIMEOUT"):
        return "TOOL_TIMEOUT"
    if code in {"TOOL_FAILURE", "DETERMINISTIC_RETRIEVAL_EXECUTION_FAILED"}:
        return "TOOL_FAILURE"
    return "UNKNOWN_FAILURE"


class FailureTaxonomy:
    """Authoritative deterministic failure classification and recovery policy.

    Unknown exception messages never become reason-code metadata merely because
    they look like compact identifiers. Only recognized taxonomy codes/patterns
    are retained; everything else becomes `UNKNOWN_FAILURE`.
    """

    schema_version = FAILURE_TAXONOMY_SCHEMA
    taxonomy_id = FAILURE_TAXONOMY_ID

    @staticmethod
    def definitions() -> tuple[FailureDefinition, ...]:
        return tuple(_DEFINITIONS[key] for key in sorted(_DEFINITIONS))

    @staticmethod
    def classify_reason(reason_code: object) -> FailureDecision:
        observed = _normalize_reason_code(reason_code)
        canonical = _canonical_failure_code(observed)
        safe_observed = observed if canonical != "UNKNOWN_FAILURE" else "UNKNOWN_FAILURE"
        return FailureDecision(_DEFINITIONS[canonical], safe_observed)

    @staticmethod
    def classify_exception(exc: BaseException) -> FailureDecision:
        reason = getattr(exc, "reason_code", None)
        if reason:
            decision = FailureTaxonomy.classify_reason(reason)
            return FailureDecision(decision.definition, decision.observed_reason_code, type(exc).__name__)

        name = type(exc).__name__
        type_map = {
            "CapabilityAuthorityDenied": "CAPABILITY_DENIED",
            "ModelAuthorityDenied": "CAPABILITY_DENIED",
            "ExecutionBudgetExceeded": "BUDGET_EXHAUSTED",
            "OutboundDLPError": "SECURITY_DENIED",
            "OutboundSecurityError": "SECURITY_DENIED",
            "HandoffSecurityValidationError": "SECURITY_DENIED",
            "TaskContractError": "CONTRACT_INVALID",
            "ResourceBusyError": "RESOURCE_BUSY",
            "ResourceAdmissionError": "RESOURCE_ADMISSION",
            "LocalLLMError": "MODEL_FAILURE",
            "StructuredOutputValidationError": "MODEL_OUTPUT_INVALID",
            "TimeoutError": "TOOL_TIMEOUT",
            "TimeoutExpired": "TOOL_TIMEOUT",
        }
        if name in type_map:
            definition = _DEFINITIONS[type_map[name]]
            return FailureDecision(definition, definition.code, name)

        text = str(exc).strip().upper()
        if _REASON_RE.fullmatch(text):
            canonical = _canonical_failure_code(text)
            if canonical != "UNKNOWN_FAILURE":
                return FailureDecision(_DEFINITIONS[canonical], text, name)

        if isinstance(exc, PermissionError):
            definition = _DEFINITIONS["SECURITY_DENIED"]
            return FailureDecision(definition, "SECURITY_DENIED", name)
        return FailureDecision(_DEFINITIONS["UNKNOWN_FAILURE"], "UNKNOWN_FAILURE", name)

    @staticmethod
    def require_operation(reason_code: object, operation: str) -> FailureDecision:
        decision = FailureTaxonomy.classify_reason(reason_code)
        if not decision.permits(operation):
            raise RuntimeError(
                f"FAILURE_RECOVERY_NOT_AUTHORIZED:{decision.code}:{str(operation).strip()}"
            )
        return decision

    @staticmethod
    def registry_payload() -> dict[str, object]:
        return {
            "schema_version": FAILURE_TAXONOMY_SCHEMA,
            "taxonomy_id": FAILURE_TAXONOMY_ID,
            "definitions": [item.to_dict() for item in FailureTaxonomy.definitions()],
            "unknown_failure_policy": "hard_stop",
            "raw_content_required": False,
        }


DEFAULT_FAILURE_TAXONOMY = FailureTaxonomy()


def classify_failure(exc: BaseException | None = None, *, reason_code: object | None = None) -> FailureDecision:
    if exc is not None and reason_code is not None:
        raise ValueError("provide either exc or reason_code, not both")
    if exc is not None:
        return DEFAULT_FAILURE_TAXONOMY.classify_exception(exc)
    return DEFAULT_FAILURE_TAXONOMY.classify_reason(reason_code)


def recovery_permitted(reason_code: object, operation: str) -> bool:
    return DEFAULT_FAILURE_TAXONOMY.classify_reason(reason_code).permits(operation)


def assert_no_authority_expansion(decisions: Iterable[FailureDecision]) -> None:
    for decision in decisions:
        if decision.to_dict()["authority_may_expand"] is not False:
            raise ValueError("failure recovery may never expand task authority")
