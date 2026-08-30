from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

# Keep the authoritative P2 corpus/evaluator unchanged. This wrapper swaps the
# ordinary-chat service implementation under test to the current production
# ContractAwareProjectChatService and adds metadata-only runtime evidence.
from . import chat_multiturn_acceptance as acceptance
from .chat_multiturn_acceptance import PromptEvidence
from .chat_service_fidelity_v2 import ContractAwareProjectChatService
from .llm import LocalLLMError
from .resource_budget import ResourceAdmissionError, ResourceBusyError


@dataclass(frozen=True)
class RuntimePromptEvidence(PromptEvidence):
    succeeded: bool = False
    failure_code: str = ""


_SAFE_VALIDATION_REASONS = frozenset(
    {
        "empty_response",
        "requested_format_mismatch",
        "target_language_mismatch",
        "workflow_wrapper_leak",
        "output_contract_empty",
        "output_contract_non_bullet_text",
        "output_contract_multiple_sentences",
        "output_contract_invalid_json",
        "output_contract_not_single_number",
        "response_validation_failed",
    }
)
_SAFE_DYNAMIC_VALIDATION_REASONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"output_contract_chars:\d+_gt_\d+"), "output_contract_chars_limit"),
    (re.compile(r"output_contract_lines:\d+_gt_\d+"), "output_contract_lines_limit"),
    (re.compile(r"output_contract_bullets:\d+_not_\d+"), "output_contract_bullet_count"),
)


def safe_response_validation_reason(value: object) -> str:
    """Return only an allowlisted validator code, never arbitrary model/error text."""

    reason = str(value or "").strip()
    if reason in _SAFE_VALIDATION_REASONS:
        return reason
    for pattern, code in _SAFE_DYNAMIC_VALIDATION_REASONS:
        if pattern.fullmatch(reason):
            return code
    if reason.startswith("output_contract_"):
        return "response_validation_unknown"
    return ""


def safe_runtime_failure_code(exc: BaseException) -> str:
    """Map runtime failures to a stable non-sensitive diagnostic code."""
    if isinstance(exc, ResourceBusyError):
        return "resource_busy"
    if isinstance(exc, ResourceAdmissionError):
        return "resource_admission"
    if isinstance(exc, PermissionError):
        return "runtime_permission"
    if isinstance(exc, TimeoutError):
        return "llm_transport_timeout"
    if isinstance(exc, LocalLLMError):
        text = str(exc).lower()
        if "permission denied" in text:
            return "runtime_permission"
        if "timed out" in text or "timeout" in text:
            return "llm_transport_timeout"
        if any(
            marker in text
            for marker in (
                "connection refused",
                "network is unreachable",
                "name or service not known",
                "temporary failure in name resolution",
                "no route to host",
            )
        ):
            return "llm_endpoint_unreachable"
        if "http error 4" in text:
            return "llm_http_client_error"
        if "http error 5" in text:
            return "llm_http_server_error"
        if "empty response" in text:
            return "llm_empty_response"
        if "request failed" in text:
            return "llm_transport_error"
        return "llm_error"
    return "runtime_error"


class DiagnosticRecordingLLM:
    """Record only hashed prompt metadata and whether the delegate returned."""

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.calls: list[RuntimePromptEvidence] = []

    @staticmethod
    def _evidence(
        user_prompt: str,
        *,
        succeeded: bool,
        failure_code: str = "",
    ) -> RuntimePromptEvidence:
        body = str(user_prompt or "")
        return RuntimePromptEvidence(
            sha256=acceptance._sha256(body),
            chars=len(body),
            current_request_boundary="<CURRENT_USER_REQUEST>" in body,
            follow_up_policy='mode="follow_up"' in body,
            standalone_policy='mode="standalone"' in body,
            recent_context="<RECENT_CONVERSATION_CONTEXT>" in body,
            unavailable_context='available="false"' in body,
            succeeded=succeeded,
            failure_code=failure_code,
        )

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        try:
            answer = self.delegate.generate(system_prompt, user_prompt, **kwargs)
        except Exception as exc:
            self.calls.append(
                self._evidence(
                    user_prompt,
                    succeeded=False,
                    failure_code=safe_runtime_failure_code(exc),
                )
            )
            raise
        self.calls.append(self._evidence(user_prompt, succeeded=True))
        return answer


class DiagnosticContractAwareProjectChatService(ContractAwareProjectChatService):
    """Production chat service with metadata-only terminal validator observation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.p2_validation_outcomes: list[str] = []

    def _stage(
        self,
        job_id: str,
        name: str,
        status: str,
        detail: str = "",
    ) -> None:
        if name == "answer" and status in {"completed", "failed"}:
            self.p2_validation_outcomes.append(
                "" if status == "completed" else safe_response_validation_reason(detail)
            )
        return super()._stage(job_id, name, status, detail)


_BASE_RUN_CASE = acceptance.run_case
_BASE_RUN_LIVE_SUITE = acceptance.run_live_suite


def _job_failure_code(turn: dict[str, Any], calls: Sequence[RuntimePromptEvidence]) -> str:
    job_failed = any(str(item).startswith("job_status:") for item in turn.get("failures", []))
    if not job_failed:
        return ""
    failed_calls = [call for call in calls if not call.succeeded]
    if failed_calls:
        return failed_calls[-1].failure_code or "runtime_error"
    if calls:
        return "response_validation"
    return "pre_model_failure"


def diagnostic_run_case(
    service: Any,
    recorder: DiagnosticRecordingLLM,
    case: Any,
    *,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    before = len(recorder.calls)
    outcome_before = len(getattr(service, "p2_validation_outcomes", ()))
    result = _BASE_RUN_CASE(
        service,
        recorder,
        case,
        timeout_seconds=timeout_seconds,
    )
    offset = before
    outcomes = list(getattr(service, "p2_validation_outcomes", ()))[outcome_before:]
    for turn_index, turn in enumerate(result.get("turns", [])):
        attempts = max(0, int(turn.get("attempts", 0) or 0))
        calls = recorder.calls[offset : offset + attempts]
        offset += attempts
        turn["job_failure_code"] = _job_failure_code(turn, calls)
        turn["response_validation_reason"] = (
            outcomes[turn_index] if turn_index < len(outcomes) else ""
        )
        prompt_evidence = turn.get("prompt_evidence")
        if isinstance(prompt_evidence, dict):
            prompt_evidence.setdefault("succeeded", False)
            prompt_evidence.setdefault("failure_code", "")
    return result


def summarize_runtime_evidence(report: dict[str, Any]) -> dict[str, Any]:
    attempted = False
    returned = False
    failure_codes: set[str] = set()
    validation_reasons: set[str] = set()
    for case in report.get("results", []):
        for turn in case.get("turns", []):
            attempted = attempted or int(turn.get("attempts", 0) or 0) > 0
            evidence = turn.get("prompt_evidence")
            if isinstance(evidence, dict) and evidence.get("succeeded") is True:
                returned = True
            code = str(turn.get("job_failure_code") or "").strip()
            if code:
                failure_codes.add(code)
            validation_reason = str(turn.get("response_validation_reason") or "").strip()
            if validation_reason:
                validation_reasons.add(validation_reason)
    report["model_call_attempted"] = attempted
    report["live_model_executed"] = returned
    report["runtime_failure_codes"] = sorted(failure_codes)
    report["response_validation_reasons"] = sorted(validation_reasons)
    return report


def diagnostic_run_live_suite(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return summarize_runtime_evidence(_BASE_RUN_LIVE_SUITE(*args, **kwargs))


def safe_top_level_failure(exc: BaseException, *, live: bool) -> dict[str, Any]:
    code = safe_runtime_failure_code(exc)
    return {
        "schema_version": acceptance.SCHEMA_VERSION,
        "model_call_attempted": False,
        "live_model_executed": False,
        "passed": False,
        "failure_code": code,
        "runtime_failure_codes": [code],
        "response_validation_reasons": [],
        "privacy": {
            "raw_prompts_in_report": False,
            "raw_answers_in_report": False,
            "production_database_mutated": False,
            "public_egress_enabled": False,
        },
        "mode": "live" if live else "contract",
    }


def install_runtime_hooks() -> None:
    acceptance.ContextAwareProjectChatService = DiagnosticContractAwareProjectChatService
    acceptance.RecordingLLM = DiagnosticRecordingLLM
    acceptance.run_case = diagnostic_run_case
    acceptance.run_live_suite = diagnostic_run_live_suite


def main(argv: Sequence[str] | None = None) -> int:
    install_runtime_hooks()
    args = acceptance.build_parser().parse_args(argv)
    try:
        cases = acceptance.select_cases(args.case_ids)
        report = (
            acceptance.contract_summary(cases)
            if args.contract
            else acceptance.run_live_suite(
                acceptance.load_config(args.config or None),
                cases,
                source_sha=args.source_sha,
                timeout_seconds=args.timeout_seconds,
            )
        )
    except Exception as exc:
        report = safe_top_level_failure(exc, live=bool(args.live))

    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if bool(report.get("passed", report.get("valid", False))) else 1


if __name__ == "__main__":
    raise SystemExit(main())
