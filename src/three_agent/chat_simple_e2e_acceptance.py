from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Sequence

from .chat_acceptance import assert_local_model_endpoints
from .chat_fidelity import response_language_matches
from .chat_multiturn_acceptance import NoopStore, _sha256, _wait, isolated_config
from .chat_multiturn_acceptance_v2 import DiagnosticRecordingLLM
from .chat_service_fidelity_v2 import ContractAwareProjectChatService
from .config import AppConfig, load_config
from .orchestrator import Orchestrator
from .workspace_frontend_v12 import WORKSPACE_HTML_V12

SCHEMA_VERSION = "workspace-simple-chat-e2e/v1"
FORBIDDEN_WORKFLOW_STAGES = frozenset({"research", "presentation", "daily_report"})


@dataclass(frozen=True)
class SimpleChatCase:
    case_id: str
    prompt: str
    expected_language: str


CASES: tuple[SimpleChatCase, ...] = (
    SimpleChatCase(
        "simple_vi_intro",
        "Hãy giới thiệu ngắn gọn về bạn bằng tiếng Việt.",
        "vi",
    ),
    SimpleChatCase(
        "simple_ja_intro",
        "日本語で簡単に自己紹介してください。",
        "ja",
    ),
    SimpleChatCase(
        "simple_en_intro",
        "Please introduce yourself briefly in English.",
        "en",
    ),
)


def frontend_contract_errors(html: str = WORKSPACE_HTML_V12) -> tuple[str, ...]:
    """Verify that the shipped UI keeps ordinary source chat on the direct-chat UX."""

    checks = (
        ("requestMode:'chat'", "frontend_default_mode_not_chat"),
        ('<select id="fmt"><option value="source">', "frontend_default_output_not_source"),
        (
            "const directUi=state.requestMode==='chat'&&document.getElementById('fmt').value==='source'",
            "frontend_direct_chat_route_marker_missing",
        ),
        ("ui_route:directUi?'direct_chat':'workflow'", "frontend_direct_chat_ui_marker_missing"),
        ("node.dataset.uiRoute!=='direct_chat'", "frontend_stage_suppression_missing"),
    )
    return tuple(code for marker, code in checks if marker not in html)


def validation_errors(cases: Sequence[SimpleChatCase] = CASES) -> tuple[str, ...]:
    errors = list(frontend_contract_errors())
    seen: set[str] = set()
    for case in cases:
        if not case.case_id or case.case_id in seen:
            errors.append(f"invalid_or_duplicate_case:{case.case_id}")
        seen.add(case.case_id)
        if not case.prompt.strip():
            errors.append(f"{case.case_id}:empty_prompt")
        if case.expected_language not in {"vi", "ja", "en"}:
            errors.append(f"{case.case_id}:invalid_language")
    return tuple(errors)


def _stage_ids(job: Any) -> tuple[str, ...]:
    return tuple(
        str(item.get("id") or "").strip()
        for item in (getattr(job, "stages", None) or [])
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    )


def _safe_failure_code(job: Any, calls: Sequence[Any]) -> str:
    failed = [call for call in calls if not bool(getattr(call, "succeeded", False))]
    if failed:
        return str(getattr(failed[-1], "failure_code", "") or "runtime_error")[:80]
    if str(getattr(job, "status", "")) == "failed":
        text = str(getattr(job, "error", "") or "")
        if "ResourceAdmissionError" in text or "resource admission" in text.lower():
            return "resource_admission"
        if "response rejected" in text.lower() or "response validation" in text.lower():
            return "response_validation"
        return "job_failed"
    return ""


def run_case(
    service: ContractAwareProjectChatService,
    recorder: DiagnosticRecordingLLM,
    case: SimpleChatCase,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    before = len(recorder.calls)
    submitted = service.submit(
        case.prompt,
        channel="simple-e2e",
        sender="workspace-user:simple-e2e",
        language="auto",
        upload_ids=[],
        request_mode="chat",
        effort="standard",
        conversation_id=None,
    )
    initial_stage_ids = _stage_ids(submitted)
    job = _wait(service, submitted.job_id, timeout_seconds)
    calls = recorder.calls[before:]
    final_stage_ids = _stage_ids(job)
    answer = str(getattr(job, "answer", "") or "").strip()
    failures: list[str] = []

    if str(getattr(job, "status", "")) != "completed":
        failures.append(f"job_status:{getattr(job, 'status', '')}")
    if any(stage in FORBIDDEN_WORKFLOW_STAGES for stage in initial_stage_ids):
        failures.append("route:workflow_stage_in_initial_response")
    if any(stage in FORBIDDEN_WORKFLOW_STAGES for stage in final_stage_ids):
        failures.append("route:workflow_stage_in_final_response")
    if "answer" not in initial_stage_ids:
        failures.append("route:direct_answer_stage_missing")
    if str(getattr(job, "language", "")) != case.expected_language:
        failures.append(
            f"language:{getattr(job, 'language', '')}_not_{case.expected_language}"
        )
    if not answer:
        failures.append("answer:empty")
    elif not response_language_matches(answer, case.expected_language):
        failures.append("answer:target_language_mismatch")
    if not calls:
        failures.append("model:not_called")
    elif not any(bool(getattr(call, "succeeded", False)) for call in calls):
        failures.append("model:no_successful_return")

    failure_code = _safe_failure_code(job, calls)
    if failure_code == "resource_admission":
        failures.append("resource:admission_denied")

    failures = list(dict.fromkeys(failures))
    return {
        "case_id": case.case_id,
        "passed": not failures,
        "route": (
            "direct_chat"
            if "answer" in initial_stage_ids
            and not any(stage in FORBIDDEN_WORKFLOW_STAGES for stage in initial_stage_ids)
            else "unexpected"
        ),
        "expected_language": case.expected_language,
        "actual_language": str(getattr(job, "language", "")),
        "status": str(getattr(job, "status", "")),
        "initial_stage_ids": list(initial_stage_ids),
        "final_stage_ids": list(final_stage_ids),
        "model_call_count": len(calls),
        "model_returned": any(bool(getattr(call, "succeeded", False)) for call in calls),
        "failure_code": failure_code,
        "response_chars": len(answer),
        "response_sha256": _sha256(answer),
        "failures": failures,
    }


def contract_summary(cases: Sequence[SimpleChatCase] = CASES) -> dict[str, Any]:
    errors = validation_errors(cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "valid": not errors,
        "case_count": len(cases),
        "languages": [case.expected_language for case in cases],
        "frontend_contract_passed": not frontend_contract_errors(),
        "validation_errors": list(errors),
        "privacy": {
            "raw_prompts_in_report": False,
            "raw_answers_in_report": False,
            "production_database_mutated": False,
            "public_egress_enabled": False,
        },
    }


def run_live_suite(
    config: AppConfig,
    cases: Sequence[SimpleChatCase] = CASES,
    *,
    source_sha: str = "",
    timeout_seconds: float = 180.0,
) -> dict[str, Any]:
    errors = validation_errors(cases)
    if errors:
        raise ValueError("Invalid simple-chat E2E contract: " + "; ".join(errors))
    endpoints = assert_local_model_endpoints(config)

    with tempfile.TemporaryDirectory(prefix="workspace-simple-chat-e2e-") as temp:
        isolated = isolated_config(config, Path(temp))
        assert_local_model_endpoints(isolated)
        orchestrator = Orchestrator(isolated)
        orchestrator.initialize()
        recorder = DiagnosticRecordingLLM(orchestrator.llm)
        service = ContractAwareProjectChatService(
            SimpleNamespace(
                config=isolated,
                knowledge_gateway=orchestrator.knowledge_gateway,
                store=NoopStore(),
                llm=recorder,
            ),
            default_language=os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja"),
        )
        service.start()
        results = [
            run_case(service, recorder, case, timeout_seconds=timeout_seconds)
            for case in cases
        ]
        service._queue.join()

    try:
        package_version = importlib.metadata.version("workspace-local-ai")
    except importlib.metadata.PackageNotFoundError:
        package_version = "unknown"
    model_name = (
        config.model_policy.research_model
        if config.model_policy and config.model_policy.enabled
        else config.llm.model
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": all(item["passed"] for item in results),
        "source_sha": str(source_sha or os.getenv("GITHUB_SHA") or "unknown")[:80],
        "package_version": package_version,
        "case_count": len(cases),
        "languages": [case.expected_language for case in cases],
        "frontend_contract_passed": True,
        "endpoint_policy": "localhost_private_link_local_only",
        "endpoint_count": len(endpoints),
        "model_identity_sha256": _sha256(model_name),
        "privacy": {
            "raw_prompts_in_report": False,
            "raw_answers_in_report": False,
            "production_database_mutated": False,
            "public_egress_enabled": False,
        },
        "results": results,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WorkSpace multilingual simple-chat local-model E2E acceptance"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--contract", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--config", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--source-sha", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = (
            contract_summary()
            if args.contract
            else run_live_suite(
                load_config(args.config or None),
                source_sha=args.source_sha,
                timeout_seconds=args.timeout_seconds,
            )
        )
    except Exception as exc:
        text = str(exc)
        if "ResourceAdmissionError" in text or "resource admission" in text.lower():
            code = "resource_admission"
        elif "timeout" in text.lower():
            code = "timeout"
        else:
            code = type(exc).__name__
        report = {
            "schema_version": SCHEMA_VERSION,
            "passed": False,
            "failure_code": code,
            "source_sha": str(args.source_sha or os.getenv("GITHUB_SHA") or "unknown")[:80],
            "privacy": {
                "raw_prompts_in_report": False,
                "raw_answers_in_report": False,
                "production_database_mutated": False,
                "public_egress_enabled": False,
            },
        }

    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if bool(report.get("passed", report.get("valid", False))) else 1


if __name__ == "__main__":
    raise SystemExit(main())
