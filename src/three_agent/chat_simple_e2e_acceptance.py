from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Sequence
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

from .chat_acceptance import assert_local_model_endpoints
from .chat_fidelity import response_language_matches
from .chat_gateway import WorkflowV4ContextApplication, WorkflowV4ContextHTTPHandler
from .chat_multiturn_acceptance import _sha256, _wait, isolated_config
from .chat_multiturn_acceptance import DiagnosticRecordingLLM
from .chat_service_fidelity import ContractAwareProjectChatService
from .config import AppConfig, load_config
from .orchestrator import Orchestrator
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)
from .workspace_frontend import WORKSPACE_HTML

SCHEMA_VERSION = "workspace-simple-chat-e2e/v2"
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


def frontend_contract_errors(html: str = WORKSPACE_HTML) -> tuple[str, ...]:
    """Verify the shipped browser request and ordinary-chat rendering contract."""

    checks = (
        ("requestMode:'chat'", "frontend_default_mode_not_chat"),
        ('<select id="fmt"><option value="source">', "frontend_default_output_not_source"),
        ("api('/api/chat'", "frontend_chat_endpoint_missing"),
        ("mode:state.requestMode", "frontend_request_mode_missing"),
        ("poll(d.job_id", "frontend_job_poll_missing"),
        ("api('/api/jobs/'+id)", "frontend_job_endpoint_missing"),
        (
            "const directUi=state.requestMode==='chat'&&document.getElementById('fmt').value==='source'",
            "frontend_direct_chat_route_marker_missing",
        ),
        ("ui_route:directUi?'direct_chat':'workflow'", "frontend_direct_chat_ui_marker_missing"),
        ("function shouldShowAnswerStages(job,route)", "frontend_stage_suppression_helper_missing"),
        ("return route!=='direct_chat'", "frontend_stage_suppression_route_missing"),
        ("shouldShowAnswerStages(job,d.dataset.uiRoute)", "frontend_initial_stage_suppression_missing"),
        ("shouldShowAnswerStages(j,node.dataset.uiRoute)", "frontend_stage_suppression_missing"),
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
    stages = job.get("stages", []) if isinstance(job, dict) else getattr(job, "stages", None) or []
    return tuple(
        str(item.get("id") or "").strip()
        for item in stages
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    )


def _job_value(job: Any, key: str, default: Any = "") -> Any:
    if isinstance(job, dict):
        return job.get(key, default)
    return getattr(job, key, default)


def _safe_failure_code(job: Any, calls: Sequence[Any]) -> str:
    failed = [call for call in calls if not bool(getattr(call, "succeeded", False))]
    if failed:
        return str(getattr(failed[-1], "failure_code", "") or "runtime_error")[:80]
    if str(_job_value(job, "status")) == "failed":
        text = str(_job_value(job, "error") or "")
        if "ResourceAdmissionError" in text or "resource admission" in text.lower():
            return "resource_admission"
        if "response rejected" in text.lower() or "response validation" in text.lower():
            return "response_validation"
        return "job_failed"
    return ""


def _evaluate_result(
    case: SimpleChatCase,
    initial_job: Any,
    final_job: Any,
    calls: Sequence[Any],
    *,
    transport: str,
    http_submit_status: int = 0,
    http_poll_status: int = 0,
) -> dict[str, Any]:
    initial_stage_ids = _stage_ids(initial_job)
    final_stage_ids = _stage_ids(final_job)
    answer = str(_job_value(final_job, "answer") or "").strip()
    actual_language = str(_job_value(final_job, "language") or "")
    status = str(_job_value(final_job, "status") or "")
    failures: list[str] = []

    if http_submit_status and http_submit_status != 202:
        failures.append(f"http:submit_status_{http_submit_status}")
    if http_poll_status and http_poll_status != 200:
        failures.append(f"http:poll_status_{http_poll_status}")
    if status != "completed":
        failures.append(f"job_status:{status}")
    if any(stage in FORBIDDEN_WORKFLOW_STAGES for stage in initial_stage_ids):
        failures.append("route:workflow_stage_in_initial_response")
    if any(stage in FORBIDDEN_WORKFLOW_STAGES for stage in final_stage_ids):
        failures.append("route:workflow_stage_in_final_response")
    if "answer" not in initial_stage_ids:
        failures.append("route:direct_answer_stage_missing")
    if actual_language != case.expected_language:
        failures.append(f"language:{actual_language}_not_{case.expected_language}")
    if not answer:
        failures.append("answer:empty")
    elif not response_language_matches(answer, case.expected_language):
        failures.append("answer:target_language_mismatch")
    if not calls:
        failures.append("model:not_called")
    elif not any(bool(getattr(call, "succeeded", False)) for call in calls):
        failures.append("model:no_successful_return")

    failure_code = _safe_failure_code(final_job, calls)
    if failure_code == "resource_admission":
        failures.append("resource:admission_denied")

    failures = list(dict.fromkeys(failures))
    return {
        "case_id": case.case_id,
        "passed": not failures,
        "transport": transport,
        "route": (
            "direct_chat"
            if "answer" in initial_stage_ids
            and not any(stage in FORBIDDEN_WORKFLOW_STAGES for stage in initial_stage_ids)
            else "unexpected"
        ),
        "expected_language": case.expected_language,
        "actual_language": actual_language,
        "status": status,
        "initial_stage_ids": list(initial_stage_ids),
        "final_stage_ids": list(final_stage_ids),
        "model_call_count": len(calls),
        "model_returned": any(bool(getattr(call, "succeeded", False)) for call in calls),
        "failure_code": failure_code,
        "response_chars": len(answer),
        "response_sha256": _sha256(answer),
        "http_submit_status": http_submit_status,
        "http_poll_status": http_poll_status,
        "failures": failures,
    }


def run_case(
    service: ContractAwareProjectChatService,
    recorder: DiagnosticRecordingLLM,
    case: SimpleChatCase,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Service-bound helper retained for deterministic unit tests."""

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
    job = _wait(service, submitted.job_id, timeout_seconds)
    calls = recorder.calls[before:]
    return _evaluate_result(case, submitted, job, calls, transport="service")


def _http_json(opener: Any, url: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        response = opener.open(request, timeout=15)
    except HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = {}
        return int(exc.code), parsed if isinstance(parsed, dict) else {}
    with response:
        raw = response.read()
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
        return int(response.status), parsed if isinstance(parsed, dict) else {}


def run_http_case(
    opener: Any,
    base_url: str,
    recorder: DiagnosticRecordingLLM,
    case: SimpleChatCase,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Exercise the same POST /api/chat and GET /api/jobs path used by the browser."""

    before = len(recorder.calls)
    submit_status, submitted = _http_json(
        opener,
        base_url + "/api/chat",
        method="POST",
        payload={
            "message": case.prompt,
            "language": "auto",
            "format": "source",
            "upload_ids": [],
            "mode": "chat",
            "effort": "standard",
            "conversation_id": "",
        },
    )
    job_id = str(submitted.get("job_id") or "")
    if submit_status != 202 or not job_id:
        return _evaluate_result(
            case,
            submitted,
            submitted,
            recorder.calls[before:],
            transport="http_api",
            http_submit_status=submit_status,
        )

    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    poll_status = 0
    final_job: dict[str, Any] = dict(submitted)
    while time.monotonic() < deadline:
        poll_status, final_job = _http_json(opener, base_url + "/api/jobs/" + job_id)
        if poll_status != 200:
            break
        if str(final_job.get("status") or "") not in {"queued", "running"}:
            break
        time.sleep(0.05)
    else:
        final_job = dict(final_job)
        final_job["status"] = "timeout"

    return _evaluate_result(
        case,
        submitted,
        final_job,
        recorder.calls[before:],
        transport="http_api",
        http_submit_status=submit_status,
        http_poll_status=poll_status,
    )


def contract_summary(cases: Sequence[SimpleChatCase] = CASES) -> dict[str, Any]:
    errors = validation_errors(cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "valid": not errors,
        "case_count": len(cases),
        "languages": [case.expected_language for case in cases],
        "transport": "browser_contract_plus_http_api",
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
        orchestrator.llm = recorder
        service = ContractAwareProjectChatService(
            orchestrator,
            default_language=os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja"),
        )
        service.start()

        auth = ExternalSessionAuthStore(isolated.database_path)
        auth.initialize()
        access_token = secrets.token_urlsafe(32)
        auth.bootstrap_admin(
            "e2e-admin",
            access_token,
            display_name="E2E Administrator",
            title="Administrator",
        )
        external_store = ExternalIdentityStore(auth)
        external_store.initialize()
        external_settings = ExternalAuthSettings.from_env()
        app = WorkflowV4ContextApplication(
            service,
            auth,
            isolated.artifact_root,
            external_store,
            external_settings,
        )

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), WorkflowV4ContextHTTPHandler)
        httpd.app = app  # type: ignore[attr-defined]
        server_thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="workspace-simple-chat-e2e-http",
            daemon=True,
        )
        server_thread.start()
        base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
        opener = build_opener(HTTPCookieProcessor(CookieJar()))
        try:
            login_status, _ = _http_json(
                opener,
                base_url + "/api/login",
                method="POST",
                payload={"username": "e2e-admin", "password": access_token},
            )
            if login_status != 200:
                raise RuntimeError(f"local E2E login failed with HTTP {login_status}")
            results = [
                run_http_case(
                    opener,
                    base_url,
                    recorder,
                    case,
                    timeout_seconds=timeout_seconds,
                )
                for case in cases
            ]
            service._queue.join()
        finally:
            httpd.shutdown()
            httpd.server_close()
            server_thread.join(timeout=5.0)

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
        "transport": "browser_contract_plus_http_api",
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
        description="WorkSpace multilingual browser-contract + HTTP local-model E2E acceptance"
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
