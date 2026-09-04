from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Sequence

from .chat_acceptance import AcceptanceCase, assert_local_model_endpoints, evaluate_answer
from .chat_context import CONTEXT_MODE_FOLLOW_UP, CONTEXT_MODE_STANDALONE
from .chat_gateway_v5 import _history_owner_key
from .chat_gateway_v16 import ContextAwareProjectChatService
from .config import AppConfig, load_config
from .orchestrator import Orchestrator

SCHEMA_VERSION = "workspace-chat-multiturn-acceptance/v1"


@dataclass(frozen=True)
class TurnSpec:
    prompt: str
    expected_language: str
    expected_context_mode: str
    output_kind: str = "prose"
    required_groups: tuple[tuple[str, ...], ...] = ()
    forbidden_terms: tuple[str, ...] = ()
    exact_items: int = 0
    max_lines: int = 0
    max_chars: int = 0
    exact_text: str = ""
    selected_language: str = "auto"
    effort: str = "standard"
    min_context_messages: int = 0
    context_available: bool | None = None


@dataclass(frozen=True)
class MultiTurnCase:
    case_id: str
    turns: tuple[TurnSpec, ...]


@dataclass(frozen=True)
class PromptEvidence:
    sha256: str
    chars: int
    current_request_boundary: bool
    follow_up_policy: bool
    standalone_policy: bool
    recent_context: bool
    unavailable_context: bool


CORPUS: tuple[MultiTurnCase, ...] = (
    MultiTurnCase(
        "vi_network_reference_chain",
        (
            TurnSpec(
                "Hãy trả lời bằng tiếng Việt với đúng 3 gạch đầu dòng theo thứ tự: "
                "(1) kiểm tra địa chỉ IP bằng ip addr; (2) kiểm tra default gateway bằng "
                "ip route; (3) kiểm tra DNS bằng resolvectl status.",
                "vi",
                CONTEXT_MODE_STANDALONE,
                output_kind="bullets",
                required_groups=(("ip addr",), ("ip route",), ("resolvectl", "dns")),
                exact_items=3,
                max_chars=900,
                context_available=False,
            ),
            TurnSpec(
                "Cái thứ hai: giải thích trong đúng một câu.",
                "vi",
                CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("gateway", "cổng mặc định"),),
                max_lines=1,
                max_chars=500,
                min_context_messages=2,
                context_available=True,
            ),
            TurnSpec(
                "Phần đó, chỉ đưa lệnh thôi.",
                "vi",
                CONTEXT_MODE_FOLLOW_UP,
                output_kind="code_only",
                required_groups=(("ip route",),),
                max_chars=160,
                min_context_messages=2,
                context_available=True,
            ),
        ),
    ),
    MultiTurnCase(
        "en_reference_then_language_override",
        (
            TurnSpec(
                "Reply in English with exactly 2 bullet points: first, ping checks reachability; "
                "second, traceroute shows path hops.",
                "en",
                CONTEXT_MODE_STANDALONE,
                output_kind="bullets",
                required_groups=(("ping",), ("traceroute",)),
                exact_items=2,
                max_chars=700,
                context_available=False,
            ),
            TurnSpec(
                "The second one: reply in Vietnamese in one sentence and keep the word traceroute unchanged.",
                "vi",
                CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("traceroute",), ("đường", "hop", "tuyến", "lộ trình")),
                max_lines=1,
                max_chars=500,
                min_context_messages=2,
                context_available=True,
            ),
            TurnSpec(
                "Cái đó, chỉ trả lời một lệnh Linux.",
                "vi",
                CONTEXT_MODE_FOLLOW_UP,
                output_kind="code_only",
                required_groups=(("traceroute", "tracepath"),),
                max_chars=160,
                min_context_messages=2,
                context_available=True,
            ),
        ),
    ),
    MultiTurnCase(
        "ja_network_reference_chain",
        (
            TurnSpec(
                "日本語で、次の順序どおりにちょうど3つの箇条書きで答えてください。"
                "1つ目は ip addr でIPアドレス確認、2つ目は ip route でデフォルト"
                "ゲートウェイ確認、3つ目は resolvectl status でDNS確認です。",
                "ja",
                CONTEXT_MODE_STANDALONE,
                output_kind="bullets",
                required_groups=(("ip addr",), ("ip route",), ("resolvectl", "dns")),
                exact_items=3,
                max_chars=900,
                context_available=False,
            ),
            TurnSpec(
                "2つ目だけを一文で詳しく説明してください。",
                "ja",
                CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("ゲートウェイ", "gateway"),),
                max_lines=1,
                max_chars=500,
                min_context_messages=2,
                context_available=True,
            ),
            TurnSpec(
                "その設定について、コマンドだけ返してください。",
                "ja",
                CONTEXT_MODE_FOLLOW_UP,
                output_kind="code_only",
                required_groups=(("ip route",),),
                max_chars=160,
                min_context_messages=2,
                context_available=True,
            ),
        ),
    ),
    MultiTurnCase(
        "stale_history_isolation",
        (
            TurnSpec(
                "Reply in English in one sentence. Include the exact marker LEGACY_ALPHA and state "
                "that PostgreSQL commonly listens on TCP port 5432.",
                "en",
                CONTEXT_MODE_STANDALONE,
                required_groups=(("LEGACY_ALPHA",), ("PostgreSQL",), ("5432",)),
                max_lines=1,
                max_chars=450,
                context_available=False,
            ),
            TurnSpec(
                "Hãy chỉ trả lời bằng một số duy nhất: cổng HTTPS mặc định là bao nhiêu?",
                "vi",
                CONTEXT_MODE_STANDALONE,
                output_kind="single_number",
                forbidden_terms=("LEGACY_ALPHA", "PostgreSQL", "5432"),
                exact_text="443",
                max_lines=1,
                max_chars=8,
                context_available=False,
            ),
        ),
    ),
    MultiTurnCase(
        "vi_missing_reference_clarifies",
        (
            TurnSpec(
                "tiếp theo?",
                "vi",
                CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("phần", "nội dung", "trước", "cung cấp", "muốn", "tiếp tục"),),
                max_chars=400,
                context_available=False,
            ),
        ),
    ),
)


class NoopStore:
    def record_activity(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs


class RecordingLLM:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.calls: list[PromptEvidence] = []

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        body = str(user_prompt or "")
        self.calls.append(
            PromptEvidence(
                sha256=_sha256(body),
                chars=len(body),
                current_request_boundary="<CURRENT_USER_REQUEST>" in body,
                follow_up_policy='mode="follow_up"' in body,
                standalone_policy='mode="standalone"' in body,
                recent_context="<RECENT_CONVERSATION_CONTEXT>" in body,
                unavailable_context='available="false"' in body,
            )
        )
        return self.delegate.generate(system_prompt, user_prompt, **kwargs)


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def corpus_sha256(cases: Sequence[MultiTurnCase] = CORPUS) -> str:
    encoded = json.dumps(
        [asdict(case) for case in cases],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validation_errors(cases: Sequence[MultiTurnCase] = CORPUS) -> tuple[str, ...]:
    errors: list[str] = []
    seen: set[str] = set()
    for case in cases:
        if not case.case_id or case.case_id in seen:
            errors.append(f"invalid_or_duplicate_case:{case.case_id}")
        seen.add(case.case_id)
        if not case.turns:
            errors.append(f"{case.case_id}:empty_turns")
        for index, turn in enumerate(case.turns, 1):
            prefix = f"{case.case_id}:turn_{index}"
            if not turn.prompt.strip():
                errors.append(prefix + ":empty_prompt")
            if turn.expected_language not in {"vi", "en", "ja"}:
                errors.append(prefix + ":invalid_language")
            if turn.expected_context_mode not in {CONTEXT_MODE_STANDALONE, CONTEXT_MODE_FOLLOW_UP}:
                errors.append(prefix + ":invalid_context_mode")
            if turn.output_kind not in {"prose", "json_object", "single_number", "code_only", "bullets"}:
                errors.append(prefix + ":invalid_output_kind")
            if turn.selected_language not in {"auto", "vi", "en", "ja"}:
                errors.append(prefix + ":invalid_selected_language")
            if turn.effort not in {"standard", "high"}:
                errors.append(prefix + ":invalid_effort")
            if min(turn.exact_items, turn.max_lines, turn.max_chars, turn.min_context_messages) < 0:
                errors.append(prefix + ":negative_limit")
    return tuple(errors)


def select_cases(case_ids: Iterable[str] | None) -> tuple[MultiTurnCase, ...]:
    requested = tuple(str(item).strip() for item in (case_ids or ()) if str(item).strip())
    if not requested:
        return CORPUS
    by_id = {case.case_id: case for case in CORPUS}
    unknown = [item for item in requested if item not in by_id]
    if unknown:
        raise ValueError("Unknown multi-turn acceptance case: " + ", ".join(unknown))
    return tuple(by_id[item] for item in requested)


def _answer_case(case_id: str, index: int, turn: TurnSpec) -> AcceptanceCase:
    return AcceptanceCase(
        case_id=f"{case_id}_t{index}",
        prompt=turn.prompt,
        expected_language=turn.expected_language,
        output_kind=turn.output_kind,
        required_groups=turn.required_groups,
        forbidden_terms=turn.forbidden_terms,
        exact_items=turn.exact_items,
        max_lines=turn.max_lines,
        max_chars=turn.max_chars,
        exact_text=turn.exact_text,
        effort=turn.effort,
    )


def _wait(service: ContextAwareProjectChatService, job_id: str, timeout_seconds: float) -> Any:
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    job = service.get(job_id)
    while job is not None and job.status in {"queued", "running"}:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"acceptance job timed out: {job_id}")
        time.sleep(0.05)
        job = service.get(job_id)
    if job is None:
        raise RuntimeError(f"acceptance job disappeared: {job_id}")
    return job


def run_case(
    service: ContextAwareProjectChatService,
    recorder: RecordingLLM,
    case: MultiTurnCase,
    *,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    sender = "workspace-user:acceptance-" + _sha256(case.case_id)[7:23]
    channel = "acceptance"
    owner = _history_owner_key(channel, sender)
    conversation_id = service.history.create_conversation(owner, f"Acceptance {case.case_id}")
    results: list[dict[str, Any]] = []

    for index, turn in enumerate(case.turns, 1):
        before = len(recorder.calls)
        submitted = service.submit(
            turn.prompt,
            channel=channel,
            sender=sender,
            language=turn.selected_language,
            request_mode="chat",
            effort=turn.effort,
            conversation_id=conversation_id,
        )
        job = _wait(service, submitted.job_id, timeout_seconds)
        calls = recorder.calls[before:]
        evidence = calls[0] if calls else PromptEvidence(
            _sha256(""), 0, False, False, False, False, False
        )
        plan = service.context_plan_for_job(submitted.job_id)
        actual_mode = plan.mode if plan is not None else "missing"
        message_count = int(plan.message_count) if plan is not None else 0
        failures: list[str] = []

        if job.status != "completed":
            failures.append(f"job_status:{job.status}")
        if str(job.language or "") != turn.expected_language:
            failures.append(f"language:{job.language}_not_{turn.expected_language}")
        if actual_mode != turn.expected_context_mode:
            failures.append(f"context_mode:{actual_mode}_not_{turn.expected_context_mode}")
        if not evidence.current_request_boundary:
            failures.append("prompt:missing_current_request_boundary")

        if turn.expected_context_mode == CONTEXT_MODE_STANDALONE:
            if message_count:
                failures.append(f"standalone_context_messages:{message_count}")
            if not evidence.standalone_policy:
                failures.append("prompt:missing_standalone_policy")
            if evidence.recent_context:
                failures.append("prompt:standalone_history_present")
        else:
            if not evidence.follow_up_policy:
                failures.append("prompt:missing_follow_up_policy")
            if message_count < turn.min_context_messages:
                failures.append(f"context_messages:{message_count}_lt_{turn.min_context_messages}")

        if turn.context_available is True and evidence.unavailable_context:
            failures.append("prompt:context_unexpectedly_unavailable")
        if turn.context_available is False and turn.expected_context_mode == CONTEXT_MODE_FOLLOW_UP:
            if not evidence.unavailable_context:
                failures.append("prompt:missing_unavailable_context_marker")

        answer = str(job.answer or "").strip()
        evaluated = evaluate_answer(_answer_case(case.case_id, index, turn), answer, attempts=len(calls))
        failures.extend(evaluated.failures)
        failures = list(dict.fromkeys(failures))
        results.append(
            {
                "turn_index": index,
                "passed": not failures,
                "failures": failures,
                "expected_language": turn.expected_language,
                "actual_language": str(job.language or ""),
                "expected_context_mode": turn.expected_context_mode,
                "actual_context_mode": actual_mode,
                "context_message_count": message_count,
                "attempts": len(calls),
                "response_sha256": _sha256(answer),
                "response_chars": len(answer),
                "prompt_evidence": asdict(evidence),
            }
        )

    return {"case_id": case.case_id, "passed": all(r["passed"] for r in results), "turns": results}


def isolated_config(config: AppConfig, root: Path) -> AppConfig:
    internet = replace(
        config.internet_gateway,
        enabled=False,
        allow_all=False,
        public_search_enabled=False,
        audit_log=root / "internet-audit.jsonl",
    )
    execution = replace(
        config.execution_gateway,
        enabled=False,
        allow_all=False,
        audit_log=root / "execution-audit.jsonl",
    )
    return replace(
        config,
        test_mode_full_access=False,
        database_path=root / "acceptance.db",
        artifact_root=root / "artifacts",
        profile_root=root / "profiles",
        internet_gateway=internet,
        execution_gateway=execution,
    )


def contract_summary(cases: Sequence[MultiTurnCase] = CORPUS) -> dict[str, Any]:
    errors = validation_errors(cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "valid": not errors,
        "live_model_executed": False,
        "case_count": len(cases),
        "turn_count": sum(len(case.turns) for case in cases),
        "corpus_sha256": corpus_sha256(cases),
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
    cases: Sequence[MultiTurnCase],
    *,
    source_sha: str = "",
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    errors = validation_errors(cases)
    if errors:
        raise ValueError("Invalid corpus: " + "; ".join(errors))
    endpoints = assert_local_model_endpoints(config)

    with tempfile.TemporaryDirectory(prefix="workspace-multiturn-") as temp:
        isolated = isolated_config(config, Path(temp))
        assert_local_model_endpoints(isolated)
        orchestrator = Orchestrator(isolated)
        orchestrator.initialize()
        recorder = RecordingLLM(orchestrator.llm)
        service = ContextAwareProjectChatService(
            SimpleNamespace(
                config=isolated,
                knowledge_gateway=orchestrator.knowledge_gateway,
                store=NoopStore(),
                llm=recorder,
            ),
            default_language=os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja"),
        )
        service.start()
        results = [run_case(service, recorder, case, timeout_seconds=timeout_seconds) for case in cases]
        service._queue.join()

    try:
        package_version = importlib.metadata.version("workspace-local-ai")
    except importlib.metadata.PackageNotFoundError:
        package_version = "unknown"
    model_name = config.model_policy.research_model if config.model_policy and config.model_policy.enabled else config.llm.model
    return {
        "schema_version": SCHEMA_VERSION,
        "live_model_executed": True,
        "passed": all(item["passed"] for item in results),
        "source_sha": str(source_sha or os.getenv("GITHUB_SHA") or "unknown")[:80],
        "package_version": package_version,
        "case_count": len(cases),
        "turn_count": sum(len(case.turns) for case in cases),
        "corpus_sha256": corpus_sha256(cases),
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
    parser = argparse.ArgumentParser(description="WorkSpace local-only multi-turn chat acceptance")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--contract", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--case", dest="case_ids", action="append", default=[])
    parser.add_argument("--config", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--source-sha", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cases = select_cases(args.case_ids)
        report = contract_summary(cases) if args.contract else run_live_suite(
            load_config(args.config or None),
            cases,
            source_sha=args.source_sha,
            timeout_seconds=args.timeout_seconds,
        )
    except Exception as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "live_model_executed": bool(args.live),
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}"[:1000],
            "privacy": {"raw_prompts_in_report": False, "raw_answers_in_report": False},
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


# Canonical metadata-only runtime diagnostics for multi-turn acceptance.
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

# Keep the authoritative P2 corpus/evaluator unchanged. This wrapper swaps the
# ordinary-chat service implementation under test to the current production
# ContractAwareProjectChatService and adds metadata-only runtime evidence.
import sys

acceptance = sys.modules[__name__]
from .chat_service_fidelity import ContractAwareProjectChatService
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

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Preserve metadata-only model evidence for structured decoding calls."""

        try:
            answer = self.delegate.generate_json(system_prompt, user_prompt, **kwargs)
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
