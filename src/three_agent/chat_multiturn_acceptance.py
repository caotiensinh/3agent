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

MULTITURN_ACCEPTANCE_SCHEMA_VERSION = "workspace-chat-multiturn-acceptance/v1"
_ALLOWED_CONTEXT_MODES = frozenset({CONTEXT_MODE_STANDALONE, CONTEXT_MODE_FOLLOW_UP})
_ALLOWED_LANGUAGES = frozenset({"vi", "en", "ja"})
_ALLOWED_OUTPUT_KINDS = frozenset({"prose", "json_object", "single_number", "code_only", "bullets"})


@dataclass(frozen=True)
class MultiTurnSpec:
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
    expect_context_available: bool | None = None


@dataclass(frozen=True)
class MultiTurnCase:
    case_id: str
    turns: tuple[MultiTurnSpec, ...]


@dataclass(frozen=True)
class PromptCallEvidence:
    prompt_sha256: str
    prompt_chars: int
    has_current_request: bool
    has_follow_up_policy: bool
    has_standalone_policy: bool
    has_recent_context: bool
    context_marked_unavailable: bool


@dataclass(frozen=True)
class MultiTurnResult:
    turn_index: int
    passed: bool
    failures: tuple[str, ...]
    expected_language: str
    actual_language: str
    expected_context_mode: str
    actual_context_mode: str
    context_message_count: int
    attempts: int
    response_sha256: str
    response_chars: int
    prompt_evidence: PromptCallEvidence

    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["failures"] = list(self.failures)
        return payload


MULTITURN_ACCEPTANCE_CORPUS: tuple[MultiTurnCase, ...] = (
    MultiTurnCase(
        case_id="vi_network_reference_chain",
        turns=(
            MultiTurnSpec(
                prompt=(
                    "Hãy trả lời bằng tiếng Việt với đúng 3 gạch đầu dòng theo thứ tự: "
                    "(1) kiểm tra địa chỉ IP bằng ip addr; (2) kiểm tra default gateway bằng "
                    "ip route; (3) kiểm tra DNS bằng resolvectl status."
                ),
                expected_language="vi",
                expected_context_mode=CONTEXT_MODE_STANDALONE,
                output_kind="bullets",
                required_groups=(("ip addr",), ("ip route",), ("resolvectl", "dns")),
                exact_items=3,
                max_chars=900,
                expect_context_available=False,
            ),
            MultiTurnSpec(
                prompt="Cái thứ hai: giải thích trong đúng một câu.",
                expected_language="vi",
                expected_context_mode=CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("gateway", "cổng mặc định"),),
                max_lines=1,
                max_chars=500,
                min_context_messages=2,
                expect_context_available=True,
            ),
            MultiTurnSpec(
                prompt="Phần đó, chỉ đưa lệnh thôi.",
                expected_language="vi",
                expected_context_mode=CONTEXT_MODE_FOLLOW_UP,
                output_kind="code_only",
                required_groups=(("ip route",),),
                max_chars=160,
                min_context_messages=2,
                expect_context_available=True,
            ),
        ),
    ),
    MultiTurnCase(
        case_id="en_reference_then_language_override",
        turns=(
            MultiTurnSpec(
                prompt=(
                    "Reply in English with exactly 2 bullet points: first, ping checks reachability; "
                    "second, traceroute shows the path hops."
                ),
                expected_language="en",
                expected_context_mode=CONTEXT_MODE_STANDALONE,
                output_kind="bullets",
                required_groups=(("ping",), ("traceroute",)),
                exact_items=2,
                max_chars=700,
                expect_context_available=False,
            ),
            MultiTurnSpec(
                prompt=(
                    "The second one: reply in Vietnamese in one sentence and keep the word "
                    "traceroute unchanged."
                ),
                expected_language="vi",
                expected_context_mode=CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("traceroute",), ("đường", "hop", "tuyến", "lộ trình")),
                max_lines=1,
                max_chars=500,
                min_context_messages=2,
                expect_context_available=True,
            ),
            MultiTurnSpec(
                prompt="Cái đó, chỉ trả lời một lệnh Linux.",
                expected_language="vi",
                expected_context_mode=CONTEXT_MODE_FOLLOW_UP,
                output_kind="code_only",
                required_groups=(("traceroute", "tracepath"),),
                max_chars=160,
                min_context_messages=2,
                expect_context_available=True,
            ),
        ),
    ),
    MultiTurnCase(
        case_id="ja_network_reference_chain",
        turns=(
            MultiTurnSpec(
                prompt=(
                    "日本語で、次の順序どおりにちょうど3つの箇条書きで答えてください。"
                    "1つ目は ip addr でIPアドレス確認、2つ目は ip route でデフォルト"
                    "ゲートウェイ確認、3つ目は resolvectl status でDNS確認です。"
                ),
                expected_language="ja",
                expected_context_mode=CONTEXT_MODE_STANDALONE,
                output_kind="bullets",
                required_groups=(("ip addr",), ("ip route",), ("resolvectl", "dns")),
                exact_items=3,
                max_chars=900,
                expect_context_available=False,
            ),
            MultiTurnSpec(
                prompt="2つ目だけを一文で詳しく説明してください。",
                expected_language="ja",
                expected_context_mode=CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("ゲートウェイ", "gateway"),),
                max_lines=1,
                max_chars=500,
                min_context_messages=2,
                expect_context_available=True,
            ),
            MultiTurnSpec(
                prompt="その設定について、コマンドだけ返してください。",
                expected_language="ja",
                expected_context_mode=CONTEXT_MODE_FOLLOW_UP,
                output_kind="code_only",
                required_groups=(("ip route",),),
                max_chars=160,
                min_context_messages=2,
                expect_context_available=True,
            ),
        ),
    ),
    MultiTurnCase(
        case_id="stale_history_isolation",
        turns=(
            MultiTurnSpec(
                prompt=(
                    "Reply in English in one sentence. Include the exact marker LEGACY_ALPHA and "
                    "state that PostgreSQL commonly listens on TCP port 5432."
                ),
                expected_language="en",
                expected_context_mode=CONTEXT_MODE_STANDALONE,
                required_groups=(("LEGACY_ALPHA",), ("PostgreSQL",), ("5432",)),
                max_lines=1,
                max_chars=450,
                expect_context_available=False,
            ),
            MultiTurnSpec(
                prompt=(
                    "Hãy chỉ trả lời bằng một số duy nhất: cổng HTTPS mặc định là bao nhiêu?"
                ),
                expected_language="vi",
                expected_context_mode=CONTEXT_MODE_STANDALONE,
                output_kind="single_number",
                forbidden_terms=("LEGACY_ALPHA", "PostgreSQL", "5432"),
                exact_text="443",
                max_lines=1,
                max_chars=8,
                expect_context_available=False,
            ),
        ),
    ),
    MultiTurnCase(
        case_id="vi_missing_reference_clarifies",
        turns=(
            MultiTurnSpec(
                prompt="tiếp theo?",
                expected_language="vi",
                expected_context_mode=CONTEXT_MODE_FOLLOW_UP,
                required_groups=(("phần", "nội dung", "trước", "cung cấp", "muốn", "tiếp tục"),),
                max_chars=400,
                min_context_messages=0,
                expect_context_available=False,
            ),
        ),
    ),
)


class _NoopActivityStore:
    def record_activity(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs


class _RecordingLLM:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.calls: list[PromptCallEvidence] = []

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        del system_prompt
        body = str(user_prompt or "")
        self.calls.append(
            PromptCallEvidence(
                prompt_sha256="sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest(),
                prompt_chars=len(body),
                has_current_request="<CURRENT_USER_REQUEST>" in body,
                has_follow_up_policy='mode="follow_up"' in body,
                has_standalone_policy='mode="standalone"' in body,
                has_recent_context="<RECENT_CONVERSATION_CONTEXT>" in body,
                context_marked_unavailable='available="false"' in body,
            )
        )
        return self.delegate.generate(system_prompt, user_prompt, **kwargs)


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _canonical_corpus_payload(cases: Sequence[MultiTurnCase]) -> list[dict[str, Any]]:
    return [asdict(case) for case in cases]


def multiturn_corpus_sha256(
    cases: Sequence[MultiTurnCase] = MULTITURN_ACCEPTANCE_CORPUS,
) -> str:
    encoded = json.dumps(
        _canonical_corpus_payload(cases),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def corpus_validation_errors(
    cases: Sequence[MultiTurnCase] = MULTITURN_ACCEPTANCE_CORPUS,
) -> tuple[str, ...]:
    failures: list[str] = []
    seen: set[str] = set()
    for case in cases:
        if not case.case_id or case.case_id in seen:
            failures.append(f"invalid_or_duplicate_case:{case.case_id}")
        seen.add(case.case_id)
        if not case.turns:
            failures.append(f"{case.case_id}:empty_turns")
        for index, turn in enumerate(case.turns, 1):
            prefix = f"{case.case_id}:turn_{index}"
            if not turn.prompt.strip():
                failures.append(prefix + ":empty_prompt")
            if turn.expected_language not in _ALLOWED_LANGUAGES:
                failures.append(prefix + ":invalid_language")
            if turn.expected_context_mode not in _ALLOWED_CONTEXT_MODES:
                failures.append(prefix + ":invalid_context_mode")
            if turn.output_kind not in _ALLOWED_OUTPUT_KINDS:
                failures.append(prefix + ":invalid_output_kind")
            if turn.selected_language not in {"auto", "vi", "en", "ja"}:
                failures.append(prefix + ":invalid_selected_language")
            if turn.effort not in {"standard", "high"}:
                failures.append(prefix + ":invalid_effort")
            if min(turn.exact_items, turn.max_lines, turn.max_chars, turn.min_context_messages) < 0:
                failures.append(prefix + ":negative_limit")
    return tuple(failures)


def select_cases(case_ids: Iterable[str] | None) -> tuple[MultiTurnCase, ...]:
    requested = tuple(str(item).strip() for item in (case_ids or ()) if str(item).strip())
    if not requested:
        return MULTITURN_ACCEPTANCE_CORPUS
    by_id = {case.case_id: case for case in MULTITURN_ACCEPTANCE_CORPUS}
    unknown = [item for item in requested if item not in by_id]
    if unknown:
        raise ValueError("Unknown multi-turn acceptance case: " + ", ".join(unknown))
    return tuple(by_id[item] for item in requested)


def _as_acceptance_case(case_id: str, index: int, turn: MultiTurnSpec) -> AcceptanceCase:
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


def _wait_for_job(service: ContextAwareProjectChatService, job_id: str, timeout_seconds: float) -> Any:
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    current = service.get(job_id)
    while current is not None and current.status in {"queued", "running"}:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"multi-turn acceptance job timed out: {job_id}")
        time.sleep(0.05)
        current = service.get(job_id)
    if current is None:
        raise RuntimeError(f"multi-turn acceptance job disappeared: {job_id}")
    return current


def run_case(
    service: ContextAwareProjectChatService,
    recording_llm: _RecordingLLM,
    case: MultiTurnCase,
    *,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    sender = f"workspace-user:acceptance-{_sha256_text(case.case_id)[7:23]}"
    channel = "acceptance"
    owner_key = _history_owner_key(channel, sender)
    conversation_id = service.history.create_conversation(owner_key, f"Acceptance {case.case_id}")
    turn_results: list[MultiTurnResult] = []

    for index, turn in enumerate(case.turns, 1):
        calls_before = len(recording_llm.calls)
        job = service.submit(
            turn.prompt,
            channel=channel,
            sender=sender,
            language=turn.selected_language,
            request_mode="chat",
            effort=turn.effort,
            conversation_id=conversation_id,
        )
        current = _wait_for_job(service, job.job_id, timeout_seconds)
        calls_after = len(recording_llm.calls)
        new_calls = recording_llm.calls[calls_before:calls_after]
        prompt_evidence = new_calls[0] if new_calls else PromptCallEvidence(
            prompt_sha256="sha256:" + ("0" * 64),
            prompt_chars=0,
            has_current_request=False,
            has_follow_up_policy=False,
            has_standalone_policy=False,
            has_recent_context=False,
            context_marked_unavailable=False,
        )
        plan = service.context_plan_for_job(job.job_id)
        actual_context_mode = plan.mode if plan is not None else "missing"
        context_message_count = int(plan.message_count) if plan is not None else 0
        failures: list[str] = []

        if current.status != "completed":
            failures.append(f"job_status:{current.status}")
        if current.language != turn.expected_language:
            failures.append(f"language:{current.language}_not_{turn.expected_language}")
        if actual_context_mode != turn.expected_context_mode:
            failures.append(
                f"context_mode:{actual_context_mode}_not_{turn.expected_context_mode}"
            )
        if turn.expected_context_mode == CONTEXT_MODE_STANDALONE:
            if context_message_count != 0:
                failures.append(f"standalone_context_messages:{context_message_count}")
            if not prompt_evidence.has_standalone_policy:
                failures.append("prompt:missing_standalone_policy")
            if prompt_evidence.has_recent_context:
                failures.append("prompt:standalone_history_present")
        else:
            if not prompt_evidence.has_follow_up_policy:
                failures.append("prompt:missing_follow_up_policy")
            if context_message_count < turn.min_context_messages:
                failures.append(
                    f"context_messages:{context_message_count}_lt_{turn.min_context_messages}"
                )
        if not prompt_evidence.has_current_request:
            failures.append("prompt:missing_current_request_boundary")
        if turn.expect_context_available is True and prompt_evidence.context_marked_unavailable:
            failures.append("prompt:context_unexpectedly_unavailable")
        if turn.expect_context_available is False:
            if turn.expected_context_mode == CONTEXT_MODE_FOLLOW_UP:
                if not prompt_evidence.context_marked_unavailable:
                    failures.append("prompt:missing_unavailable_context_marker")
            elif prompt_evidence.has_recent_context:
                failures.append("prompt:standalone_context_present")

        answer = str(current.answer or "").strip()
        evaluated = evaluate_answer(
            _as_acceptance_case(case.case_id, index, turn),
            answer,
            attempts=len(new_calls),
        )
        failures.extend(evaluated.failures)
        failures = list(dict.fromkeys(failures))
        turn_results.append(
            MultiTurnResult(
                turn_index=index,
                passed=not failures,
                failures=tuple(failures),
                expected_language=turn.expected_language,
                actual_language=str(current.language or ""),
                expected_context_mode=turn.expected_context_mode,
                actual_context_mode=actual_context_mode,
                context_message_count=context_message_count,
                attempts=len(new_calls),
                response_sha256=_sha256_text(answer),
                response_chars=len(answer),
                prompt_evidence=prompt_evidence,
            )
        )

    return {
        "case_id": case.case_id,
        "passed": all(item.passed for item in turn_results),
        "turns": [item.public_dict() for item in turn_results],
    }


def _isolated_config(config: AppConfig, root: Path) -> AppConfig:
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
        database_path=root / "acceptance.db",
        artifact_root=root / "artifacts",
        profile_root=root / "profiles",
        internet_gateway=internet,
        execution_gateway=execution,
        test_mode_full_access=False,
    )


def _model_identity_hash(config: AppConfig) -> str:
    model = config.model_policy.research_model if config.model_policy and config.model_policy.enabled else config.llm.model
    return _sha256_text(model)


def contract_summary(
    cases: Sequence[MultiTurnCase] = MULTITURN_ACCEPTANCE_CORPUS,
) -> dict[str, Any]:
    errors = corpus_validation_errors(cases)
    return {
        "schema_version": MULTITURN_ACCEPTANCE_SCHEMA_VERSION,
        "valid": not errors,
        "live_model_executed": False,
        "case_count": len(cases),
        "turn_count": sum(len(case.turns) for case in cases),
        "corpus_sha256": multiturn_corpus_sha256(cases),
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
    errors = corpus_validation_errors(cases)
    if errors:
        raise ValueError("Invalid multi-turn acceptance corpus: " + "; ".join(errors))
    assert_local_model_endpoints(config)

    with tempfile.TemporaryDirectory(prefix="workspace-multiturn-acceptance-") as temp:
        root = Path(temp)
        isolated = _isolated_config(config, root)
        assert_local_model_endpoints(isolated)
        orchestrator = Orchestrator(isolated)
        orchestrator.initialize()
        recording_llm = _RecordingLLM(orchestrator.llm)
        service_orchestrator = SimpleNamespace(
            config=isolated,
            knowledge_gateway=orchestrator.knowledge_gateway,
            store=_NoopActivityStore(),
            llm=recording_llm,
        )
        service = ContextAwareProjectChatService(
            service_orchestrator,
            default_language=os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja"),
        )
        service.start()
        results = [
            run_case(
                service,
                recording_llm,
                case,
                timeout_seconds=timeout_seconds,
            )
            for case in cases
        ]
        service._queue.join()

    try:
        package_version = importlib.metadata.version("workspace-local-ai")
    except importlib.metadata.PackageNotFoundError:
        package_version = "unknown"
    payload = {
        "schema_version": MULTITURN_ACCEPTANCE_SCHEMA_VERSION,
        "live_model_executed": True,
        "passed": all(bool(item["passed"]) for item in results),
        "source_sha": str(source_sha or os.getenv("GITHUB_SHA") or "unknown")[:80],
        "package_version": package_version,
        "case_count": len(cases),
        "turn_count": sum(len(case.turns) for case in cases),
        "corpus_sha256": multiturn_corpus_sha256(cases),
        "endpoint_policy": "localhost_private_link_local_only",
        "endpoint_count": len(assert_local_model_endpoints(config)),
        "model_identity_sha256": _model_identity_hash(config),
        "privacy": {
            "raw_prompts_in_report": False,
            "raw_answers_in_report": False,
            "production_database_mutated": False,
            "public_egress_enabled": False,
        },
        "results": results,
    }
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WorkSpace local-only multi-turn conversation acceptance"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--contract", action="store_true", help="Validate corpus only; no model call")
    mode.add_argument("--live", action="store_true", help="Run local model through the v16 service path")
    parser.add_argument("--case", dest="case_ids", action="append", default=[])
    parser.add_argument("--config", default="", help="Optional WorkSpace config path")
    parser.add_argument("--output", default="", help="Write sanitized JSON evidence to this path")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--source-sha", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cases = select_cases(args.case_ids)
        if args.contract:
            report = contract_summary(cases)
        else:
            config = load_config(args.config or None)
            report = run_live_suite(
                config,
                cases,
                source_sha=args.source_sha,
                timeout_seconds=args.timeout_seconds,
            )
    except Exception as exc:
        report = {
            "schema_version": MULTITURN_ACCEPTANCE_SCHEMA_VERSION,
            "live_model_executed": bool(args.live),
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}"[:1000],
            "privacy": {
                "raw_prompts_in_report": False,
                "raw_answers_in_report": False,
            },
        }

    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    passed = bool(report.get("passed", report.get("valid", False)))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
