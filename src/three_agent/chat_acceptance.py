from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse

from .chat_fidelity import (
    direct_chat_answer_valid,
    direct_chat_system_prompt,
    language_neutral_response_matches_request,
    parse_chat_request,
)
from .config import AppConfig, load_config
from .orchestrator import Orchestrator

ACCEPTANCE_SCHEMA_VERSION = "workspace-chat-fidelity-acceptance/v1"
_ALLOWED_OUTPUT_KINDS = frozenset(
    {"prose", "json_object", "single_number", "code_only", "bullets"}
)
_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_]{2,63}$")
_NUMBER_RE = re.compile(r"[-+]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][-+]?\d+)?")
_BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+\S")


@dataclass(frozen=True)
class AcceptanceCase:
    case_id: str
    prompt: str
    expected_language: str
    output_kind: str = "prose"
    required_groups: tuple[tuple[str, ...], ...] = ()
    forbidden_terms: tuple[str, ...] = ()
    exact_items: int = 0
    max_lines: int = 0
    max_chars: int = 0
    json_keys: tuple[str, ...] = ()
    exact_text: str = ""
    effort: str = "standard"


@dataclass(frozen=True)
class AcceptanceResult:
    case_id: str
    passed: bool
    failures: tuple[str, ...]
    attempts: int = 0
    response_chars: int = 0

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


CHAT_ACCEPTANCE_CORPUS: tuple[AcceptanceCase, ...] = (
    AcceptanceCase(
        case_id="vi_dns_diagnosis",
        prompt=(
            "Hãy trả lời bằng tiếng Việt. Máy có thể ping 1.1.1.1 nhưng không mở được "
            "example.com. Nêu nguyên nhân có khả năng nhất và một lệnh kiểm tra DNS."
        ),
        expected_language="vi",
        required_groups=(("dns", "phân giải tên"), ("nslookup", "dig", "resolvectl")),
        max_chars=900,
    ),
    AcceptanceCase(
        case_id="en_http_404_one_sentence",
        prompt="Reply in English in one sentence: what does HTTP 404 mean?",
        expected_language="en",
        required_groups=(("not found",), ("resource", "page", "requested")),
        max_lines=1,
        max_chars=420,
    ),
    AcceptanceCase(
        case_id="ja_network_three_bullets",
        prompt=(
            "日本語で答えてください。Linuxでネットワーク障害を切り分ける確認項目を"
            "ちょうど3つの箇条書きで示してください。"
        ),
        expected_language="ja",
        output_kind="bullets",
        required_groups=(("ip", "アドレス"), ("ルート", "ゲートウェイ"), ("dns", "名前解決")),
        exact_items=3,
        max_chars=900,
    ),
    AcceptanceCase(
        case_id="vi_https_port_number",
        prompt="Hãy chỉ trả lời bằng một số duy nhất: cổng HTTPS mặc định là bao nhiêu?",
        expected_language="vi",
        output_kind="single_number",
        exact_text="443",
        max_lines=1,
        max_chars=8,
    ),
    AcceptanceCase(
        case_id="en_https_json_only",
        prompt=(
            "Reply in English with JSON only, no prose. Use keys protocol and port for the "
            "default HTTPS service."
        ),
        expected_language="en",
        output_kind="json_object",
        required_groups=(("https",), ("443",)),
        json_keys=("protocol", "port"),
        max_chars=160,
    ),
    AcceptanceCase(
        case_id="ja_linux_ip_code_only",
        prompt=(
            "LinuxでIPアドレスを表示するコマンドをコードブロックだけで返してください。"
            "日本語の説明文は不要です。"
        ),
        expected_language="ja",
        output_kind="code_only",
        required_groups=(("ip addr", "ip a"),),
        max_chars=240,
    ),
    AcceptanceCase(
        case_id="en_bind_three_bullets",
        prompt=(
            "Reply in English with exactly 3 bullet points listing common reasons a server "
            "cannot bind a TCP port."
        ),
        expected_language="en",
        output_kind="bullets",
        required_groups=(
            ("already in use", "in use", "occupied"),
            ("permission", "privilege"),
            ("address", "interface", "ip"),
        ),
        exact_items=3,
        max_chars=900,
    ),
    AcceptanceCase(
        case_id="vi_preserve_model_identifier",
        prompt=(
            "Hãy trả lời bằng tiếng Việt trong một câu và giữ nguyên chính xác tên biến "
            "WORKSPACE_LLM_MODEL: biến này dùng để chỉ gì?"
        ),
        expected_language="vi",
        required_groups=(("WORKSPACE_LLM_MODEL",), ("model", "mô hình")),
        max_lines=1,
        max_chars=500,
    ),
    AcceptanceCase(
        case_id="ja_ping_traceroute_normal_chat",
        prompt=(
            "日本語で答えてください。ping と traceroute の違いを簡潔に説明してください。"
            "通常チャットとして答え、調査レポートにはしないでください。"
        ),
        expected_language="ja",
        required_groups=(("ping",), ("traceroute",)),
        forbidden_terms=("# workspace report", "agent 1 · research", "presentation_ready"),
        max_chars=900,
    ),
    AcceptanceCase(
        case_id="en_translation_one_line",
        prompt=(
            "Translate the following into English in one line only: "
            "'Dịch vụ đã khởi động thành công.'"
        ),
        expected_language="en",
        required_groups=(("service",), ("started", "successfully", "success")),
        max_lines=1,
        max_chars=220,
    ),
    AcceptanceCase(
        case_id="vi_port_8080_two_steps",
        prompt=(
            "Hãy trả lời bằng tiếng Việt với đúng 2 gạch đầu dòng để kiểm tra vì sao dịch vụ "
            "không lắng nghe ở cổng 8080."
        ),
        expected_language="vi",
        output_kind="bullets",
        required_groups=(("8080",), ("ss", "netstat", "Get-NetTCPConnection")),
        exact_items=2,
        max_chars=900,
    ),
    AcceptanceCase(
        case_id="en_listening_socket_command_only",
        prompt="Command only, no explanation: show listening TCP sockets on Linux.",
        expected_language="en",
        output_kind="code_only",
        required_groups=(("ss", "netstat"),),
        max_lines=1,
        max_chars=160,
    ),
)


def _canonical_corpus_payload(cases: Sequence[AcceptanceCase]) -> list[dict[str, Any]]:
    return [asdict(case) for case in cases]


def corpus_sha256(cases: Sequence[AcceptanceCase] = CHAT_ACCEPTANCE_CORPUS) -> str:
    encoded = json.dumps(
        _canonical_corpus_payload(cases),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def corpus_validation_errors(
    cases: Sequence[AcceptanceCase] = CHAT_ACCEPTANCE_CORPUS,
) -> tuple[str, ...]:
    errors: list[str] = []
    seen: set[str] = set()
    for case in cases:
        if not _CASE_ID_RE.fullmatch(case.case_id):
            errors.append(f"invalid_case_id:{case.case_id}")
        if case.case_id in seen:
            errors.append(f"duplicate_case_id:{case.case_id}")
        seen.add(case.case_id)
        if case.output_kind not in _ALLOWED_OUTPUT_KINDS:
            errors.append(f"{case.case_id}:invalid_output_kind")
        if case.expected_language not in {"ja", "vi", "en"}:
            errors.append(f"{case.case_id}:invalid_expected_language")
        if case.effort not in {"standard", "high"}:
            errors.append(f"{case.case_id}:invalid_effort")
        if not case.prompt.strip():
            errors.append(f"{case.case_id}:empty_prompt")
            continue
        try:
            controls = parse_chat_request(case.prompt, selected_language="auto")
        except ValueError:
            errors.append(f"{case.case_id}:prompt_parse_failed")
        else:
            if controls.language != case.expected_language:
                errors.append(
                    f"{case.case_id}:language_resolves_{controls.language}_not_{case.expected_language}"
                )
        if case.exact_items < 0 or case.max_lines < 0 or case.max_chars < 0:
            errors.append(f"{case.case_id}:negative_limit")
        for group in case.required_groups:
            if not group or any(not str(term).strip() for term in group):
                errors.append(f"{case.case_id}:invalid_required_group")
    return tuple(errors)


def _nonempty_lines(text: str) -> list[str]:
    return [line for line in str(text or "").splitlines() if line.strip()]


def evaluate_answer(case: AcceptanceCase, answer: str, *, attempts: int = 0) -> AcceptanceResult:
    failures: list[str] = []
    body = str(answer or "").strip()
    valid, reason = direct_chat_answer_valid(body, case.expected_language, case.prompt)
    if not valid:
        failures.append(f"direct_chat:{reason}")

    lowered = body.casefold()
    for index, group in enumerate(case.required_groups, 1):
        if not any(str(term).casefold() in lowered for term in group):
            failures.append(f"missing_required_group:{index}")
    for term in case.forbidden_terms:
        if str(term).casefold() in lowered:
            failures.append(f"forbidden_term:{str(term).casefold()}")

    if case.output_kind == "json_object":
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            failures.append("format:not_json")
        else:
            if not isinstance(parsed, dict):
                failures.append("format:not_json_object")
            else:
                missing_keys = [key for key in case.json_keys if key not in parsed]
                if missing_keys:
                    failures.append("format:missing_json_keys:" + ",".join(missing_keys))
    elif case.output_kind == "single_number":
        if _NUMBER_RE.fullmatch(body) is None:
            failures.append("format:not_single_number")
    elif case.output_kind == "code_only":
        if not language_neutral_response_matches_request(body, case.prompt):
            failures.append("format:not_code_only")
    elif case.output_kind == "bullets":
        lines = _nonempty_lines(body)
        bullets = [line for line in lines if _BULLET_RE.match(line)]
        if len(bullets) != len(lines):
            failures.append("format:non_bullet_text")
        if case.exact_items and len(bullets) != case.exact_items:
            failures.append(f"format:bullet_count:{len(bullets)}_not_{case.exact_items}")

    if case.exact_text and body != case.exact_text:
        failures.append("format:exact_text_mismatch")
    line_count = len(_nonempty_lines(body))
    if case.max_lines and line_count > case.max_lines:
        failures.append(f"limit:lines:{line_count}_gt_{case.max_lines}")
    if case.max_chars and len(body) > case.max_chars:
        failures.append(f"limit:chars:{len(body)}_gt_{case.max_chars}")

    unique_failures = tuple(dict.fromkeys(failures))
    return AcceptanceResult(
        case_id=case.case_id,
        passed=not unique_failures,
        failures=unique_failures,
        attempts=attempts,
        response_chars=len(body),
    )


def endpoint_is_local(url: str) -> bool:
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.casefold().rstrip(".")
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_unspecified:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local)


def configured_model_urls(config: AppConfig) -> tuple[str, ...]:
    urls = [config.llm.base_url]
    policy = config.model_policy
    raw_policy = config.raw.get("model_policy", {}) if isinstance(config.raw, dict) else {}
    raw_workers = raw_policy.get("worker_pool", {}) if isinstance(raw_policy, dict) else {}
    if policy and policy.enabled and bool(raw_workers.get("enabled", False)):
        urls.extend(
            [
                os.getenv(
                    "THREE_AGENT_GPU0_OLLAMA_URL",
                    str(raw_workers.get("gpu0_url", "http://127.0.0.1:11435")),
                ),
                os.getenv(
                    "THREE_AGENT_GPU1_OLLAMA_URL",
                    str(raw_workers.get("gpu1_url", "http://127.0.0.1:11436")),
                ),
                os.getenv(
                    "THREE_AGENT_DUAL_OLLAMA_URL",
                    str(raw_workers.get("dual_url", config.llm.base_url)),
                ),
            ]
        )
    return tuple(dict.fromkeys(str(url).rstrip("/") for url in urls))


def assert_local_model_endpoints(config: AppConfig) -> tuple[str, ...]:
    urls = configured_model_urls(config)
    if not urls or any(not endpoint_is_local(url) for url in urls):
        raise ValueError("Live chat acceptance requires only localhost/private/link-local Ollama endpoints")
    return urls


def select_cases(case_ids: Iterable[str] | None) -> tuple[AcceptanceCase, ...]:
    requested = tuple(str(case_id).strip() for case_id in (case_ids or ()) if str(case_id).strip())
    if not requested:
        return CHAT_ACCEPTANCE_CORPUS
    by_id = {case.case_id: case for case in CHAT_ACCEPTANCE_CORPUS}
    unknown = [case_id for case_id in requested if case_id not in by_id]
    if unknown:
        raise ValueError("Unknown acceptance case: " + ", ".join(unknown))
    return tuple(by_id[case_id] for case_id in requested)


def _model_route(config: AppConfig) -> str:
    policy = config.model_policy
    if policy and policy.enabled:
        return policy.research_model
    return config.llm.model


def run_live_case(orchestrator: Any, case: AcceptanceCase) -> tuple[AcceptanceResult, str]:
    controls = parse_chat_request(case.prompt, selected_language="auto")
    prompt = "\n".join(
        ("<CURRENT_USER_REQUEST>", controls.text, "</CURRENT_USER_REQUEST>")
    )
    answer = ""
    attempts = 0
    for attempt in range(2):
        attempts = attempt + 1
        answer = orchestrator.llm.generate(
            direct_chat_system_prompt(
                controls.language,
                effort=case.effort,
                repair=attempt > 0,
            ),
            prompt,
            think=case.effort == "high",
            num_predict=4096,
            trust_domain="workspace-local-chat",
            template_version="workspace.chat.direct.v1",
        )
        valid, _ = direct_chat_answer_valid(answer, controls.language, controls.text)
        if valid:
            break
    return evaluate_answer(case, answer, attempts=attempts), str(answer or "")


def contract_summary(cases: Sequence[AcceptanceCase]) -> dict[str, Any]:
    errors = corpus_validation_errors(CHAT_ACCEPTANCE_CORPUS)
    selected_ids = [case.case_id for case in cases]
    return {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "mode": "contract",
        "valid": not errors,
        "corpus_case_count": len(CHAT_ACCEPTANCE_CORPUS),
        "selected_case_count": len(cases),
        "selected_case_ids": selected_ids,
        "corpus_sha256": corpus_sha256(),
        "errors": list(errors),
        "live_model_executed": False,
    }


def live_summary(
    config: AppConfig,
    orchestrator: Any,
    cases: Sequence[AcceptanceCase],
    *,
    show_responses: bool = False,
) -> dict[str, Any]:
    endpoint_count = len(assert_local_model_endpoints(config))
    results: list[AcceptanceResult] = []
    for case in cases:
        try:
            result, answer = run_live_case(orchestrator, case)
        except Exception as exc:
            result = AcceptanceResult(
                case_id=case.case_id,
                passed=False,
                failures=(f"runtime:{type(exc).__name__}",),
                attempts=0,
                response_chars=0,
            )
            answer = ""
        results.append(result)
        if show_responses:
            print(f"=== {case.case_id} ===")
            print(answer)
    passed = sum(result.passed for result in results)
    return {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "mode": "live_local_model",
        "corpus_sha256": corpus_sha256(),
        "case_count": len(results),
        "passed_count": passed,
        "failed_count": len(results) - passed,
        "all_passed": passed == len(results),
        "model_route": _model_route(config),
        "local_endpoints_checked": endpoint_count,
        "raw_responses_persisted": False,
        "cases": [result.public_dict() for result in results],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-chat-acceptance",
        description="Deterministic multilingual WorkSpace chat-fidelity acceptance harness.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run the corpus against the configured local WorkSpace model route",
    )
    parser.add_argument("--config", help="WorkSpace config path used only with --live")
    parser.add_argument(
        "--case",
        action="append",
        dest="case_ids",
        help="Run/select one case id; repeat to select multiple cases",
    )
    parser.add_argument(
        "--show-responses",
        action="store_true",
        help="Print synthetic live responses to stdout; never persisted by this tool",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cases = select_cases(args.case_ids)
    except ValueError as exc:
        print(
            json.dumps(
                {"schema_version": ACCEPTANCE_SCHEMA_VERSION, "error": str(exc)},
                ensure_ascii=False,
            )
        )
        return 2

    if not args.live:
        summary = contract_summary(cases)
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if summary["valid"] else 3

    errors = corpus_validation_errors(CHAT_ACCEPTANCE_CORPUS)
    if errors:
        print(
            json.dumps(
                {
                    "schema_version": ACCEPTANCE_SCHEMA_VERSION,
                    "error": "corpus_validation_failed",
                    "failures": list(errors),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3

    try:
        config = load_config(args.config)
        assert_local_model_endpoints(config)
        orchestrator = Orchestrator(config)
        orchestrator.initialize()
        summary = live_summary(
            config,
            orchestrator,
            cases,
            show_responses=bool(args.show_responses),
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": ACCEPTANCE_SCHEMA_VERSION,
                    "mode": "live_local_model",
                    "error": type(exc).__name__,
                    "live_model_executed": False,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["all_passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
