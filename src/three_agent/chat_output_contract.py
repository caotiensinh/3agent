from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .chat_fidelity import requested_language_neutral_format


_BULLET_LINE_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+\S")
_BULLET_PREFIX_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")
_SENTENCE_TERMINATOR_RE = re.compile(r"[!?。！？]+|\.(?=\s|$)")
_BRIEF_PROSE_MAX_CHARS = 600
_BRIEF_PROSE_NUM_PREDICT = 128
STRICT_STRUCTURED_OUTPUT_KINDS = frozenset(
    {"bullets", "single_sentence", "single_number", "code_only"}
)


def _sentence_terminator_count(text: str) -> int:
    """Count likely sentence terminators without treating decimals as boundaries."""

    body = str(text or "").strip()
    if not body:
        return 0
    body = re.sub(r"(?<=\d)\.(?=\d)", "", body)
    body = re.sub(r"\b(?:e\.g|i\.e)\.", "", body, flags=re.IGNORECASE)
    return len(_SENTENCE_TERMINATOR_RE.findall(body))


@dataclass(frozen=True)
class ChatOutputContract:
    """Deterministic current-request response-shape contract.

    The contract is derived only from the current user request. It never reads
    prior conversation text and never grants model/tool/network authority.
    """

    kind: str
    exact_items: int = 0
    max_lines: int = 0
    max_chars: int = 0
    num_predict: int = 0
    instruction: str = ""

    def validate(self, answer: str) -> tuple[bool, str]:
        body = str(answer or "").strip()
        if not body:
            return False, "output_contract_empty"
        if self.max_chars and len(body) > self.max_chars:
            return False, f"output_contract_chars:{len(body)}_gt_{self.max_chars}"

        nonempty_lines = [line for line in body.splitlines() if line.strip()]
        if self.max_lines and len(nonempty_lines) > self.max_lines:
            return False, f"output_contract_lines:{len(nonempty_lines)}_gt_{self.max_lines}"

        if self.kind == "bullets":
            bullet_lines = [line for line in nonempty_lines if _BULLET_LINE_RE.match(line)]
            if len(bullet_lines) != len(nonempty_lines):
                return False, "output_contract_non_bullet_text"
            if self.exact_items and len(bullet_lines) != self.exact_items:
                return False, f"output_contract_bullets:{len(bullet_lines)}_not_{self.exact_items}"
        elif self.kind == "single_sentence":
            if _sentence_terminator_count(body) > 1:
                return False, "output_contract_multiple_sentences"
        elif self.kind == "json_only":
            try:
                json.loads(body)
            except (TypeError, ValueError, json.JSONDecodeError):
                return False, "output_contract_invalid_json"
        elif self.kind == "single_number":
            if re.fullmatch(r"[-+]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][-+]?\d+)?", body) is None:
                return False, "output_contract_not_single_number"
        elif self.kind == "code_only":
            # The established chat_fidelity validator performs the authoritative
            # command/code shape check. This layer only enforces bounded size.
            pass
        return True, "ok"


def strict_structured_schema(contract: ChatOutputContract) -> dict[str, Any] | None:
    """Return a decoder-time intermediate schema for strict standard-chat shapes.

    The intermediate representation exists only in memory. It is rendered into
    the user's requested plain-text shape before the existing language/format
    and output-contract validators run. It does not relax any validator or
    persist model output.
    """

    if contract.kind == "bullets" and contract.exact_items > 0:
        properties = {
            f"item_{index}": {
                "type": "string",
                "description": (
                    f"Content for bullet {index} only. Do not include a bullet marker, heading, "
                    "preface, or suffix."
                ),
            }
            for index in range(1, contract.exact_items + 1)
        }
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }
    if contract.kind == "single_sentence":
        return {
            "type": "object",
            "properties": {
                "answer": {
                    "type": "string",
                    "description": "Exactly one concise answer sentence and no heading or note.",
                }
            },
            "required": ["answer"],
            "additionalProperties": False,
        }
    if contract.kind == "single_number":
        return {
            "type": "object",
            "properties": {
                "value": {
                    "type": "number",
                    "description": "The requested numeric value only.",
                }
            },
            "required": ["value"],
            "additionalProperties": False,
        }
    if contract.kind == "code_only":
        return {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Requested code or command only, without explanatory prose.",
                }
            },
            "required": ["code"],
            "additionalProperties": False,
        }
    return None


def strict_structured_schema_id(contract: ChatOutputContract) -> str:
    if contract.kind == "bullets":
        return f"workspace.chat.strict.bullets.{contract.exact_items}.v1"
    return f"workspace.chat.strict.{contract.kind}.v1"


def _single_line(value: object, *, strip_bullet_prefix: bool = False) -> str:
    body = " ".join(str(value or "").split()).strip()
    if strip_bullet_prefix:
        body = _BULLET_PREFIX_RE.sub("", body, count=1).strip()
    return body


def render_strict_structured_answer(
    contract: ChatOutputContract,
    payload: dict[str, Any],
) -> str:
    """Render the intermediate object into the exact user-visible text family."""

    if contract.kind == "bullets":
        items = [
            _single_line(payload.get(f"item_{index}"), strip_bullet_prefix=True)
            for index in range(1, contract.exact_items + 1)
        ]
        return "\n".join(f"- {item}" for item in items if item).strip()
    if contract.kind == "single_sentence":
        return _single_line(payload.get("answer"))
    if contract.kind == "single_number":
        value = payload.get("value")
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        if isinstance(value, float):
            return format(value, ".15g")
        return str(value or "").strip()
    if contract.kind == "code_only":
        return str(payload.get("code") or "").strip()
    raise ValueError(f"Unsupported strict structured output kind: {contract.kind}")


def _exact_bullet_count(request: str) -> int:
    text = " ".join(str(request or "").split())
    patterns = (
        r"\bexactly\s+(\d{1,2})\s+(?:bullet(?:\s+point)?s?|bullets?)\b",
        r"\b(?:with|in)\s+(\d{1,2})\s+(?:bullet(?:\s+point)?s?|bullets?)\b",
        r"(?:đúng|dung|chính\s+xác|chinh\s+xac)\s+(\d{1,2})\s+(?:gạch\s+đầu\s+dòng|gach\s+dau\s+dong|ý|y)\b",
        r"(\d{1,2})\s+(?:gạch\s+đầu\s+dòng|gach\s+dau\s+dong)\b",
        r"(?:ちょうど|必ず)?\s*(\d{1,2})\s*(?:つ|個)?の箇条書き",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = int(match.group(1))
            if 1 <= value <= 20:
                return value
    return 0


def _requests_single_sentence(request: str) -> bool:
    text = " ".join(str(request or "").casefold().split())
    patterns = (
        r"\b(?:in\s+)?(?:exactly\s+)?(?:one|1)\s+sentence\b",
        r"(?:đúng|dung|chỉ|chi)?\s*(?:một|mot|1)\s+câu\b(?!\s+hỏi)",
        r"(?:一文|1文)(?:で|だけ|のみ|に|。|$)",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _requests_brief_response(request: str) -> bool:
    """Detect explicit current-request brevity intent in supported chat languages."""

    text = " ".join(str(request or "").casefold().split())
    patterns = (
        r"\bbriefly\b",
        r"\bbe\s+brief\b",
        r"\bconcise(?:ly)?\b",
        r"\bin\s+brief\b",
        r"\bbrief\s+(?:answer|response|introduction|intro|summary)\b",
        r"\bshort\s+(?:answer|response|introduction|intro|summary)\b",
        r"\bngắn\s+gọn\b",
        r"\bngắn\s+thôi\b",
        r"\btrả\s+lời\s+ngắn\b",
        r"\btóm\s+tắt\s+ngắn\b",
        r"簡単に",
        r"簡潔に",
        r"短く",
        r"手短に",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def compile_chat_output_contract(request: str, *, effort: str = "standard") -> ChatOutputContract:
    """Compile bounded response-shape rules from the current request only."""

    neutral = requested_language_neutral_format(request)
    if neutral == "number":
        return ChatOutputContract(
            kind="single_number",
            max_lines=1,
            max_chars=32,
            num_predict=16,
            instruction="Return exactly one numeric value and nothing else.",
        )
    if neutral == "code":
        return ChatOutputContract(
            kind="code_only",
            max_chars=160,
            num_predict=96,
            instruction="Return only the requested code or command. No explanation, heading, preface, or suffix.",
        )
    if neutral == "json":
        return ChatOutputContract(
            kind="json_only",
            max_chars=2_000,
            num_predict=512,
            instruction="Return one valid JSON value only. Do not wrap it in Markdown or add prose.",
        )

    bullets = _exact_bullet_count(request)
    if bullets:
        max_chars = min(4_000, 180 + 220 * bullets)
        num_predict = min(768, 96 + 64 * bullets)
        return ChatOutputContract(
            kind="bullets",
            exact_items=bullets,
            max_chars=max_chars,
            num_predict=num_predict,
            instruction=(
                f"Return exactly {bullets} bullet lines and no text outside those bullets. "
                "Each bullet must directly satisfy the current request."
            ),
        )

    if _requests_single_sentence(request):
        return ChatOutputContract(
            kind="single_sentence",
            max_lines=1,
            max_chars=400,
            num_predict=128,
            instruction="Return exactly one concise sentence. Do not add a heading, bullets, notes, or a second sentence.",
        )

    if _requests_brief_response(request):
        return ChatOutputContract(
            kind="brief_prose",
            max_chars=_BRIEF_PROSE_MAX_CHARS,
            num_predict=_BRIEF_PROSE_NUM_PREDICT,
            instruction=(
                "Answer briefly and directly using only the minimum detail needed; normally use 2-4 short sentences. "
                "Do not add headings, unrelated sections, or repeat the prompt."
            ),
        )

    high = str(effort or "standard").strip().lower() == "high"
    return ChatOutputContract(
        kind="prose",
        max_chars=8_000 if high else 2_800,
        num_predict=2_048 if high else 768,
        instruction=(
            "Answer the current request directly. Do not add unrelated sections or repeat the prompt."
            if high
            else "Answer directly and concisely. Do not add unrelated sections or repeat the prompt."
        ),
    )


def tighten_for_missing_reference(contract: ChatOutputContract) -> ChatOutputContract:
    """Bound a clarification when a follow-up has no eligible prior context."""

    return ChatOutputContract(
        kind="single_sentence",
        max_lines=1,
        max_chars=min(contract.max_chars or 400, 400),
        num_predict=min(contract.num_predict or 128, 128),
        instruction=(
            "The current request references missing prior context. Ask one concise clarification sentence; "
            "do not invent the missing referenced content."
        ),
    )


def render_output_contract(contract: ChatOutputContract, *, repair_reason: str = "") -> str:
    lines = [
        "CURRENT-REQUEST OUTPUT CONTRACT (deterministic; mandatory):",
        f"- kind={contract.kind}",
        f"- max_chars={contract.max_chars}",
    ]
    if contract.exact_items:
        lines.append(f"- exact_items={contract.exact_items}")
    if contract.max_lines:
        lines.append(f"- max_nonempty_lines={contract.max_lines}")
    lines.append(f"- instruction={contract.instruction}")
    if repair_reason:
        lines.append(f"- previous_attempt_failure={repair_reason}")
        lines.append("- correct that failure completely; do not explain the correction")
    return "\n".join(lines)
