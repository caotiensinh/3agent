"""Isolated no-tool execution boundary for held-out skill cases.

The child model generates a response only.  PASS/FAIL is computed by this trusted
parent from bounded, content-addressed literal assertions; the model cannot grade
itself or mutate learning/runtime state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .adaptive_learning_reflection_worker import assert_loopback_ollama_base_url

CASE_SCHEMA = "workspace-heldout-skill-execution-case/v1"
PACKET_SCHEMA = "workspace-heldout-skill-execution-packet/v1"
RESULT_SCHEMA = "workspace-heldout-skill-execution-result/v1"
AUTHORITY = "offline_evaluation_only_no_tool_or_learning_mutation"
TEMPLATE_VERSION = "workspace.learning.heldout-skill-execution.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SKILL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_PACKET_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 16 * 1024


class HeldOutSkillExecutionError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha_payload(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: Any, code: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or "\x00" in text:
        raise HeldOutSkillExecutionError(code)
    return text


def _terms(values: Any, code: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > 16:
        raise HeldOutSkillExecutionError(code)
    result = tuple(str(value or "").strip() for value in values)
    if any(not value or len(value) > 120 or "\x00" in value for value in result):
        raise HeldOutSkillExecutionError(code)
    folded = tuple(value.casefold() for value in result)
    if len(set(folded)) != len(folded):
        raise HeldOutSkillExecutionError(code)
    return result


def _canonical_instruction_bytes(text: str) -> bytes:
    return str(text).replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


@dataclass(frozen=True)
class HeldOutSkillExecutionCase:
    case_id: str
    heldout_task_id: str
    prompt: str
    required_terms: tuple[str, ...]
    forbidden_terms: tuple[str, ...]
    schema_version: str = CASE_SCHEMA

    def validate(self) -> "HeldOutSkillExecutionCase":
        if self.schema_version != CASE_SCHEMA:
            raise HeldOutSkillExecutionError("HELDOUT_CASE_SCHEMA_INVALID")
        if not _ID.fullmatch(self.case_id) or not _ID.fullmatch(self.heldout_task_id):
            raise HeldOutSkillExecutionError("HELDOUT_CASE_ID_INVALID")
        _text(self.prompt, "HELDOUT_CASE_PROMPT_INVALID", 4000)
        required = _terms(self.required_terms, "HELDOUT_CASE_REQUIRED_TERMS_INVALID")
        forbidden = _terms(self.forbidden_terms, "HELDOUT_CASE_FORBIDDEN_TERMS_INVALID")
        if not required and not forbidden:
            raise HeldOutSkillExecutionError("HELDOUT_CASE_ORACLE_EMPTY")
        if set(value.casefold() for value in required).intersection(value.casefold() for value in forbidden):
            raise HeldOutSkillExecutionError("HELDOUT_CASE_ORACLE_CONTRADICTORY")
        return self

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "heldout_task_id": self.heldout_task_id,
            "prompt": self.prompt,
            "required_terms": list(self.required_terms),
            "forbidden_terms": list(self.forbidden_terms),
        }

    @property
    def case_sha256(self) -> str:
        self.validate()
        return _sha_payload(self._payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._payload(), "case_sha256": self.case_sha256}

    @classmethod
    def from_payload(cls, payload: Any) -> "HeldOutSkillExecutionCase":
        if not isinstance(payload, dict):
            raise HeldOutSkillExecutionError("HELDOUT_CASE_PAYLOAD_INVALID")
        data = dict(payload)
        case_sha = data.pop("case_sha256", None)
        expected = {"schema_version", "case_id", "heldout_task_id", "prompt", "required_terms", "forbidden_terms"}
        if set(data) != expected:
            raise HeldOutSkillExecutionError("HELDOUT_CASE_PAYLOAD_INVALID")
        case = cls(
            schema_version=str(data["schema_version"]),
            case_id=str(data["case_id"]),
            heldout_task_id=str(data["heldout_task_id"]),
            prompt=str(data["prompt"]),
            required_terms=tuple(data["required_terms"]) if isinstance(data["required_terms"], list) else (),
            forbidden_terms=tuple(data["forbidden_terms"]) if isinstance(data["forbidden_terms"], list) else (),
        ).validate()
        if case_sha is not None and case_sha != case.case_sha256:
            raise HeldOutSkillExecutionError("HELDOUT_CASE_SHA_MISMATCH")
        return case


@dataclass(frozen=True)
class HeldOutSkillExecutionPacket:
    subject_id: str
    subject_sha256: str
    skill_name: str
    skill_sha256: str
    skill_document: str
    case: HeldOutSkillExecutionCase
    schema_version: str = PACKET_SCHEMA

    def validate(self) -> "HeldOutSkillExecutionPacket":
        if self.schema_version != PACKET_SCHEMA:
            raise HeldOutSkillExecutionError("HELDOUT_PACKET_SCHEMA_INVALID")
        if not _ID.fullmatch(self.subject_id) or not _SHA.fullmatch(self.subject_sha256):
            raise HeldOutSkillExecutionError("HELDOUT_PACKET_SUBJECT_INVALID")
        if not _SKILL.fullmatch(self.skill_name) or not _SHA.fullmatch(self.skill_sha256):
            raise HeldOutSkillExecutionError("HELDOUT_PACKET_SKILL_INVALID")
        raw = _canonical_instruction_bytes(_text(self.skill_document, "HELDOUT_PACKET_DOCUMENT_INVALID", 4096))
        if "sha256:" + hashlib.sha256(raw).hexdigest() != self.skill_sha256:
            raise HeldOutSkillExecutionError("HELDOUT_PACKET_SKILL_SHA_MISMATCH")
        self.case.validate()
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "subject_id": self.subject_id,
            "subject_sha256": self.subject_sha256,
            "skill_name": self.skill_name,
            "skill_sha256": self.skill_sha256,
            "skill_document": self.skill_document,
            "case": self.case.to_payload(),
        }

    @classmethod
    def from_payload(cls, payload: Any) -> "HeldOutSkillExecutionPacket":
        fields = {"schema_version", "subject_id", "subject_sha256", "skill_name", "skill_sha256", "skill_document", "case"}
        if not isinstance(payload, dict) or set(payload) != fields:
            raise HeldOutSkillExecutionError("HELDOUT_PACKET_PAYLOAD_INVALID")
        return cls(
            schema_version=str(payload["schema_version"]),
            subject_id=str(payload["subject_id"]),
            subject_sha256=str(payload["subject_sha256"]),
            skill_name=str(payload["skill_name"]),
            skill_sha256=str(payload["skill_sha256"]),
            skill_document=str(payload["skill_document"]),
            case=HeldOutSkillExecutionCase.from_payload(payload["case"]),
        ).validate()


@dataclass(frozen=True)
class HeldOutSkillExecutionConfig:
    base_url: str
    model: str
    timeout_seconds: int = 180
    keep_alive: str = "2m"

    def validate(self) -> "HeldOutSkillExecutionConfig":
        try:
            assert_loopback_ollama_base_url(self.base_url)
        except Exception as exc:
            raise HeldOutSkillExecutionError("HELDOUT_EXECUTION_LOOPBACK_REQUIRED") from exc
        if not self.model or len(self.model) > 160 or any(ch in self.model for ch in "\r\n\x00"):
            raise HeldOutSkillExecutionError("HELDOUT_EXECUTION_MODEL_INVALID")
        if not 5 <= int(self.timeout_seconds) <= 1200:
            raise HeldOutSkillExecutionError("HELDOUT_EXECUTION_TIMEOUT_INVALID")
        if not self.keep_alive or len(self.keep_alive) > 32:
            raise HeldOutSkillExecutionError("HELDOUT_EXECUTION_KEEP_ALIVE_INVALID")
        return self

    @property
    def executor_sha256(self) -> str:
        self.validate()
        return _sha_payload(
            {"template_version": TEMPLATE_VERSION, "model": self.model, "temperature": 0, "tools": False}
        )


@dataclass(frozen=True)
class HeldOutSkillExecutionResult:
    subject_id: str
    subject_sha256: str
    skill_sha256: str
    case_id: str
    case_sha256: str
    executor_sha256: str
    response_sha256: str
    response_size_bytes: int
    required_term_count: int
    required_matched_count: int
    forbidden_term_count: int
    forbidden_matched_count: int
    reason_codes: tuple[str, ...]
    passed: bool
    authority: str = AUTHORITY
    schema_version: str = RESULT_SCHEMA

    def validate(self) -> "HeldOutSkillExecutionResult":
        if self.schema_version != RESULT_SCHEMA or self.authority != AUTHORITY:
            raise HeldOutSkillExecutionError("HELDOUT_RESULT_HEADER_INVALID")
        if not _ID.fullmatch(self.subject_id) or not _ID.fullmatch(self.case_id):
            raise HeldOutSkillExecutionError("HELDOUT_RESULT_ID_INVALID")
        for value in (self.subject_sha256, self.skill_sha256, self.case_sha256, self.executor_sha256, self.response_sha256):
            if not _SHA.fullmatch(value):
                raise HeldOutSkillExecutionError("HELDOUT_RESULT_SHA_INVALID")
        for value in (
            self.response_size_bytes,
            self.required_term_count,
            self.required_matched_count,
            self.forbidden_term_count,
            self.forbidden_matched_count,
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise HeldOutSkillExecutionError("HELDOUT_RESULT_COUNT_INVALID")
        if self.required_matched_count > self.required_term_count or self.forbidden_matched_count > self.forbidden_term_count:
            raise HeldOutSkillExecutionError("HELDOUT_RESULT_COUNT_INVALID")
        expected_pass = self.required_matched_count == self.required_term_count and self.forbidden_matched_count == 0
        if self.passed != expected_pass:
            raise HeldOutSkillExecutionError("HELDOUT_RESULT_VERDICT_INVALID")
        expected_reasons = []
        if self.required_matched_count != self.required_term_count:
            expected_reasons.append("HELDOUT_REQUIRED_TERM_MISSING")
        if self.forbidden_matched_count:
            expected_reasons.append("HELDOUT_FORBIDDEN_TERM_PRESENT")
        if self.reason_codes != tuple(expected_reasons):
            raise HeldOutSkillExecutionError("HELDOUT_RESULT_REASONS_INVALID")
        return self

    @property
    def result_sha256(self) -> str:
        self.validate()
        return _sha_payload(asdict(self))

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["reason_codes"] = list(self.reason_codes)
        payload["result_sha256"] = self.result_sha256
        return payload


class IsolatedSkillHeldOutRunner:
    """Execute one held-out case in a separate no-tool Python worker."""

    def __init__(
        self,
        config: HeldOutSkillExecutionConfig,
        *,
        executor: Callable[..., Any] = subprocess.run,
        python_executable: str | None = None,
    ) -> None:
        self.config = config.validate()
        self.executor = executor
        self.python_executable = str(python_executable or sys.executable)

    def _environment(self) -> dict[str, str]:
        env = {
            "PYTHONIOENCODING": "utf-8",
            "WORKSPACE_HELDOUT_OLLAMA_BASE_URL": assert_loopback_ollama_base_url(self.config.base_url),
            "WORKSPACE_HELDOUT_MODEL": self.config.model,
            "WORKSPACE_HELDOUT_TIMEOUT_SECONDS": str(int(self.config.timeout_seconds)),
            "WORKSPACE_HELDOUT_KEEP_ALIVE": self.config.keep_alive,
        }
        for name in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(name)
            if value:
                env[name] = value
        return env

    def run(self, packet: HeldOutSkillExecutionPacket) -> HeldOutSkillExecutionResult:
        packet.validate()
        raw_packet = _canonical(packet.to_payload())
        if len(raw_packet.encode("utf-8")) > _MAX_PACKET_BYTES:
            raise HeldOutSkillExecutionError("HELDOUT_PACKET_SIZE_INVALID")
        try:
            with tempfile.TemporaryDirectory(prefix="workspace-heldout-skill-") as tmp:
                completed = self.executor(
                    (
                        self.python_executable,
                        "-I",
                        "-m",
                        "three_agent.adaptive_learning_heldout_execution_worker",
                    ),
                    input=raw_packet,
                    text=True,
                    encoding="utf-8",
                    errors="strict",
                    capture_output=True,
                    timeout=int(self.config.timeout_seconds) + 30,
                    cwd=tmp,
                    env=self._environment(),
                    shell=False,
                    close_fds=True,
                )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HeldOutSkillExecutionError("HELDOUT_WORKER_EXECUTION_FAILED") from exc
        if int(getattr(completed, "returncode", 1)) != 0:
            raise HeldOutSkillExecutionError("HELDOUT_WORKER_FAILED")
        stdout = str(getattr(completed, "stdout", "") or "")
        if not stdout or len(stdout.encode("utf-8")) > _MAX_RESPONSE_BYTES:
            raise HeldOutSkillExecutionError("HELDOUT_WORKER_RESPONSE_INVALID")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise HeldOutSkillExecutionError("HELDOUT_WORKER_RESPONSE_INVALID") from exc
        if not isinstance(payload, dict) or set(payload) != {"response"}:
            raise HeldOutSkillExecutionError("HELDOUT_WORKER_RESPONSE_INVALID")
        response = _text(payload.get("response"), "HELDOUT_WORKER_RESPONSE_INVALID", 12000)
        folded = response.casefold()
        required_matched = sum(1 for term in packet.case.required_terms if term.casefold() in folded)
        forbidden_matched = sum(1 for term in packet.case.forbidden_terms if term.casefold() in folded)
        reasons = []
        if required_matched != len(packet.case.required_terms):
            reasons.append("HELDOUT_REQUIRED_TERM_MISSING")
        if forbidden_matched:
            reasons.append("HELDOUT_FORBIDDEN_TERM_PRESENT")
        response_raw = response.encode("utf-8")
        return HeldOutSkillExecutionResult(
            subject_id=packet.subject_id,
            subject_sha256=packet.subject_sha256,
            skill_sha256=packet.skill_sha256,
            case_id=packet.case.case_id,
            case_sha256=packet.case.case_sha256,
            executor_sha256=self.config.executor_sha256,
            response_sha256="sha256:" + hashlib.sha256(response_raw).hexdigest(),
            response_size_bytes=len(response_raw),
            required_term_count=len(packet.case.required_terms),
            required_matched_count=required_matched,
            forbidden_term_count=len(packet.case.forbidden_terms),
            forbidden_matched_count=forbidden_matched,
            reason_codes=tuple(reasons),
            passed=not reasons,
        ).validate()
