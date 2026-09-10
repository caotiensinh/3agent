#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import three_agent.application_e2e_multilingual as app
from three_agent.chat_multiturn_acceptance import safe_runtime_failure_code
from three_agent.config import load_config

TARGET_CASE_IDS = (
    "vi_translation_one_line",
    "ja_translation_one_line",
    "en_translation_one_line",
    "vi_summary_two_bullets",
    "vi_https_json_only",
)


def _sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _safe_schema_id(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate.startswith("workspace.chat."):
        return ""
    if len(candidate) > 160:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return candidate if all(ch in allowed for ch in candidate) else ""


def _payload_metadata(payload: object) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "payload_type": type(payload).__name__,
        "payload_sha256": _sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        ),
    }
    if isinstance(payload, dict):
        keys = sorted(str(key) for key in payload.keys())
        metadata["payload_keys"] = keys[:16]
        metadata["value_types"] = {
            str(key): type(value).__name__
            for key, value in sorted(payload.items(), key=lambda item: str(item[0]))[:16]
        }
        metadata["value_chars"] = {
            str(key): len(str(value))
            for key, value in sorted(payload.items(), key=lambda item: str(item[0]))[:16]
        }
    return metadata


@dataclass
class RichCallEvidence:
    call_kind: str
    schema_id: str
    succeeded: bool
    failure_code: str = ""
    user_prompt_sha256: str = ""
    user_prompt_chars: int = 0
    current_request_boundary: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    _payload: object = field(default=None, repr=False)

    def public_dict(self) -> dict[str, Any]:
        payload = {
            "call_kind": self.call_kind,
            "schema_id": self.schema_id,
            "succeeded": self.succeeded,
            "failure_code": self.failure_code,
            "user_prompt_sha256": self.user_prompt_sha256,
            "user_prompt_chars": self.user_prompt_chars,
            "current_request_boundary": self.current_request_boundary,
        }
        payload.update(self.metadata)
        return payload


class RichDiagnosticRecordingLLM:
    """Record only hashes, schema identifiers, types, lengths, and safe booleans."""

    latest: "RichDiagnosticRecordingLLM | None" = None

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.calls: list[RichCallEvidence] = []
        type(self).latest = self

    @staticmethod
    def _base(call_kind: str, user_prompt: str, schema_id: str = "") -> dict[str, Any]:
        body = str(user_prompt or "")
        return {
            "call_kind": call_kind,
            "schema_id": _safe_schema_id(schema_id),
            "user_prompt_sha256": _sha256(body),
            "user_prompt_chars": len(body),
            "current_request_boundary": "<CURRENT_USER_REQUEST>" in body,
        }

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        base = self._base("generate", user_prompt)
        try:
            answer = self.delegate.generate(system_prompt, user_prompt, **kwargs)
        except Exception as exc:
            self.calls.append(
                RichCallEvidence(
                    **base,
                    succeeded=False,
                    failure_code=safe_runtime_failure_code(exc),
                )
            )
            raise
        self.calls.append(RichCallEvidence(**base, succeeded=True))
        return answer

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        schema_id = _safe_schema_id(kwargs.get("schema_id"))
        base = self._base("generate_json", user_prompt, schema_id)
        try:
            payload = self.delegate.generate_json(system_prompt, user_prompt, **kwargs)
        except Exception as exc:
            self.calls.append(
                RichCallEvidence(
                    **base,
                    succeeded=False,
                    failure_code=safe_runtime_failure_code(exc),
                )
            )
            raise

        metadata = _payload_metadata(payload)
        if schema_id == "workspace.chat.translation.verifier.v1" and isinstance(payload, dict):
            faithful = payload.get("faithful")
            translation_only = payload.get("translation_only")
            metadata["verifier_faithful"] = faithful if type(faithful) is bool else None
            metadata["verifier_translation_only"] = (
                translation_only if type(translation_only) is bool else None
            )

        self.calls.append(
            RichCallEvidence(
                **base,
                succeeded=True,
                metadata=metadata,
                _payload=payload,
            )
        )
        return payload


def _flatten_payload(payload: object) -> str:
    if isinstance(payload, dict):
        return " ".join(_flatten_payload(value) for value in payload.values())
    if isinstance(payload, (list, tuple)):
        return " ".join(_flatten_payload(value) for value in payload)
    return str(payload or "")


def _required_group_hits(case: Any, payload: object) -> list[bool]:
    lowered = _flatten_payload(payload).casefold()
    return [
        any(str(term).casefold() in lowered for term in group)
        for group in case.required_groups
    ]


def _case_diagnostics(
    cases: Sequence[Any],
    results: Sequence[dict[str, Any]],
    calls: Sequence[RichCallEvidence],
) -> list[dict[str, Any]]:
    by_id = {case.case_id: case for case in cases}
    offset = 0
    output: list[dict[str, Any]] = []
    for result in results:
        count = max(0, int(result.get("model_call_count", 0) or 0))
        case_calls = list(calls[offset : offset + count])
        offset += count
        case = by_id.get(str(result.get("case_id") or ""))
        public_calls: list[dict[str, Any]] = []
        for call in case_calls:
            public = call.public_dict()
            if case is not None and call.call_kind == "generate_json" and call._payload is not None:
                public["required_group_hits"] = _required_group_hits(case, call._payload)
            public_calls.append(public)
        output.append(
            {
                "case_id": result.get("case_id"),
                "status": result.get("status"),
                "passed": bool(result.get("passed")),
                "validator_failure_code": result.get("validator_failure_code", ""),
                "model_call_count": count,
                "calls": public_calls,
            }
        )
    return output


def _focused_matrix_validation_errors(cases: Sequence[Any]) -> tuple[str, ...]:
    """Validate case integrity while intentionally skipping full 30-case balance rules."""

    return tuple(app.corpus_validation_errors(cases))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run privacy-safe structured diagnostics for failing multilingual E2E cases"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    selected = tuple(case for case in app.PROMPT_MATRIX if case.case_id in TARGET_CASE_IDS)
    if tuple(case.case_id for case in selected) != TARGET_CASE_IDS:
        raise RuntimeError("diagnostic target matrix drift")

    original_recorder = app.DiagnosticRecordingLLM
    original_matrix_validation = app.matrix_validation_errors
    app.DiagnosticRecordingLLM = RichDiagnosticRecordingLLM  # type: ignore[assignment]
    app.matrix_validation_errors = _focused_matrix_validation_errors  # type: ignore[assignment]
    try:
        report = app.run_live_suite(
            load_config(args.config),
            cases=selected,
            source_sha=args.source_sha,
        )
    finally:
        app.matrix_validation_errors = original_matrix_validation  # type: ignore[assignment]
        app.DiagnosticRecordingLLM = original_recorder  # type: ignore[assignment]

    recorder = RichDiagnosticRecordingLLM.latest
    if recorder is None:
        raise RuntimeError("diagnostic recorder was not initialized")

    receipt = {
        "schema_version": "workspace-application-structured-diagnostics/v1",
        "source_sha": str(args.source_sha)[:80],
        "diagnostic_completed": True,
        "acceptance_passed": bool(report.get("passed")),
        "cases": _case_diagnostics(selected, report.get("results", []), recorder.calls),
        "privacy": {
            "raw_prompts_persisted": False,
            "raw_answers_persisted": False,
            "raw_structured_values_persisted": False,
            "hashes_types_lengths_and_booleans_only": True,
            "public_egress_enabled": False,
        },
    }
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "diagnostic_completed": True,
                "source_sha": receipt["source_sha"],
                "case_count": len(receipt["cases"]),
                "acceptance_passed": receipt["acceptance_passed"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
