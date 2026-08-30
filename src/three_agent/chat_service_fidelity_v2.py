from __future__ import annotations

from typing import Any

from .chat_context import CONTEXT_MODE_FOLLOW_UP
from .chat_fidelity import direct_chat_answer_valid, direct_chat_system_prompt
from .chat_gateway_v16 import ContextAwareProjectChatService
from .chat_output_contract import (
    compile_chat_output_contract,
    render_output_contract,
    tighten_for_missing_reference,
)
from .privacy import redact_sensitive_text


OUTPUT_CONTRACT_POLICY_VERSION = "current-request-output-contract/v1"
_STANDARD_OUTPUT_CHARS_PER_PREDICT_TOKEN = 5
_MIN_STANDARD_NUM_PREDICT = 8


def _bounded_generation_num_predict(contract: Any, high_effort: bool) -> int:
    """Bound standard direct-chat output tokens to the deterministic char contract.

    High-effort thinking keeps its established floor because Ollama thinking tokens
    share the generation budget on supported reasoning models. Standard chat does
    not need that reasoning reserve, so its output budget is capped conservatively
    against max_chars instead of allowing the decoder to outrun the validator.
    """

    configured = max(1, int(getattr(contract, "num_predict", 0) or 1))
    if high_effort:
        return max(configured, 768)

    max_chars = max(0, int(getattr(contract, "max_chars", 0) or 0))
    if not max_chars:
        return configured
    char_bound = max(
        _MIN_STANDARD_NUM_PREDICT,
        (max_chars + _STANDARD_OUTPUT_CHARS_PER_PREDICT_TOKEN - 1)
        // _STANDARD_OUTPUT_CHARS_PER_PREDICT_TOKEN,
    )
    return min(configured, char_bound)


class ContractAwareProjectChatService(ContextAwareProjectChatService):
    """Reference-gated local chat plus deterministic response-shape enforcement."""

    def _effective_output_contract(self, job: Any, effort: str):
        contract = compile_chat_output_contract(job.message, effort=effort)
        plan = self._context_plan(job)
        if plan.mode == CONTEXT_MODE_FOLLOW_UP and not plan.text:
            contract = tighten_for_missing_reference(contract)
        return contract

    def _execute_direct_chat(self, job_id: str, job: Any, effort: str) -> None:
        uploads = list(self._job_uploads.get(job_id, []))
        language_source = self._job_language_sources.get(job_id, "fallback")
        contract = self._effective_output_contract(job, effort)
        high_effort = str(effort or "").strip().lower() == "high"
        generation_num_predict = _bounded_generation_num_predict(contract, high_effort)
        generation_temperature = None if high_effort else 0.0

        self._update(job_id, status="running")
        self._stage(
            job_id,
            "answer",
            "running",
            f"Local model · language={job.language} · output={contract.kind}",
        )
        self.orchestrator.store.record_activity(
            None,
            "chat_gateway",
            "direct_chat_started",
            "ok",
            (
                f"mode=chat language={job.language} language_source={language_source} "
                f"effort={effort} uploads={len(uploads)} output_kind={contract.kind} "
                f"num_predict={generation_num_predict} "
                f"sampling={'default' if generation_temperature is None else 'temperature0'}"
            ),
        )

        prompt = self._direct_prompt(job, uploads)
        last_reason = ""
        try:
            for attempt in range(2):
                system_prompt = (
                    direct_chat_system_prompt(
                        job.language,
                        effort=effort,
                        repair=attempt > 0,
                    )
                    + "\n\n"
                    + render_output_contract(
                        contract,
                        repair_reason=last_reason if attempt > 0 else "",
                    )
                )
                answer = self.orchestrator.llm.generate(
                    system_prompt,
                    prompt,
                    think=high_effort,
                    num_predict=generation_num_predict,
                    temperature=generation_temperature,
                    trust_domain="workspace-local-chat",
                    template_version="workspace.chat.direct.v2",
                )

                valid, reason = direct_chat_answer_valid(answer, job.language, job.message)
                if valid:
                    valid, reason = contract.validate(answer)
                if valid:
                    self._stage(job_id, "answer", "completed", "Direct local answer validated.")
                    self._update(
                        job_id,
                        status="completed",
                        answer=answer.strip(),
                        error=None,
                        artifacts=[],
                    )
                    self.orchestrator.store.record_activity(
                        None,
                        "chat_gateway",
                        "direct_chat_completed",
                        "ok",
                        (
                            f"language={job.language} attempts={attempt + 1} validator=pass "
                            f"output_kind={contract.kind} response_chars={len(answer.strip())}"
                        ),
                    )
                    return

                last_reason = reason
                self.orchestrator.store.record_activity(
                    None,
                    "chat_gateway",
                    "direct_chat_retry",
                    "warning",
                    (
                        f"language={job.language} attempt={attempt + 1} reason={reason} "
                        f"output_kind={contract.kind}"
                    ),
                )

            raise ValueError(
                "Direct chat response rejected after bounded retry: "
                + (last_reason or "response_validation_failed")
            )
        except Exception as exc:
            self._stage(job_id, "answer", "failed", last_reason or type(exc).__name__)
            self._update(
                job_id,
                status="failed",
                answer="",
                error=redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:1200],
                artifacts=[],
            )
