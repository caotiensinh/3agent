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
                f"num_predict={contract.num_predict}"
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
                    think=effort == "high",
                    num_predict=contract.num_predict,
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
