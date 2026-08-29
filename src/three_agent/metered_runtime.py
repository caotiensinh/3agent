from __future__ import annotations

from typing import Any

from .gateways import ExecutionGateway, InternetGateway
from .llm import AdaptiveOllamaClient, LocalLLMError
from .resource_budget import ResourceAdmissionError
from .resource_events import ResourceEventRecorder
from .worker_pool import OllamaWorkerPool


class MeteredInternetGateway:
    """Count top-level Internet Gateway invocations without duplicating inner audits."""

    def __init__(self, inner: InternetGateway, recorder: ResourceEventRecorder):
        self._inner = inner
        self._recorder = recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def _record(self, agent_id: str, task_id: str | None, action: str) -> None:
        self._recorder.record(
            "tool_call",
            task_id=task_id,
            actor_id=agent_id,
            action=action,
            reason_code="TOOL_CALL_ATTEMPT",
        )

    def get(self, agent_id: str, task_id: str | None, url: str, timeout: int = 30) -> bytes:
        self._record(agent_id, task_id, "internet_get")
        return self._inner.get(agent_id, task_id, url, timeout=timeout)

    def search_get(
        self,
        agent_id: str,
        task_id: str | None,
        endpoint: str,
        params: dict[str, str | int],
        *,
        timeout: int = 30,
    ) -> bytes:
        self._record(agent_id, task_id, "internet_search")
        return self._inner.search_get(agent_id, task_id, endpoint, params, timeout=timeout)

    def grant_public_fetch(self, agent_id: str, task_id: str | None, url: str) -> str:
        self._record(agent_id, task_id, "internet_fetch_grant")
        return self._inner.grant_public_fetch(agent_id, task_id, url)

    def fetch_granted(
        self,
        agent_id: str,
        task_id: str | None,
        grant_token: str,
        *,
        timeout: int = 30,
    ) -> bytes:
        self._record(agent_id, task_id, "internet_fetch_granted")
        return self._inner.fetch_granted(agent_id, task_id, grant_token, timeout=timeout)

    def post_json(
        self,
        agent_id: str,
        task_id: str | None,
        url: str,
        payload: dict,
        timeout: int = 30,
    ) -> bytes:
        self._record(agent_id, task_id, "internet_post")
        return self._inner.post_json(agent_id, task_id, url, payload, timeout=timeout)


class MeteredExecutionGateway:
    def __init__(self, inner: ExecutionGateway, recorder: ResourceEventRecorder):
        self._inner = inner
        self._recorder = recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def run(
        self,
        agent_id: str,
        task_id: str | None,
        argv: list[str],
        cwd: str | None = None,
    ):
        self._recorder.record(
            "tool_call",
            task_id=task_id,
            actor_id=agent_id,
            action="execution_command",
            reason_code="TOOL_CALL_ATTEMPT",
        )
        return self._inner.run(agent_id, task_id, argv, cwd=cwd)


class MeteredOllamaWorkerPool(OllamaWorkerPool):
    """Preserve worker routing while counting only actual same-model retry attempts."""

    def __init__(self, *args, resource_events: ResourceEventRecorder, **kwargs):
        super().__init__(*args, **kwargs)
        self.resource_events = resource_events

    def _call(self, method: str, *args, **kwargs):
        errors: list[str] = []
        model = self.config.model
        order = self.route_order(model)
        for index, worker in enumerate(order):
            client = self._clients[worker.name]
            try:
                if worker.dual_gpu:
                    self._wait_for_dual_balance(model)
                return getattr(client, method)(*args, **kwargs)
            except (ResourceAdmissionError, LocalLLMError) as exc:
                errors.append(f"{worker.name}: {exc}")
                if index + 1 < len(order):
                    reason = (
                        "RESOURCE_ADMISSION"
                        if isinstance(exc, ResourceAdmissionError)
                        else "LOCAL_LLM_ERROR"
                    )
                    self.resource_events.record(
                        "model_retry",
                        task_id=None,
                        actor_id="worker_pool",
                        action="worker_fallback",
                        reason_code=reason,
                        model=model,
                        target=order[index + 1].name,
                    )
                continue
        detail = "; ".join(errors) if errors else "no eligible Ollama worker"
        raise LocalLLMError(f"All Ollama workers failed for {model}: {detail}")


class MeteredAdaptiveOllamaClient(AdaptiveOllamaClient):
    """Adaptive model router with typed retry/escalation telemetry.

    Planned deep-model routing due to prompt size is not an escalation. A second
    model invocation caused by failure is one retry. Moving primary -> stronger
    deep model additionally records one escalation. Resource denial never causes
    an upward escalation.
    """

    def __init__(self, *args, resource_events: ResourceEventRecorder, **kwargs):
        super().__init__(*args, **kwargs)
        self.resource_events = resource_events

    def _retry(
        self,
        *,
        action: str,
        reason_code: str,
        model: str | None,
        target: str | None,
    ) -> None:
        self.resource_events.record(
            "model_retry",
            task_id=None,
            actor_id="model_router",
            action=action,
            reason_code=reason_code,
            model=model,
            target=target,
        )

    def _escalate(self, *, model: str | None, target: str | None) -> None:
        self.resource_events.record(
            "model_escalation",
            task_id=None,
            actor_id="model_router",
            action="primary_to_deep",
            reason_code="PRIMARY_MODEL_FAILED",
            model=model,
            target=target,
        )

    def _call(self, method: str, system_prompt: str, user_prompt: str, **kwargs):
        primary_method = getattr(self.primary, method)
        deep_method = getattr(self.deep, method) if self.deep else None
        primary_model = getattr(getattr(self.primary, "config", None), "model", None)
        deep_model = getattr(getattr(self.deep, "config", None), "model", None) if self.deep else None

        if self._prefer_deep(user_prompt) and deep_method is not None:
            try:
                return deep_method(system_prompt, user_prompt, **kwargs)
            except ResourceAdmissionError:
                self._retry(
                    action="deep_to_primary",
                    reason_code="RESOURCE_ADMISSION",
                    model=deep_model,
                    target=primary_model,
                )
                return primary_method(system_prompt, user_prompt, **kwargs)
            except LocalLLMError:
                self._retry(
                    action="deep_to_primary",
                    reason_code="LOCAL_LLM_ERROR",
                    model=deep_model,
                    target=primary_model,
                )
                return primary_method(system_prompt, user_prompt, **kwargs)

        try:
            return primary_method(system_prompt, user_prompt, **kwargs)
        except ResourceAdmissionError:
            raise
        except LocalLLMError:
            if self.deep_escalation and self._deep_is_distinct() and deep_method is not None:
                self._retry(
                    action="primary_to_deep",
                    reason_code="LOCAL_LLM_ERROR",
                    model=primary_model,
                    target=deep_model,
                )
                self._escalate(model=primary_model, target=deep_model)
                return deep_method(system_prompt, user_prompt, **kwargs)
            raise
