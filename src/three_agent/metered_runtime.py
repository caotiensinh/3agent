from __future__ import annotations

from typing import Any

from .capability_authority import CapabilityAuthorityDenied
from .gateways import ExecutionGateway, InternetGateway
from .inference_scope import (
    current_capability_authority,
    current_execution_budget,
    current_inference_scope,
    current_model_authority,
)
from .llm import AdaptiveOllamaClient, LocalLLMError
from .model_authority import ModelAuthorityDenied
from .resource_budget import ResourceAdmissionError
from .resource_events import ResourceEventRecorder
from .worker_pool import OllamaWorkerPool


def _reserve_model_budget(*, retries: int = 0, escalations: int = 0) -> None:
    state = current_execution_budget()
    if state is not None:
        state.reserve(retries=retries, escalations=escalations)


def _model_tier_permitted(target_tier: str) -> bool:
    authority = current_model_authority()
    return authority is None or authority.permits_tier(target_tier)


def _require_model_tier(target_tier: str) -> None:
    authority = current_model_authority()
    if authority is not None:
        authority.require_tier(target_tier)


def _require_capability(
    capability: str,
    *,
    task_id: str | None,
    resource_kind: str,
    resource_ref: str,
    effect: str,
) -> None:
    authority = current_capability_authority()
    if authority is None:
        return
    scope = current_inference_scope()
    if scope is None or scope.task_id != authority.task_id:
        raise CapabilityAuthorityDenied("CAPABILITY_SCOPE_MISSING_OR_INVALID")
    if task_id is not None and str(task_id).strip() != authority.task_id:
        raise CapabilityAuthorityDenied("CAPABILITY_TASK_SCOPE_MISMATCH")
    authority.require(
        capability,
        resource_kind=resource_kind,
        resource_ref=resource_ref,
        effect=effect,
    )


class MeteredInternetGateway:
    """Count authorized Internet invocations without duplicating inner audits."""

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
        _require_capability(
            "web_gateway",
            task_id=task_id,
            resource_kind="network",
            resource_ref="public_fetch",
            effect="network_read",
        )
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
        _require_capability(
            "web_gateway",
            task_id=task_id,
            resource_kind="network",
            resource_ref="public_search",
            effect="network_read",
        )
        self._record(agent_id, task_id, "internet_search")
        return self._inner.search_get(agent_id, task_id, endpoint, params, timeout=timeout)

    def grant_public_fetch(self, agent_id: str, task_id: str | None, url: str) -> str:
        _require_capability(
            "web_gateway",
            task_id=task_id,
            resource_kind="network",
            resource_ref="public_fetch_grant",
            effect="network_read",
        )
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
        _require_capability(
            "web_gateway",
            task_id=task_id,
            resource_kind="network",
            resource_ref="public_fetch_granted",
            effect="network_read",
        )
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
        _require_capability(
            "web_gateway",
            task_id=task_id,
            resource_kind="network",
            resource_ref="public_post",
            effect="network_write",
        )
        self._record(agent_id, task_id, "internet_post")
        return self._inner.post_json(agent_id, task_id, url, payload, timeout=timeout)


class MeteredExecutionGateway:
    """Execution boundary requiring a logical TaskContract capability when scoped."""

    _WRITE_CAPABILITIES = {"write_staging", "apply_patch"}

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
        *,
        capability: str | None = None,
        resource_ref: str | None = None,
    ):
        authority = current_capability_authority()
        if authority is not None:
            logical = str(capability or "").strip()
            if not logical:
                raise CapabilityAuthorityDenied("CAPABILITY_DECLARATION_REQUIRED")
            effect = "write" if logical in self._WRITE_CAPABILITIES else "execute"
            reference = str(resource_ref or "").strip()
            if effect == "write" and not reference:
                raise CapabilityAuthorityDenied("WRITE_RESOURCE_REQUIRED")
            _require_capability(
                logical,
                task_id=task_id,
                resource_kind="path" if effect == "write" else "execution",
                resource_ref=reference or "workspace",
                effect=effect,
            )
        self._recorder.record(
            "tool_call",
            task_id=task_id,
            actor_id=agent_id,
            action="execution_command",
            reason_code="TOOL_CALL_ATTEMPT",
        )
        return self._inner.run(agent_id, task_id, argv, cwd=cwd)


class MeteredOllamaWorkerPool(OllamaWorkerPool):
    """Preserve worker routing while enforcing task-wide same-model retry budget."""

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
                    _reserve_model_budget(retries=1)
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
    """Adaptive model router with hard budget and monotonic model authority.

    The TaskContract-derived authority envelope remains outside the model. Any
    planned or failure-driven stronger-model transition must fit the immutable
    max tier and escalation policy before the stronger model can be invoked.
    """

    def __init__(
        self,
        *args,
        resource_events: ResourceEventRecorder,
        primary_tier: str = "specialist",
        deep_tier: str = "strong",
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.resource_events = resource_events
        self.primary_tier = str(primary_tier).strip().lower()
        self.deep_tier = str(deep_tier).strip().lower()

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

        # Unscoped/legacy callers retain historical behavior. Production task
        # scopes must authorize even the primary tier.
        _require_model_tier(self.primary_tier)

        if self._prefer_deep(user_prompt) and deep_method is not None:
            if not _model_tier_permitted(self.deep_tier):
                return primary_method(system_prompt, user_prompt, **kwargs)
            _require_model_tier(self.deep_tier)
            try:
                return deep_method(system_prompt, user_prompt, **kwargs)
            except ResourceAdmissionError:
                _reserve_model_budget(retries=1)
                self._retry(
                    action="deep_to_primary",
                    reason_code="RESOURCE_ADMISSION",
                    model=deep_model,
                    target=primary_model,
                )
                return primary_method(system_prompt, user_prompt, **kwargs)
            except LocalLLMError:
                _reserve_model_budget(retries=1)
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
                # Authority is checked before budget reservation so a forbidden
                # model transition cannot consume budget or create telemetry.
                _require_model_tier(self.deep_tier)
                _reserve_model_budget(retries=1, escalations=1)
                self._retry(
                    action="primary_to_deep",
                    reason_code="LOCAL_LLM_ERROR",
                    model=primary_model,
                    target=deep_model,
                )
                self._escalate(model=primary_model, target=deep_model)
                return deep_method(system_prompt, user_prompt, **kwargs)
            raise
