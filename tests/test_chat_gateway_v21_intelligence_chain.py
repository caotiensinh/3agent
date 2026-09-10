from types import SimpleNamespace

from three_agent import chat_gateway
from three_agent.chat_gateway import IntelligenceAwareProjectChatService
from three_agent.chat_gateway import SecurityAwareProjectChatService


def test_v21_preserves_v20_intelligence_service_inheritance():
    assert issubclass(SecurityAwareProjectChatService, IntelligenceAwareProjectChatService)


def test_v21_direct_prompt_composes_intelligence_then_security(monkeypatch):
    monkeypatch.setattr(
        IntelligenceAwareProjectChatService,
        "_direct_prompt",
        lambda self, job, upload_ids: "V20_INTELLIGENCE_CONTEXT",
    )
    monkeypatch.setattr(
        chat_gateway,
        "_bounded_security_context",
        lambda message: "V21_SECURITY_CONTEXT:" + message,
    )

    service = object.__new__(SecurityAwareProjectChatService)
    job = SimpleNamespace(message="check our network")

    prompt = service._direct_prompt(job, [])

    assert prompt.startswith("V20_INTELLIGENCE_CONTEXT")
    assert "V21_SECURITY_CONTEXT:check our network" in prompt
