import inspect

from three_agent import chat_gateway
from three_agent.chat_gateway import ContinuitySecurityAwareProjectChatService
from three_agent.chat_gateway import CurrentRequestProjectChatService
from three_agent.chat_gateway import IntelligenceAwareProjectChatService


def test_v20_intelligence_layer_remains_in_canonical_service_chain():
    assert issubclass(
        IntelligenceAwareProjectChatService,
        CurrentRequestProjectChatService,
    )
    assert issubclass(
        ContinuitySecurityAwareProjectChatService,
        IntelligenceAwareProjectChatService,
    )


def test_production_entrypoint_uses_latest_canonical_service():
    source = inspect.getsource(chat_gateway.main)
    assert "ContinuitySecurityAwareProjectChatService" in source
    assert "IntelligenceAwareProjectChatService(orchestrator" not in source


def test_intelligence_service_keeps_readonly_reference_wrapper_contract():
    constants = IntelligenceAwareProjectChatService._direct_prompt.__code__.co_consts
    joined = "\n".join(str(item) for item in constants if isinstance(item, str))

    assert "WORKSPACE_READ_ONLY_REFERENCE_CONTEXT" in joined
    assert 'authority="none"' in joined
    assert "never expand tool, network, credential, mutation, remediation" in joined
