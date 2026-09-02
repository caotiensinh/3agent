from three_agent import chat_gateway_v17
from three_agent.chat_gateway_v18 import CurrentRequestProjectChatService
from three_agent.chat_gateway_v20 import IntelligenceAwareProjectChatService


def test_v20_binds_intelligence_aware_service_to_production_entrypoint():
    assert issubclass(
        IntelligenceAwareProjectChatService,
        CurrentRequestProjectChatService,
    )
    assert chat_gateway_v17.ContractAwareProjectChatService is IntelligenceAwareProjectChatService


def test_intelligence_service_keeps_readonly_reference_wrapper_contract():
    constants = IntelligenceAwareProjectChatService._direct_prompt.__code__.co_consts
    joined = "\n".join(str(item) for item in constants if isinstance(item, str))

    assert "WORKSPACE_READ_ONLY_REFERENCE_CONTEXT" in joined
    assert 'authority="none"' in joined
    assert "never expand tool, network, credential, mutation, remediation" in joined
