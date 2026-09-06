from __future__ import annotations

from three_agent import chat_gateway, orchestrator
from three_agent.knowledge_gateway import KnowledgeGatewayV3


def test_production_orchestrator_binds_v3_directly() -> None:
    """Legacy chat monkey-patching must not be able to downgrade production."""
    assert chat_gateway._orchestrator is orchestrator
    assert orchestrator.KnowledgeGateway is not KnowledgeGatewayV3
    assert orchestrator.KnowledgeGatewayV3 is KnowledgeGatewayV3
    names = set(orchestrator.Orchestrator.__init__.__code__.co_names)
    assert "KnowledgeGatewayV3" in names
    assert "KnowledgeGateway" not in names


def test_v3_is_the_multimodal_runtime_contract() -> None:
    assert hasattr(KnowledgeGatewayV3, "build_attachment_context")
    assert hasattr(KnowledgeGatewayV3, "ingest_upload")
