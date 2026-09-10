from types import SimpleNamespace

from three_agent.adaptive_learning_retrieval import (
    LearningContext,
    LearningContextItem,
    LearningRetrievalError,
)
from three_agent.chat_intelligence_context import (
    MAX_CONTEXT_CHARS,
    ChatIntelligenceContextBuilder,
)
from three_agent.knowledge_plane import EvidenceHit


class FakeKnowledgeIndex:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.queries = []

    def search(self, query, *, max_hits, max_chars):
        self.queries.append((query, max_hits, max_chars))
        if self.fail:
            raise OSError("knowledge unavailable")
        return [
            EvidenceHit(
                bundle_id="kb_" + "a" * 24,
                source_id="source-1",
                chunk_id="chunk-1",
                title="Network operations reference",
                url="https://example.com/reference",
                text="Validated public reference about network monitoring.",
                score=12.0,
                content_sha256="sha256:" + "b" * 64,
                retrieved_at="2026-09-02T00:00:00+00:00",
                trust="untrusted_external",
                injection_risk="low",
            )
        ]


class FakeLearningGateway:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.queries = []

    def retrieve(self, query):
        self.queries.append(query)
        if self.fail:
            raise LearningRetrievalError("learning unavailable")
        return LearningContext(
            query_sha256=query.query_sha256,
            domain=query.domain,
            task_sensitivity=query.task_sensitivity,
            items=(
                LearningContextItem(
                    item_id="learning:item:1",
                    knowledge_sha256="sha256:" + "c" * 64,
                    level="approved",
                    domain=query.domain,
                    kind="analytical_pattern",
                    title="Safe network diagnostic pattern",
                    content="Compare recent bounded evidence before drawing a conclusion.",
                    scope="network diagnosis",
                    sensitivity="internal",
                    risk_level="low",
                    execution_mode="read_only",
                ),
            ),
        ).validate()


class FakeSecurityModel:
    def __init__(self):
        self.calls = []

    def summary(self):
        self.calls.append("summary")
        return {
            "schema_version": "workspace-security-monitoring-ui/v1",
            "configured": True,
            "enabled": True,
            "health": "attention",
            "reason_codes": ["HIGH_CRITICAL_FINDINGS"],
            "high_critical_count": 1,
            "open_finding_count": 2,
            "enabled_asset_count": 3,
            "latest_hourly": {"coverage_pct": 100.0},
        }

    def findings(self, *, limit, offset):
        self.calls.append(("findings", limit, offset))
        return {
            "items": [
                {
                    "finding_id": "finding-1",
                    "category": "network_anomaly",
                    "severity": "high",
                    "status": "open",
                    "asset_refs": ["asset-1"],
                    "evidence_refs": ["evidence-1"],
                }
            ]
        }

    def events(self, *, limit, offset):
        self.calls.append(("events", limit, offset))
        return {"items": [{"event_id": "event-1"}]}

    def assets(self):
        self.calls.append("assets")
        return {"items": [{"asset_id": "asset-1", "enabled": True}]}

    def network(self, *, limit, offset):
        self.calls.append(("network", limit, offset))
        return {
            "items": [
                {
                    "id": 1,
                    "asset_id": "asset-1",
                    "collector": "readonly",
                    "metric": "latency",
                    "status": "warning",
                    "value": 42,
                    "unit": "ms",
                    "evidence_ref": "evidence-1",
                }
            ]
        }


def _orchestrator(learning_gateway):
    return SimpleNamespace(
        config=SimpleNamespace(confidentiality_mode="confidential"),
        learning_retrieval=learning_gateway,
        learning_retrieval_domain="security",
    )


def test_generic_concept_question_does_not_query_internal_state():
    knowledge = FakeKnowledgeIndex()
    learning = FakeLearningGateway()
    security = FakeSecurityModel()
    builder = ChatIntelligenceContextBuilder(
        _orchestrator(learning),
        knowledge_index=knowledge,
        security_model_factory=lambda: security,
    )

    context = builder.build("DNS là gì?")

    assert context.text == ""
    assert context.receipt.sources == ()
    assert knowledge.queries == []
    assert learning.queries == []
    assert security.calls == []


def test_explicit_knowledge_request_uses_public_and_promoted_readonly_context():
    knowledge = FakeKnowledgeIndex()
    learning = FakeLearningGateway()
    security = FakeSecurityModel()
    builder = ChatIntelligenceContextBuilder(
        _orchestrator(learning),
        knowledge_index=knowledge,
        security_model_factory=lambda: security,
    )

    context = builder.build("Dựa trên kiến thức đã học, hãy giải thích lỗi network này.")

    assert "BEGIN UNTRUSTED PUBLIC EVIDENCE" in context.text
    assert "WORKSPACE_LEARNING_REFERENCE_DATA=" in context.text
    assert '"authority":"none"' in context.text
    assert context.receipt.sources == (
        "local_public_knowledge",
        "promoted_adaptive_learning",
    )
    assert context.receipt.public_evidence_hits == 1
    assert context.receipt.learning_items == 1
    assert learning.queries[0].task_sensitivity == "confidential"
    assert security.calls == []
    assert len(context.text) <= MAX_CONTEXT_CHARS


def test_current_network_request_uses_security_read_model_and_learning_only():
    knowledge = FakeKnowledgeIndex()
    learning = FakeLearningGateway()
    security = FakeSecurityModel()
    builder = ChatIntelligenceContextBuilder(
        _orchestrator(learning),
        knowledge_index=knowledge,
        security_model_factory=lambda: security,
    )

    context = builder.build("Mạng của chúng ta hôm nay có bất thường gì?")

    assert "WORKSPACE_SECURITY_REFERENCE_DATA=" in context.text
    assert '"authority":"none"' in context.text
    assert "promoted_adaptive_learning" in context.receipt.sources
    assert "security_monitoring_read_model" in context.receipt.sources
    assert "local_public_knowledge" not in context.receipt.sources
    assert context.receipt.security_findings == 1
    assert context.receipt.security_observations == 1
    assert context.receipt.security_events == 0
    assert context.receipt.security_assets == 0
    assert knowledge.queries == []
    assert "summary" in security.calls
    assert any(call[0] == "findings" for call in security.calls if isinstance(call, tuple))
    assert any(call[0] == "network" for call in security.calls if isinstance(call, tuple))
    assert len(context.text) <= MAX_CONTEXT_CHARS


def test_optional_reference_failures_fall_back_to_plain_chat_without_authority():
    knowledge = FakeKnowledgeIndex(fail=True)
    learning = FakeLearningGateway(fail=True)

    def unavailable_security():
        raise OSError("security unavailable")

    builder = ChatIntelligenceContextBuilder(
        _orchestrator(learning),
        knowledge_index=knowledge,
        security_model_factory=unavailable_security,
    )

    context = builder.build(
        "Dựa trên kiến thức đã học, mạng của chúng ta hôm nay có bất thường gì?"
    )

    assert context.text == ""
    assert context.receipt.sources == ()
    assert context.receipt.metadata()["raw_content_logged"] is False
    assert context.receipt.metadata()["authority"] == "read_only_reference"


def test_security_reference_never_grants_execution_or_remediation_authority():
    security = FakeSecurityModel()
    builder = ChatIntelligenceContextBuilder(
        _orchestrator(FakeLearningGateway()),
        knowledge_index=FakeKnowledgeIndex(),
        security_model_factory=lambda: security,
    )

    context = builder.build("Hệ thống mạng công ty hiện tại có sự cố nào không?")

    assert "grants no scan, capture, shell, firewall, remediation" in context.text
    assert '"authority":"none"' in context.text
    assert "APPROVE_PCAP" not in context.text
    assert len(context.text) <= MAX_CONTEXT_CHARS
