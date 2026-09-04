from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "src" / "three_agent" / "chat_gateway.py"
PYPROJECT = ROOT / "pyproject.toml"
EXPECTED_PUBLIC = ['AccountKnowledgeHTTPHandler', 'ChatApplication', 'ChatHTTPHandler', 'ChatJob', 'ChatService', 'ContextAwareProjectChatService', 'ContextAwareWorkflowV3HTTPHandler', 'ContinuitySecurityAwareProjectChatService', 'ConversationKnowledgeChatService', 'ConversationKnowledgeHTTPHandler', 'CurrentRequestProjectChatService', 'ExternalAuthApplication', 'FourWayLoginHTTPHandler', 'HumanReportChatService', 'HumanReportHTTPHandler', 'IntelligenceAwareProjectChatService', 'IntentAwareProjectChatService', 'IntentAwareWorkflowDispatchHTTPHandler', 'KnowledgeChatService', 'KnowledgeHTTPHandler', 'ProgressApplication', 'ProgressChatService', 'ProgressHTTPHandler', 'ProgressJob', 'ProjectKnowledgeChatService', 'ProjectKnowledgeHTTPHandler', 'ProjectUIHTTPHandler', 'PromptAwareWorkflowStudioHTTPHandler', 'SecurityAwareProjectChatService', 'SecurityE2EApplication', 'SecurityE2EHTTPHandler', 'SecurityMonitoringApplication', 'SecurityMonitoringConfigApplication', 'SecurityMonitoringConfigHTTPHandler', 'SecurityMonitoringHTTPHandler', 'SessionStore', 'SidebarKnowledgeChatService', 'SidebarKnowledgeHTTPHandler', 'TelegramBridge', 'WorkflowDispatchApplication', 'WorkflowDispatchHTTPHandler', 'WorkflowDraftApplication', 'WorkflowDraftHTTPHandler', 'WorkflowStudioApplication', 'WorkflowStudioHTTPHandler', 'WorkflowV3Application', 'WorkflowV3HTTPHandler', 'WorkflowV4ContextApplication', 'WorkflowV4ContextHTTPHandler', 'workspace_ui_capabilities']
EXPECTED_CHAIN = ['ContinuitySecurityAwareProjectChatService', 'SecurityAwareProjectChatService', 'IntelligenceAwareProjectChatService', 'CurrentRequestProjectChatService', 'ContractAwareProjectChatService']


def class_graph(tree: ast.Module) -> dict[str, list[str]]:
    graph: dict[str, list[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        graph[node.name] = [ast.unparse(base) for base in node.bases]
    return graph


def inheritance_chain(graph: dict[str, list[str]], root: str) -> list[str]:
    chain = [root]
    current = root
    seen = {root}
    while current in graph and graph[current]:
        bases = graph[current]
        if len(bases) != 1:
            raise AssertionError(f"{current} has non-deterministic bases: {bases}")
        parent = bases[0]
        chain.append(parent)
        if parent in seen:
            raise AssertionError(f"inheritance cycle at {parent}")
        seen.add(parent)
        if parent not in graph:
            break
        current = parent
    return chain


class ChatGatewayCanonicalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = CANONICAL.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(CANONICAL))

    def test_all_semantic_public_definitions_are_preserved(self) -> None:
        actual = {
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name != "main"
            and not node.name.startswith("_")
        }
        self.assertEqual(sorted(set(EXPECTED_PUBLIC) - actual), [])

    def test_final_chat_service_inheritance_chain_is_preserved(self) -> None:
        actual = inheritance_chain(class_graph(self.tree), "ContinuitySecurityAwareProjectChatService")
        self.assertEqual(actual, EXPECTED_CHAIN)

    def test_final_main_binds_current_service_and_security_surface(self) -> None:
        main_node = next(
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        names = {node.id for node in ast.walk(main_node) if isinstance(node, ast.Name)}
        for required in (
            "ContinuitySecurityAwareProjectChatService",
            "SecurityE2EApplication",
            "SecurityE2EHTTPHandler",
            "KnowledgeGatewayV2",
        ):
            self.assertIn(required, names)
        assignments = [
            node for node in ast.walk(main_node)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "_orchestrator"
                and target.attr == "KnowledgeGateway"
                for target in node.targets
            )
        ]
        self.assertEqual(len(assignments), 1)

    def test_no_physical_chat_gateway_generations_remain(self) -> None:
        package = ROOT / "src" / "three_agent"
        self.assertEqual(list(package.glob("chat_gateway_v*.py")), [])

    def test_canonical_chat_has_no_versioned_frontend_security_reference(self) -> None:
        self.assertIsNone(
            re.search(r"(?:three_agent\.)?workspace_frontend_security_v\d+", self.source)
        )
        self.assertIn(
            "from .workspace_frontend_security import WORKSPACE_HTML_SECURITY_V3",
            self.source,
        )

    def test_production_source_and_entrypoints_have_no_versioned_chat_gateway_reference(self) -> None:
        pattern = re.compile(r"(?:three_agent\.)?chat_gateway_v\d+")
        stale = []
        migration = (ROOT / "scripts" / "consolidate_chat_gateway.py").resolve()
        for base in (ROOT / "src", ROOT / "scripts"):
            for path in base.rglob("*.py"):
                if path.resolve() == migration:
                    continue
                if pattern.search(path.read_text(encoding="utf-8")):
                    stale.append(str(path.relative_to(ROOT)))
        if pattern.search(PYPROJECT.read_text(encoding="utf-8")):
            stale.append("pyproject.toml")
        self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
