import json
import tempfile
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.capability_revocation import TaskCapabilityRevocationStore
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.knowledge_plane import InboundKnowledgeImporter, PublicEvidenceExporter
from three_agent.runtime_checkpoint import RuntimeCheckpointStore
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_invocation import RuntimeInvocationBundle, TypedCapabilityInvocation
from three_agent.runtime_invocation_binding import RuntimeInvocationBindingStore
from three_agent.runtime_observation_ledger import RuntimeObservationLedger
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_production_adapters import (
    ProductionCapabilityAdapterRegistry,
    RuntimeProductionAdapterError,
)
from three_agent.runtime_production_scheduler import ProductionAuditedRuntimeDAGScheduler
from three_agent.runtime_reviewed_knowledge_search import (
    ReviewedKnowledgeSearchBoundary,
    ReviewedKnowledgeSearchError,
)
from three_agent.runtime_source_authority import ReviewedSourceBinding, RuntimeSourceBindingBundle
from three_agent.runtime_source_binding_store import RuntimeSourceBindingStore
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeKnowledgeEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_knowledge_search(
        self,
        *,
        task_id,
        node_id,
        source_class,
        resource_ref,
        query_sha256,
        result,
        result_sha256,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                source_class,
                resource_ref,
                query_sha256,
                result,
                result_sha256,
            )
        )
        return ("artifact:knowledge-search-evidence",)


class RuntimeProductionKnowledgeSearchTests(unittest.TestCase):
    @staticmethod
    def _knowledge_root(tmp):
        outbox = Path(tmp) / "outbox"
        knowledge = Path(tmp) / "knowledge"
        outbox.mkdir()
        payload = {
            "task_id": "public_research_fixture",
            "generated_at": "2026-09-07T00:00:00+00:00",
            "sources": [
                {
                    "source_id": "S1",
                    "title": "Runtime source authority",
                    "url": "https://example.com/runtime-source-authority",
                    "fetch_status": "ok",
                    "extracted_text": (
                        "Reviewed runtime knowledge keeps external evidence untrusted.\n\n"
                        "The deterministic knowledge index can find source authority safely."
                    ),
                }
            ],
            "source_assessments": [],
            "rejected_sources": [],
        }
        exported = PublicEvidenceExporter(outbox).export_research_payload(payload)
        imported = InboundKnowledgeImporter(knowledge).import_bundle(exported)
        return knowledge, imported

    @staticmethod
    def _task(tmp):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production knowledge search", "knowledge-plane fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
            allowed_sources=("public_knowledge",),
            allowed_tools=("search_docs",),
            write_scope="none",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _plan(contract, *, query="source authority", max_results=5):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_knowledge_search",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "docs",
                    "search_docs",
                    "knowledge",
                    "public_knowledge",
                    "read",
                ),
            ),
        )
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="docs",
            operation="search",
            arguments={"query": query, "max_results": max_results},
        )
        bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, bundle

    @staticmethod
    def _source(*, root, contract, registry, compiled, with_root=True):
        binding = ReviewedSourceBinding.bind(
            compiled_plan=compiled,
            node_id="docs",
            source_class="public_knowledge",
            local_root=root if with_root else None,
        )
        bundle = RuntimeSourceBindingBundle.compile(
            compiled_plan=compiled,
            task_contract=contract,
            bindings=(binding,),
            registry=registry,
        )
        return binding, bundle

    @staticmethod
    def _adapters(
        *,
        contract,
        budget,
        registry,
        compiled,
        invocation_bundle,
        source_bundle,
        sink,
    ):
        boundary = ReviewedKnowledgeSearchBoundary(
            compiled_plan=compiled,
            task_contract=contract,
            source_binding_bundle=source_bundle,
            evidence_sink=sink,
            registry=registry,
        )
        return ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=invocation_bundle,
            budget=budget,
            knowledge_search_boundary=boundary,
            source_binding_bundle=source_bundle,
            registry=registry,
        )

    @staticmethod
    def _scheduler(tmp, store, adapters):
        return ProductionAuditedRuntimeDAGScheduler(
            adapters=adapters,
            invocation_binding_store=RuntimeInvocationBindingStore(
                Path(tmp) / "invocation_bindings"
            ),
            source_binding_store=RuntimeSourceBindingStore(
                Path(tmp) / "source_bindings"
            ),
            observation_ledger=RuntimeObservationLedger(store),
            checkpoint_store=RuntimeCheckpointStore(Path(tmp) / "checkpoints"),
            registry=adapters.capability_registry,
        )

    def test_knowledge_search_uses_imported_mirror_and_persists_raw_hits_only_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            knowledge, _ = self._knowledge_root(tmp)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            binding, source_bundle = self._source(
                root=knowledge,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeKnowledgeEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            snapshot = budget.snapshot()
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.observations[0].status, "succeeded")
            self.assertEqual(result.observations[0].reason_code, "SEARCH_DOCS_OK")
            self.assertEqual(
                result.observations[0].evidence_refs,
                ("artifact:knowledge-search-evidence",),
            )
            self.assertEqual(snapshot["steps_used"], 1)
            self.assertEqual(snapshot["tool_calls_used"], 1)
            self.assertEqual(len(sink.calls), 1)
            payload = json.loads(sink.calls[0][5].decode("utf-8"))
            self.assertGreaterEqual(payload["hit_count"], 1)
            self.assertEqual(payload["hits"][0]["trust"], "untrusted_external")
            self.assertIn(payload["hits"][0]["injection_risk"], {"low", "medium", "high"})
            self.assertIn("source authority", payload["hits"][0]["text"].casefold())
            self.assertTrue(binding.fingerprint.startswith("sha256:"))
            self.assertNotIn(str(knowledge.resolve()), str(source_bundle.metadata()))
            observation_text = json.dumps(
                result.observations[0].metadata(),
                ensure_ascii=False,
                sort_keys=True,
            )
            self.assertNotIn("deterministic knowledge index", observation_text.casefold())

    def test_live_revocation_denies_before_knowledge_io_or_tool_charge(self):
        with tempfile.TemporaryDirectory() as tmp:
            knowledge, _ = self._knowledge_root(tmp)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._source(
                root=knowledge,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeKnowledgeEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "search_docs",
                reason_code="OPERATOR_REVOKED",
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].status, "denied")
            self.assertEqual(result.observations[0].reason_code, "CAPABILITY_REVOKED")
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)
            self.assertEqual(sink.calls, [])

    def test_tampered_imported_chunk_fails_integrity_before_evidence_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            knowledge, imported = self._knowledge_root(tmp)
            manifest = json.loads((imported / "manifest.json").read_text(encoding="utf-8"))
            chunk_name = manifest["sources"][0]["chunks"][0]["file"]
            (imported / "chunks" / chunk_name).write_text("tampered evidence", encoding="utf-8")
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._source(
                root=knowledge,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeKnowledgeEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "KNOWLEDGE_MIRROR_INTEGRITY_INVALID")
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(sink.calls, [])

    def test_knowledge_boundary_requires_runtime_bound_trusted_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, contract, _ = self._task(tmp)
            registry, compiled, _ = self._plan(contract)
            _, source_bundle = self._source(
                root=Path(tmp),
                contract=contract,
                registry=registry,
                compiled=compiled,
                with_root=False,
            )
            with self.assertRaisesRegex(
                ReviewedKnowledgeSearchError,
                "KNOWLEDGE_SEARCH_TRUSTED_ROOT_REQUIRED",
            ):
                ReviewedKnowledgeSearchBoundary(
                    compiled_plan=compiled,
                    task_contract=contract,
                    source_binding_bundle=source_bundle,
                    evidence_sink=FakeKnowledgeEvidenceSink(),
                    registry=registry,
                )

    def test_search_docs_requires_reviewed_knowledge_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            knowledge, _ = self._knowledge_root(tmp)
            _, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._source(
                root=knowledge,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            with self.assertRaisesRegex(
                RuntimeProductionAdapterError,
                "REVIEWED_KNOWLEDGE_SEARCH_BOUNDARY_REQUIRED",
            ):
                ProductionCapabilityAdapterRegistry(
                    compiled_plan=compiled,
                    task_contract=contract,
                    invocation_bundle=invocation_bundle,
                    budget=budget,
                    source_binding_bundle=source_bundle,
                    registry=registry,
                )


if __name__ == "__main__":
    unittest.main()
