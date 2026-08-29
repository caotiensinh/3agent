import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.cli import _runtime_task_scope
from three_agent.inference_scope import (
    current_capability_authority,
    current_model_authority,
    inference_scope,
)
from three_agent.metered_runtime import MeteredExecutionGateway, MeteredInternetGateway
from three_agent.model_authority import TaskModelAuthority
from three_agent.resource_events import ResourceEventRecorder
from three_agent.task_contract import TaskContractCompiler


class FakeInternet:
    def __init__(self):
        self.calls = []

    def get(self, agent_id, task_id, url, timeout=30):
        self.calls.append(("get", agent_id, task_id))
        return url.encode("utf-8")

    def post_json(self, agent_id, task_id, url, payload, timeout=30):
        self.calls.append(("post", agent_id, task_id))
        return b"ok"


class FakeExecution:
    def __init__(self):
        self.calls = []

    def run(self, agent_id, task_id, argv, cwd=None):
        self.calls.append((agent_id, task_id, tuple(argv), cwd))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")


class FakeBridge:
    def __init__(self, attempt):
        self.attempt = attempt
        self.calls = []

    def begin(self, task_id):
        self.calls.append(task_id)
        return self.attempt


class FakeBudget:
    def __init__(self, task_id):
        self.task_id = task_id
        self.reservations = []
        self.active_checks = 0

    def reserve(self, **kwargs):
        self.reservations.append(dict(kwargs))

    def assert_active(self):
        self.active_checks += 1


class CapabilityAuthorityTests(unittest.TestCase):
    @staticmethod
    def _public_contract(task_id="TASK-PUBLIC"):
        return TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="public",
            risk_level="low",
            public_web=True,
        )

    def test_public_web_allows_read_but_never_network_write(self):
        authority = TaskCapabilityAuthority.from_contract(self._public_contract())
        read = authority.require(
            "web_gateway",
            resource_kind="network",
            resource_ref="public_search",
            effect="network_read",
        )
        self.assertTrue(read.allowed)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "CAPABILITY_EFFECT_NOT_ALLOWED"
        ):
            authority.require(
                "web_gateway",
                resource_kind="network",
                resource_ref="public_post",
                effect="network_write",
            )

    def test_write_tool_is_still_denied_when_write_scope_is_none(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-WRITE-NONE",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
        )
        self.assertIn("apply_patch", contract.allowed_tools)
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "WRITE_SCOPE_NOT_AUTHORIZED"
        ):
            authority.require(
                "apply_patch",
                resource_kind="path",
                resource_ref="src/app.py",
                effect="write",
            )

    def test_write_scope_is_path_bounded_and_rejects_traversal(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-WRITE-BOUNDED",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
            write_scope=("src", "tests"),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        self.assertTrue(
            authority.require(
                "apply_patch",
                resource_kind="path",
                resource_ref="src/module.py",
                effect="write",
            ).allowed
        )
        for resource in ("docs/secret.md", "src/../secrets.txt"):
            with self.assertRaises(CapabilityAuthorityDenied):
                authority.require(
                    "apply_patch",
                    resource_kind="path",
                    resource_ref=resource,
                    effect="write",
                )

    def test_decision_metadata_hashes_resource_and_does_not_expose_path(self):
        authority = TaskCapabilityAuthority.from_contract(
            TaskContractCompiler().compile(
                task_id="TASK-META",
                task_type="code_fix",
                sensitivity="internal",
                write_scope=("src",),
            )
        )
        decision = authority.require(
            "apply_patch",
            resource_kind="path",
            resource_ref="src/PRIVATE_RESOURCE_MARKER.py",
            effect="write",
        )
        raw = json.dumps(decision.metadata(), sort_keys=True)
        self.assertNotIn("PRIVATE_RESOURCE_MARKER", raw)
        self.assertNotIn("resource_ref", decision.metadata())
        self.assertTrue(decision.metadata()["resource_sha256"].startswith("sha256:"))

    def test_malformed_capability_identifier_fails_closed(self):
        authority = TaskCapabilityAuthority.from_contract(self._public_contract())
        with self.assertRaisesRegex(ValueError, "capability must be a compact identifier"):
            authority.authorize(
                "web_gateway DROP AUTHORITY",
                resource_kind="network",
                resource_ref="public_search",
                effect="network_read",
            )

    def test_scope_derives_same_capability_authority_from_bridge_bound_model_authority(self):
        contract = self._public_contract("TASK-DERIVED")
        direct = TaskCapabilityAuthority.from_contract(contract)
        model_authority = TaskModelAuthority.from_contract(contract)
        with inference_scope(
            contract.task_id,
            agent_id="research",
            stage="research",
            model_authority=model_authority,
        ):
            derived = current_capability_authority()
            self.assertIsNotNone(derived)
            self.assertEqual(derived.fingerprint, direct.fingerprint)
            self.assertEqual(derived.allowed_tools, contract.allowed_tools)

    def test_direct_cli_stage_scope_binds_runtime_bridge_authority_and_budget(self):
        contract = self._public_contract("TASK-DIRECT")
        model_authority = TaskModelAuthority.from_contract(contract)
        budget = FakeBudget(contract.task_id)
        bridge = FakeBridge(
            SimpleNamespace(
                execution_budget=budget,
                model_authority=model_authority,
            )
        )
        orchestrator = SimpleNamespace(runtime_validator_bridge=bridge)
        with _runtime_task_scope(
            orchestrator,
            contract.task_id,
            agent_id="research",
            stage="research",
        ):
            self.assertIs(current_model_authority(), model_authority)
            self.assertIsNotNone(current_capability_authority())
        self.assertEqual(bridge.calls, [contract.task_id])
        self.assertEqual(budget.reservations, [{"steps": 1}])
        self.assertEqual(budget.active_checks, 1)
        self.assertIsNone(current_model_authority())
        self.assertIsNone(current_capability_authority())

    def test_direct_cli_stage_scope_fails_closed_without_bound_authority(self):
        bridge = FakeBridge(
            SimpleNamespace(
                execution_budget=FakeBudget("TASK-DIRECT-NONE"),
                model_authority=None,
            )
        )
        orchestrator = SimpleNamespace(runtime_validator_bridge=bridge)
        with self.assertRaisesRegex(RuntimeError, "RUNTIME_TASK_AUTHORITY_NOT_BOUND"):
            with _runtime_task_scope(
                orchestrator,
                "TASK-DIRECT-NONE",
                agent_id="research",
                stage="research",
            ):
                pass

    def test_internet_gateway_denies_before_inner_call_or_tool_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.jsonl"
            inner = FakeInternet()
            gateway = MeteredInternetGateway(inner, ResourceEventRecorder(path))
            contract = TaskContractCompiler().compile(
                task_id="TASK-INTERNAL",
                task_type="analysis",
                sensitivity="internal",
            )
            model_authority = TaskModelAuthority.from_contract(contract)
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=model_authority,
            ):
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"
                ):
                    gateway.get("research", contract.task_id, "https://example.com/private")
            self.assertEqual(inner.calls, [])
            self.assertFalse(path.exists())

    def test_public_gateway_allows_read_and_blocks_post_before_inner(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.jsonl"
            inner = FakeInternet()
            gateway = MeteredInternetGateway(inner, ResourceEventRecorder(path))
            contract = self._public_contract("TASK-PUBLIC-GW")
            model_authority = TaskModelAuthority.from_contract(contract)
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=model_authority,
            ):
                self.assertEqual(
                    gateway.get("research", contract.task_id, "https://example.com"),
                    b"https://example.com",
                )
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_EFFECT_NOT_ALLOWED"
                ):
                    gateway.post_json(
                        "research",
                        contract.task_id,
                        "https://example.com/upload",
                        {"secret": "MUST_NOT_LEAVE"},
                    )
            self.assertEqual([row[0] for row in inner.calls], ["get"])
            rows = [json.loads(line) for line in path.read_text().splitlines() if line]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event_type"], "tool_call")

    def test_execution_gateway_requires_declared_logical_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.jsonl"
            inner = FakeExecution()
            gateway = MeteredExecutionGateway(inner, ResourceEventRecorder(path))
            contract = TaskContractCompiler().compile(
                task_id="TASK-EXEC",
                task_type="code_review",
                sensitivity="internal",
            )
            model_authority = TaskModelAuthority.from_contract(contract)
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=model_authority,
            ):
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_DECLARATION_REQUIRED"
                ):
                    gateway.run("research", contract.task_id, ["pytest", "-q"])
                result = gateway.run(
                    "research",
                    contract.task_id,
                    ["pytest", "-q"],
                    capability="run_tests",
                )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(inner.calls), 1)
            rows = [json.loads(line) for line in path.read_text().splitlines() if line]
            self.assertEqual(len(rows), 1)

    def test_execution_write_requires_bounded_resource(self):
        with tempfile.TemporaryDirectory() as tmp:
            inner = FakeExecution()
            gateway = MeteredExecutionGateway(
                inner,
                ResourceEventRecorder(Path(tmp) / "resource.jsonl"),
            )
            contract = TaskContractCompiler().compile(
                task_id="TASK-PATCH",
                task_type="code_fix",
                sensitivity="internal",
                write_scope=("src",),
            )
            model_authority = TaskModelAuthority.from_contract(contract)
            with inference_scope(
                contract.task_id,
                agent_id="research",
                stage="research",
                model_authority=model_authority,
            ):
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "WRITE_RESOURCE_REQUIRED"
                ):
                    gateway.run(
                        "research",
                        contract.task_id,
                        ["apply-patch"],
                        capability="apply_patch",
                    )
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "WRITE_SCOPE_NOT_AUTHORIZED"
                ):
                    gateway.run(
                        "research",
                        contract.task_id,
                        ["apply-patch"],
                        capability="apply_patch",
                        resource_ref="docs/outside.md",
                    )
                gateway.run(
                    "research",
                    contract.task_id,
                    ["apply-patch"],
                    capability="apply_patch",
                    resource_ref="src/inside.py",
                )
            self.assertEqual(len(inner.calls), 1)


if __name__ == "__main__":
    unittest.main()
