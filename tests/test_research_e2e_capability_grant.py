"""Research-agent capability grant used by the live-full-workflow E2E job.

These tests pin the exact mechanism that authorizes Agent 1 (research) to use
`web_gateway` during the live Research -> Presentation -> Daily Report E2E
workflow, and prove the grant stays task-scoped, research-only, search-only,
restricted to approved providers, and fail-closed everywhere else:

- ``config/workspace.public-research.json`` is the existing, already-tested
  positive grant (confidentiality_mode=public-research,
  environment=public-research-zone, internet_gateway.public_search_enabled,
  execution_gateway disabled, allowed_search_hosts restricted). This file adds
  no new grant mechanism; it wires the E2E workflow to the one that already
  exists (see also tests/test_workspace_zones.py, tests/test_runtime_validation.py).
- The production default ``config/workspace.secure.json``
  (confidentiality_mode=confidential) must keep denying web_gateway.
- A capability grant bound to one task_id must never authorize a different
  task_id, and must never let the caller bypass InternetGateway's own
  per-request raw-egress boundary (arbitrary GET/POST stay denied even when
  the capability layer allows web_gateway for search).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.config import GatewayConfig, load_config
from three_agent.gateways import InternetGateway, OutboundSecurityError
from three_agent.inference_scope import inference_scope
from three_agent.metered_runtime import MeteredInternetGateway
from three_agent.model_authority import TaskModelAuthority
from three_agent.orchestrator import Orchestrator
from three_agent.resource_events import ResourceEventRecorder
from three_agent.task_contract import TaskContractCompiler

ROOT = Path(__file__).resolve().parents[1]


def _research_contract(task_id: str, *, sensitivity: str, public_web: bool):
    return TaskContractCompiler().compile(
        task_id=task_id,
        task_type="analysis",
        sensitivity=sensitivity,
        risk_level="low",
        public_web=public_web,
    )


class RuntimeValidatorPolicyConfigWiringTests(unittest.TestCase):
    """The live-full-workflow job resolves its config through this exact policy."""

    def test_confidential_production_default_denies_public_web(self):
        config = load_config(str(ROOT / "config" / "workspace.secure.json"))
        mode, public_web = Orchestrator._runtime_validator_policy(config)
        self.assertEqual(mode, "confidential")
        self.assertFalse(public_web)

    def test_public_research_zone_config_grants_public_web_in_narrow_scope(self):
        config = load_config(str(ROOT / "config" / "workspace.public-research.json"))
        mode, public_web = Orchestrator._runtime_validator_policy(config)
        self.assertEqual(mode, "public-research")
        self.assertTrue(public_web)
        # research-only / search-only / approved-providers-only, never a
        # broadened production default:
        self.assertFalse(config.execution_gateway.enabled)
        self.assertTrue(config.internet_gateway.public_search_enabled)
        self.assertTrue(config.internet_gateway.allowed_search_hosts)
        self.assertFalse(config.internet_gateway.allow_all)


class ResearchCapabilityGrantTests(unittest.TestCase):
    def test_research_search_allowed_with_public_research_grant(self):
        contract = _research_contract("TASK-GRANT-OK", sensitivity="public", public_web=True)
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            "web_gateway",
            resource_kind="network",
            resource_ref="public_search",
            effect="network_read",
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_code, "CAPABILITY_AUTHORIZED")

    def test_research_search_denied_without_grant_matches_production_default(self):
        # Exact contract shape Orchestrator builds from config/workspace.secure.json.
        contract = _research_contract(
            "TASK-GRANT-MISSING", sensitivity="confidential", public_web=False
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
            authority.require(
                "web_gateway",
                resource_kind="network",
                resource_ref="public_search",
                effect="network_read",
            )

    def test_non_research_task_type_gets_no_web_access_by_default(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-NON-RESEARCH",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
        )
        self.assertNotIn("web_gateway", contract.allowed_tools)
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
            authority.require(
                "web_gateway",
                resource_kind="network",
                resource_ref="public_search",
                effect="network_read",
            )

    def test_a_different_task_cannot_borrow_a_research_tasks_grant(self):
        contract = _research_contract("TASK-RESEARCH-1", sensitivity="public", public_web=True)
        model_authority = TaskModelAuthority.from_contract(contract)
        with tempfile.TemporaryDirectory() as tmp:
            recorder = ResourceEventRecorder(Path(tmp) / "resource.jsonl")
            gateway = MeteredInternetGateway(_StubInternet(), recorder)
            with inference_scope(
                "TASK-RESEARCH-1",
                agent_id="research",
                stage="research",
                model_authority=model_authority,
            ):
                # sanity: the granted task itself can search.
                gateway.search_get(
                    "research",
                    "TASK-RESEARCH-1",
                    "https://html.duckduckgo.com/html/",
                    {"q": "x"},
                )
                # an unrelated task_id must never inherit this scope's grant.
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_TASK_SCOPE_MISMATCH"
                ):
                    gateway.search_get(
                        "research",
                        "TASK-OTHER",
                        "https://html.duckduckgo.com/html/",
                        {"q": "x"},
                    )


class _StubInternet:
    """Stand-in inner gateway for tests that only exercise the capability layer."""

    def search_get(self, agent_id, task_id, endpoint, params, timeout=30):
        del agent_id, task_id, params, timeout
        return endpoint.encode("utf-8")


def _public_research_gateway_config(audit_log: Path) -> GatewayConfig:
    """Mirror config/workspace.public-research.json's internet_gateway section."""
    return GatewayConfig(
        enabled=True,
        allow_all=False,
        audit_log=audit_log,
        mode="strict",
        public_search_enabled=True,
        allowed_search_hosts=("html.duckduckgo.com", "lite.duckduckgo.com", "www.bing.com"),
        allowed_content_hosts=(),
        broker_socket=None,
        direct_egress=False,
    )


class RawEgressAndAuditTests(unittest.TestCase):
    """The web_gateway capability grant must never widen into raw egress."""

    def _bound_gateway(self, audit_log: Path):
        gw_config = _public_research_gateway_config(audit_log)
        inner = InternetGateway(gw_config, test_mode_full_access=False)
        recorder_path = audit_log.with_name("resource-events.jsonl")
        gateway = MeteredInternetGateway(inner, ResourceEventRecorder(recorder_path))
        contract = _research_contract("TASK-RAW", sensitivity="public", public_web=True)
        model_authority = TaskModelAuthority.from_contract(contract)
        return gateway, model_authority

    def test_approved_provider_search_is_allowed_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "internet-egress.jsonl"
            gateway, model_authority = self._bound_gateway(audit_log)
            with inference_scope(
                "TASK-RAW", agent_id="research", stage="research", model_authority=model_authority,
            ):
                with mock.patch.object(
                    InternetGateway, "_read_https", return_value=b"<html>ok</html>"
                ):
                    data = gateway.search_get(
                        "research",
                        "TASK-RAW",
                        "https://html.duckduckgo.com/html/",
                        {"q": "linux dns troubleshooting"},
                    )
            self.assertEqual(data, b"<html>ok</html>")

    def test_raw_arbitrary_get_stays_denied_even_with_the_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "internet-egress.jsonl"
            gateway, model_authority = self._bound_gateway(audit_log)
            with inference_scope(
                "TASK-RAW", agent_id="research", stage="research", model_authority=model_authority,
            ):
                # web_gateway is authorized at the capability layer, but the
                # inner InternetGateway still refuses a URL that did not come
                # from an allowlisted search or an earned one-time grant.
                with self.assertRaises(OutboundSecurityError):
                    gateway.get("research", "TASK-RAW", "https://not-a-search-result.example.com/x")

    def test_post_is_always_denied_even_with_the_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "internet-egress.jsonl"
            gateway, model_authority = self._bound_gateway(audit_log)
            with inference_scope(
                "TASK-RAW", agent_id="research", stage="research", model_authority=model_authority,
            ):
                # web_gateway's grant is network_read only (see _EFFECTS in
                # capability_authority.py); a network_write attempt is denied
                # at the capability layer before it can even reach the inner
                # gateway's own unconditional POST-body refusal.
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_EFFECT_NOT_ALLOWED"
                ):
                    gateway.post_json("research", "TASK-RAW", "https://html.duckduckgo.com/", {})

    def test_audit_log_records_both_the_allowed_search_and_the_denied_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "internet-egress.jsonl"
            gateway, model_authority = self._bound_gateway(audit_log)
            with inference_scope(
                "TASK-RAW", agent_id="research", stage="research", model_authority=model_authority,
            ):
                with mock.patch.object(
                    InternetGateway, "_read_https", return_value=b"<html>ok</html>"
                ):
                    gateway.search_get(
                        "research",
                        "TASK-RAW",
                        "https://html.duckduckgo.com/html/",
                        {"q": "SECRET_MARKER_QUERY"},
                    )
                with self.assertRaises(OutboundSecurityError):
                    gateway.get("research", "TASK-RAW", "https://not-a-search-result.example.com/x")

            rows = [
                json.loads(line)
                for line in audit_log.read_text(encoding="utf-8").splitlines()
                if line
            ]
            allowed_rows = [row for row in rows if row["allowed"] is True]
            denied_rows = [row for row in rows if row["allowed"] is False]
            self.assertTrue(allowed_rows, "expected at least one allowed audit record")
            self.assertTrue(denied_rows, "expected at least one denied audit record")
            self.assertTrue(
                any(row["reason"] == "search_authorized" for row in allowed_rows)
            )
            self.assertTrue(
                any(row["reason"] == "arbitrary_get_denied" for row in denied_rows)
            )
            raw = audit_log.read_text(encoding="utf-8")
            self.assertNotIn("SECRET_MARKER_QUERY", raw)


if __name__ == "__main__":
    unittest.main()
