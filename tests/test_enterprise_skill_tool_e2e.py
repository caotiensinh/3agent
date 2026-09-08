from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.adaptive_diagnostic_router import select_pc_diagnostic_tool_metadata
from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.capability_invocation_adapter import (
    CapabilityInvocationRequest,
    current_runtime_invocation_identity,
    invoke_runtime_tool,
)
from three_agent.diagnostics.complaint_intake import (
    HypothesisEvidence,
    build_complaint_session,
    classify_scope,
    evaluate_evidence_sufficiency,
    next_best_questions,
    rank_hypotheses,
)


class EnterpriseSkillToolE2ETests(unittest.TestCase):
    """Scenario-level E2E coverage across intake, routing, tool selection, and authority."""

    def _domains(self, text: str) -> tuple[str, ...]:
        return tuple(item.domain_id for item in build_complaint_session(text).candidates)

    def test_ambiguous_enterprise_language_routes_to_expected_domains(self) -> None:
        scenarios = (
            ("Mang cham", {"lan_wifi"}),
            ("Khong vao duoc server", {"server_backup"}),
            ("VPN loi", {"vpn_remote"}),
            ("wifi chap chon phong ke toan", {"lan_wifi"}),
            ("may sep khong vao duoc mang", {"lan_wifi"}),
            ("DNS chet hay sao ay", {"lan_wifi"}),
            ("Teams va Outlook cham nhung web van vao binh thuong", {"meeting_collaboration", "mail_exchange"}),
            ("Khong login duoc VPN nhung ping internet duoc", {"vpn_remote", "identity_auth"}),
            ("Excel khong mo duoc file share", {"office_productivity", "file_share_gpo"}),
            ("May ke toan tu ket noi den IP la", {"security"}),
            ("Printer offline o phong ke toan", {"printing"}),
            ("Camera mat sau khi PoE switch reboot", {"cctv_access", "network_infra"}),
        )
        for text, expected in scenarios:
            with self.subTest(text=text):
                domains = set(self._domains(text))
                self.assertTrue(expected.issubset(domains), (text, expected, domains))

    def test_completely_vague_complaint_asks_what_is_affected_before_scope(self) -> None:
        session = build_complaint_session("Bi loi roi, giup toi voi")
        self.assertEqual(session.candidates, ())
        questions = next_best_questions(session, max_questions=3)
        self.assertEqual(questions[0].id, "context.what_is_affected")
        self.assertLessEqual(len(questions), 3)

    def test_known_network_complaint_does_not_reask_what_is_affected(self) -> None:
        session = build_complaint_session("Mang cham")
        question_ids = tuple(item.id for item in next_best_questions(session, max_questions=3))
        self.assertNotIn("context.what_is_affected", question_ids)
        self.assertEqual(question_ids[0], "scope.others_affected")

    def test_scope_followup_adapts_to_previous_answer(self) -> None:
        session = build_complaint_session("wifi chap chon")
        when_others = tuple(
            item.id
            for item in next_best_questions(
                session,
                facts={"scope.others_affected": True},
                max_questions=3,
            )
        )
        self.assertIn("scope.same_area", when_others)

        when_single = tuple(
            item.id
            for item in next_best_questions(
                session,
                facts={"scope.others_affected": False},
                max_questions=3,
            )
        )
        self.assertNotIn("scope.same_area", when_single)

    def test_blast_radius_classification_distinguishes_single_area_site_and_multisite(self) -> None:
        cases = (
            ({"scope.others_affected": False}, "one_user_or_device"),
            ({"scope.others_affected": True, "scope.same_area": True}, "room_or_area"),
            ({"scope.site_affected": True}, "site"),
            ({"scope.multiple_sites": True}, "multiple_sites"),
        )
        for facts, expected in cases:
            with self.subTest(facts=facts):
                self.assertEqual(classify_scope(facts).scope, expected)

    def test_evidence_gate_refuses_diagnosis_when_route_scope_or_machine_evidence_is_missing(self) -> None:
        result = evaluate_evidence_sufficiency(
            candidate_count=2,
            scope=classify_scope({}),
            machine_evidence_count=0,
            unresolved_required_facts=1,
            confidence=0.9,
        )
        self.assertFalse(result.sufficient)
        self.assertIn("AMBIGUOUS_ROUTE", result.reason_codes)
        self.assertIn("SCOPE_UNKNOWN", result.reason_codes)
        self.assertIn("MACHINE_EVIDENCE_REQUIRED", result.reason_codes)
        self.assertIn("REQUIRED_FACTS_MISSING", result.reason_codes)

    def test_evidence_gate_stops_asking_when_one_route_scope_and_machine_evidence_are_sufficient(self) -> None:
        result = evaluate_evidence_sufficiency(
            candidate_count=1,
            scope=classify_scope({"scope.others_affected": False}),
            machine_evidence_count=2,
            unresolved_required_facts=0,
            confidence=0.8,
        )
        self.assertTrue(result.sufficient)
        self.assertEqual(result.reason_codes, ("EVIDENCE_SUFFICIENT",))

    def test_contradicting_machine_evidence_can_demote_user_hypothesis(self) -> None:
        ranked = rank_hypotheses(
            (
                HypothesisEvidence(
                    "internet_outage",
                    prior_weight=2.0,
                    supporting_evidence=("user_reports_no_internet",),
                    contradicting_evidence=("gateway_reachable", "dns_resolves"),
                ),
                HypothesisEvidence(
                    "application_or_endpoint_issue",
                    prior_weight=1.0,
                    supporting_evidence=("gateway_reachable", "dns_resolves"),
                ),
            )
        )
        self.assertEqual(ranked[0].hypothesis_id, "application_or_endpoint_issue")
        self.assertLess(ranked[1].score, ranked[0].score)

    def test_network_complaint_selects_bounded_read_only_internal_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "may sep khong vao duoc mang",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertTrue(result.selected)
        self.assertLessEqual(len(result.selected), 4)
        self.assertTrue(any(item.category == "network" or item.id.startswith("network.") for item in result.selected))
        self.assertTrue(all(item.effect in {"read", "network_read", "compute"} for item in result.selected))
        self.assertTrue(all(item.network_access != "allowlisted_egress" for item in result.selected))

    def test_dns_complaint_selects_dns_evidence_without_external_egress(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "DNS chet hay sao ay",
            platform_name="Windows",
            max_tools=4,
        )
        ids = result.selected_ids()
        self.assertIn("network.dns.snapshot", ids)
        self.assertTrue(all(item.network_access != "allowlisted_egress" for item in result.selected))

    def test_authority_prefilter_reduces_tools_instead_of_expanding_scope(self) -> None:
        authority = SimpleNamespace(
            allowed_tools=("network.ssh.probe",),
            network_scope="internal_only",
        )
        result = select_pc_diagnostic_tool_metadata(
            "SSH va SMB tren server deu khong vao duoc",
            platform_name="Windows",
            authority=authority,
        )
        self.assertEqual(result.selected_ids(), ("network.ssh.probe",))
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(("network.smb.probe", "AUTHORITY_TOOL_NOT_ALLOWED"), rejected)

    def test_destructive_wording_cannot_make_diagnostic_router_select_mutating_tools(self) -> None:
        for text in (
            "Restart core switch di",
            "Disable firewall de test",
            "Flush route tat ca thiet bi",
        ):
            with self.subTest(text=text):
                result = select_pc_diagnostic_tool_metadata(text, platform_name="Windows")
                self.assertTrue(all(item.effect in {"read", "network_read", "compute"} for item in result.selected))
                self.assertTrue(all(item.risk in {"read_only", "sensitive_read"} for item in result.selected))

    def test_real_selection_can_cross_authority_bound_invocation_seam(self) -> None:
        selection = select_pc_diagnostic_tool_metadata(
            "SSH server 192.168.11.10 is unreachable",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertIn("network.ssh.probe", selection.selected_ids())
        tool_id = "network.ssh.probe"
        snapshot_fingerprint, descriptor_fingerprint = current_runtime_invocation_identity(tool_id)
        request = CapabilityInvocationRequest.create(
            task_id="TASK-E2E-NET-001",
            tool_id=tool_id,
            snapshot_fingerprint=snapshot_fingerprint,
            descriptor_fingerprint=descriptor_fingerprint,
            parameters={"host": "192.168.11.10"},
        )
        authority = TaskCapabilityAuthority._build(
            task_id=request.task_id,
            sensitivity="internal",
            allowed_sources=(),
            allowed_tools=(tool_id,),
            write_scope="none",
            network_scope="internal_only",
        )
        with patch(
            "three_agent.capability_invocation_adapter.probe_tcp",
            return_value={"status": "unreachable", "host": "192.168.11.10", "port": 22},
        ) as io_boundary:
            invocation = invoke_runtime_tool(request, authority=authority)
        self.assertTrue(io_boundary.called)
        self.assertEqual(invocation.tool_id, tool_id)
        self.assertTrue(invocation.decision_receipt.allowed)
        self.assertFalse(invocation.decision_receipt.automatic_action_allowed)

    def test_public_target_is_never_selected_as_external_egress(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Ping 8.8.8.8 de xem internet co song khong",
            platform_name="Windows",
        )
        self.assertTrue(all(item.network_access != "allowlisted_egress" for item in result.selected))


if __name__ == "__main__":
    unittest.main()
