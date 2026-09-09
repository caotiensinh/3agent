from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.capability_promotion import promote_planned_route
from three_agent.diagnostics.catalog_compiler import compile_planned_routes
from three_agent.diagnostics.complaint_intake import (
    build_complaint_session,
    classify_scope,
    evaluate_evidence_sufficiency,
    next_best_questions,
)
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
)


REAL_USER_CASES = (
    ("NET-01", "vi", "Máy tôi không vào mạng, WiFi lỗi và không có internet.", "lan_wifi"),
    ("NET-02", "en", "Wi-Fi not working and DNS looks broken on this laptop.", "lan_wifi"),
    ("NET-03", "ja", "Wi-Fi が使えず、ネット 繋がらない状態です。", "lan_wifi"),
    ("NET-04", "vi", "Tôi không vào VPN được khi làm việc ở nhà.", "vpn_remote"),
    ("NET-05", "en", "VPN is connected but remote access is not working.", "vpn_remote"),
    ("NET-06", "ja", "VPN 接続はできますがリモートが使えません。", "vpn_remote"),
    ("NET-07", "en", "The switch port is down and PoE disappeared.", "network_infra"),
    ("NET-08", "vi", "Cổng switch bị down và mất PoE cho thiết bị.", "network_infra"),
    ("NET-09", "en", "The branch office is offline and the WAN is down.", "wan_remote"),
    ("NET-10", "vi", "Chi nhánh mất mạng, WAN lỗi và site offline.", "wan_remote"),
    ("CAM-01", "vi", "Camera offline và không xem được RTSP trên NVR.", "cctv_access"),
    ("CAM-02", "en", "The camera disappeared from the VMS and RTSP is unavailable.", "cctv_access"),
    ("CAM-03", "ja", "カメラ オフラインで、NVR から映像を確認できません。", "cctv_access"),
    # Explicit PoE/switch evidence is stronger than the downstream camera symptom.
    ("CAM-04", "en", "The camera is offline after the PoE switch port went down.", "network_infra"),
    ("CAM-05", "vi", "Camera mất sau khi cổng switch PoE bị down.", "network_infra"),
    ("HW-01", "vi", "Laptop không lên nguồn, đèn power không sáng.", "hardware_power"),
    ("HW-02", "en", "The laptop will not turn on and has no power.", "hardware_power"),
    ("HW-03", "ja", "PC の電源 入らない状態です。", "hardware_power"),
    ("HW-04", "en", "The dock is connected but the external monitor has no display.", "dock_display"),
    ("HW-05", "vi", "Dock USB-C không nhận màn hình phụ.", "dock_display"),
    ("WIN-01", "en", "Windows won't start after an update.", "windows_endpoint"),
    ("WIN-02", "vi", "Windows không vào được và máy cứ khởi động lại.", "windows_endpoint"),
    ("WIN-03", "ja", "Windows 起動ができず、再起動を繰り返します。", "windows_endpoint"),
    ("SYS-01", "en", "The computer is slow and freezes with CPU 100%.", "endpoint_performance"),
    ("SYS-02", "vi", "Máy bị chậm và hay bị đơ, CPU 100%.", "endpoint_performance"),
    # Natural filler words make this intentionally ambiguous today. The separate
    # ambiguity test below requires server_backup to remain a candidate and blocks
    # evidence sufficiency until the ambiguity is resolved.
    ("SYS-03", "en", "The server is slow and storage is full.", "endpoint_performance"),
    ("APP-01", "en", "The application is not working and shows a software error.", "business_apps"),
    ("APP-02", "vi", "Phần mềm lỗi và không mở được ứng dụng.", "business_apps"),
    ("SEC-01", "en", "I received a phishing message and see a suspicious connection.", "security"),
    ("SEC-02", "vi", "Máy có kết nối đến IP lạ và tôi nghi có virus.", "security"),
)


PROMOTABLE_ROUTE_IDS = (
    "IT-0017", "IT-0075", "IT-0076", "IT-0088", "IT-0090", "IT-0097",
    "IT-0230", "IT-0243", "IT-0260", "IT-0303", "IT-0304", "IT-0305",
    "IT-0306", "IT-0320", "IT-0325", "IT-0330", "IT-0331",
)


class DiagnosticRealUserE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.routes = compile_planned_routes(
            (
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md",
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_2_EXPANSION.md",
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_3_EXPANSION.md",
            )
        )
        cls.routes_by_id = {route.route_id: route for route in cls.routes}
        cls.registry = runtime_micro_tool_registry()
        cls.bindings = default_runtime_capability_bindings()

    def test_thirty_real_user_complaints_reach_the_expected_diagnostic_domain(self) -> None:
        self.assertEqual(len(REAL_USER_CASES), 30)
        for case_id, expected_language, complaint, expected_domain in REAL_USER_CASES:
            with self.subTest(case_id=case_id):
                session = build_complaint_session(complaint)
                self.assertEqual(session.language_hint, expected_language)
                self.assertTrue(session.candidates, case_id)
                self.assertEqual(session.candidates[0].domain_id, expected_domain)
                self.assertEqual(session.raw_text, complaint)

    def test_natural_server_wording_remains_ambiguous_and_fails_closed(self) -> None:
        session = build_complaint_session("The server is slow and storage is full.")
        candidate_domains = tuple(candidate.domain_id for candidate in session.candidates)
        self.assertIn("endpoint_performance", candidate_domains)
        self.assertIn("server_backup", candidate_domains)

        scope = classify_scope(session.facts)
        sufficiency = evaluate_evidence_sufficiency(
            candidate_count=len(session.candidates),
            scope=scope,
            machine_evidence_count=0,
            unresolved_required_facts=1,
            confidence=0.0,
        )
        self.assertFalse(sufficiency.sufficient)
        self.assertIn("AMBIGUOUS_ROUTE", sufficiency.reason_codes)
        self.assertIn("MACHINE_EVIDENCE_REQUIRED", sufficiency.reason_codes)

    def test_intake_does_not_invent_scope_and_asks_for_missing_evidence(self) -> None:
        for case_id, _language, complaint, _expected_domain in REAL_USER_CASES:
            with self.subTest(case_id=case_id):
                session = build_complaint_session(complaint)
                scope = classify_scope(session.facts)
                self.assertEqual(scope.scope, "unknown")
                self.assertIn("SCOPE_EVIDENCE_MISSING", scope.reason_codes)
                questions = next_best_questions(session)
                self.assertGreaterEqual(len(questions), 1)
                self.assertLessEqual(len(questions), 3)
                self.assertEqual(len({question.id for question in questions}), len(questions))

                sufficiency = evaluate_evidence_sufficiency(
                    candidate_count=len(session.candidates),
                    scope=scope,
                    machine_evidence_count=0,
                    unresolved_required_facts=1,
                    confidence=0.0,
                )
                self.assertFalse(sufficiency.sufficient)
                self.assertIn("MACHINE_EVIDENCE_REQUIRED", sufficiency.reason_codes)
                self.assertIn("REQUIRED_FACTS_MISSING", sufficiency.reason_codes)
                self.assertIn("LOW_CONFIDENCE", sufficiency.reason_codes)

    def test_promotable_routes_resolve_only_to_implemented_diagnostic_tools(self) -> None:
        for route_id in PROMOTABLE_ROUTE_IDS:
            with self.subTest(route_id=route_id):
                route = self.routes_by_id[route_id]
                self.assertFalse(route.execution_enabled)
                result = promote_planned_route(
                    route,
                    self.registry,
                    bindings=self.bindings,
                    allow_external_network=False,
                )
                self.assertTrue(
                    result.promotable,
                    (route_id, result.unresolved_capability_tags, result.rejected_bindings),
                )
                self.assertTrue(result.selected_tool_ids)
                self.assertFalse(result.unresolved_capability_tags)
                self.assertFalse(result.rejected_bindings)
                for tool_id in result.selected_tool_ids:
                    tool = self.registry.get(tool_id)
                    self.assertTrue(tool.implemented)
                    self.assertIn(tool.effect, {"read", "network_read", "compute"})
                    self.assertNotEqual(tool.network_access, "allowlisted_egress")

    def test_physical_domains_keep_physical_verification_boundary(self) -> None:
        physical_cases = ("network_infra", "cctv_access", "hardware_power", "dock_display", "wan_remote")
        routes_by_domain = {}
        for route in self.routes:
            routes_by_domain.setdefault(route.domain_id, route)
        for domain_id in physical_cases:
            with self.subTest(domain_id=domain_id):
                self.assertTrue(routes_by_domain[domain_id].physical_verification_possible)

    def test_catalog_and_runtime_remain_fail_closed_by_default(self) -> None:
        self.assertEqual(len(self.routes), 650)
        self.assertTrue(all(route.execution_enabled is False for route in self.routes))


if __name__ == "__main__":
    unittest.main()
