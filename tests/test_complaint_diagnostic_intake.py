from __future__ import annotations

import unittest

from three_agent.diagnostics import (
    DOMAIN_PROFILES,
    DiagnosticRoute,
    HypothesisEvidence,
    build_complaint_session,
    classify_scope,
    detect_language_hint,
    evaluate_evidence_sufficiency,
    evaluate_physical_boundary,
    extract_entities,
    next_best_questions,
    normalize_answer,
    normalize_text,
    rank_domain_candidates,
    rank_hypotheses,
)


class ComplaintDiagnosticIntakeTests(unittest.TestCase):
    def test_domain_catalog_covers_all_32_canonical_domains(self) -> None:
        self.assertEqual(len(DOMAIN_PROFILES), 32)
        self.assertEqual(len({profile.id for profile in DOMAIN_PROFILES}), 32)

    def test_vietnamese_normalization_handles_accents_and_d_stroke(self) -> None:
        self.assertEqual(normalize_text("Đăng nhập mạng chậm"), "dang nhap mang cham")

    def test_language_hint_is_only_a_ui_hint(self) -> None:
        self.assertEqual(detect_language_hint("Máy tôi bị chậm"), "vi")
        self.assertEqual(detect_language_hint("プリンターが使えません"), "ja")
        self.assertEqual(detect_language_hint("My laptop is slow"), "en")

    def test_vague_slow_computer_routes_to_performance_domain(self) -> None:
        candidates = rank_domain_candidates("Máy tôi chậm lắm")
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].domain_id, "endpoint_performance")
        self.assertFalse(hasattr(candidates[0], "root_cause"))

    def test_printing_complaint_routes_to_printing_domain(self) -> None:
        candidates = rank_domain_candidates("Không in được")
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].domain_id, "printing")

    def test_camera_complaint_routes_to_cctv_domain(self) -> None:
        candidates = rank_domain_candidates("Camera mất hết ở tầng 2")
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].domain_id, "cctv_access")
        self.assertIn("camera", extract_entities("Camera mất hết ở tầng 2"))

    def test_network_complaint_keeps_multiple_candidates_for_narrowing(self) -> None:
        session = build_complaint_session("Mạng chậm cả phòng")
        ids = tuple(candidate.domain_id for candidate in session.candidates)
        self.assertIn("lan_wifi", ids)
        self.assertIn("endpoint_performance", ids)
        self.assertEqual(session.language_hint, "vi")

    def test_question_planner_asks_at_most_three_plain_language_questions(self) -> None:
        session = build_complaint_session("Mạng chậm cả phòng")
        questions = next_best_questions(session, max_questions=3)
        self.assertLessEqual(len(questions), 3)
        ids = {question.id for question in questions}
        self.assertEqual(classify_scope(session.facts).scope, "room_or_area")
        self.assertNotIn("scope.others_affected", ids)
        self.assertNotIn("scope.same_area", ids)
        for question in questions:
            prompt = question.prompt("vi")
            self.assertTrue(prompt)
            self.assertNotIn("DHCP lease", prompt)
            self.assertNotIn("default gateway", prompt.lower())

    def test_question_planner_does_not_repeat_answered_fact(self) -> None:
        session = build_complaint_session("Không vào mạng được")
        questions = next_best_questions(
            session,
            facts={"scope.others_affected": False},
            max_questions=3,
        )
        self.assertNotIn("scope.others_affected", {question.id for question in questions})

    def test_same_area_question_only_follows_multiple_user_report(self) -> None:
        session = build_complaint_session("Không vào mạng được")
        before = {question.id for question in next_best_questions(session, max_questions=3)}
        self.assertNotIn("scope.same_area", before)
        after = {
            question.id
            for question in next_best_questions(
                session,
                facts={"scope.others_affected": True},
                max_questions=3,
            )
        }
        self.assertIn("scope.same_area", after)

    def test_yes_no_answer_normalization_is_multilingual_and_fail_closed(self) -> None:
        self.assertIs(normalize_answer("scope.others_affected", "Có").value, True)
        self.assertIs(normalize_answer("scope.others_affected", "いいえ").value, False)
        unknown = normalize_answer("scope.others_affected", "maybe")
        self.assertFalse(unknown.understood)
        self.assertIsNone(unknown.value)

    def test_scope_classifier_distinguishes_single_area_and_site(self) -> None:
        single = classify_scope({"scope.others_affected": False})
        self.assertEqual(single.scope, "one_user_or_device")
        area = classify_scope({"scope.others_affected": True, "scope.same_area": True})
        self.assertEqual(area.scope, "room_or_area")
        site = classify_scope({"scope.site_affected": True})
        self.assertEqual(site.scope, "site")

    def test_unknown_scope_stays_unknown_without_user_or_machine_evidence(self) -> None:
        result = classify_scope({})
        self.assertEqual(result.scope, "unknown")
        self.assertEqual(result.reason_codes, ("SCOPE_EVIDENCE_MISSING",))

    def test_evidence_sufficiency_requires_machine_evidence(self) -> None:
        scope = classify_scope({"scope.others_affected": False})
        result = evaluate_evidence_sufficiency(
            candidate_count=1,
            scope=scope,
            machine_evidence_count=0,
            confidence=0.9,
        )
        self.assertFalse(result.sufficient)
        self.assertIn("MACHINE_EVIDENCE_REQUIRED", result.reason_codes)

    def test_evidence_sufficiency_passes_only_after_scope_route_and_evidence_converge(self) -> None:
        scope = classify_scope({"scope.others_affected": False})
        result = evaluate_evidence_sufficiency(
            candidate_count=1,
            scope=scope,
            machine_evidence_count=2,
            unresolved_required_facts=0,
            physical_boundary_pending=False,
            confidence=0.8,
        )
        self.assertTrue(result.sufficient)
        self.assertEqual(result.reason_codes, ("EVIDENCE_SUFFICIENT",))

    def test_physical_boundary_never_turns_missing_telemetry_into_power_diagnosis(self) -> None:
        result = evaluate_physical_boundary(
            telemetry_available=False,
            direct_power_evidence=False,
            physical_fault_plausible=True,
        )
        self.assertTrue(result.physical_evidence_required)
        self.assertEqual(result.reason_code, "PHYSICAL_EVIDENCE_REQUIRED")

    def test_hypothesis_ranking_only_ranks_supplied_evidence(self) -> None:
        ranked = rank_hypotheses(
            (
                HypothesisEvidence("dns", supporting_evidence=("name-resolution-failed",)),
                HypothesisEvidence("wan", contradicting_evidence=("gateway-reachable",)),
            )
        )
        self.assertEqual(tuple(item.hypothesis_id for item in ranked), ("dns", "wan"))
        self.assertGreater(ranked[0].score, ranked[1].score)

    def test_diagnostic_route_separates_evidence_from_remediation(self) -> None:
        route = DiagnosticRoute(
            route_id="IT-0101",
            domain_id="printing",
            symptom_aliases=("cannot print", "khong in duoc"),
            required_facts=("scope.others_affected",),
            clarification_question_ids=("scope.others_affected",),
            evidence_tool_ids=("windows.printer.queue",),
            stop_conditions=("queue-state-observed",),
            remediation_tool_ids=("remediate.print.spooler.restart",),
        ).validate()
        self.assertEqual(route.evidence_tool_ids, ("windows.printer.queue",))
        self.assertEqual(route.remediation_tool_ids, ("remediate.print.spooler.restart",))

    def test_diagnostic_route_rejects_remediation_as_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "remediation tools cannot be listed"):
            DiagnosticRoute(
                route_id="IT-0101",
                domain_id="printing",
                symptom_aliases=("cannot print",),
                required_facts=(),
                clarification_question_ids=(),
                evidence_tool_ids=("remediate.print.spooler.restart",),
                stop_conditions=("done",),
            ).validate()

    def test_diagnostic_route_rejects_unknown_domain(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown domain"):
            DiagnosticRoute(
                route_id="IT-0101",
                domain_id="made_up_domain",
                symptom_aliases=("cannot print",),
                required_facts=(),
                clarification_question_ids=(),
                evidence_tool_ids=(),
                stop_conditions=("done",),
            ).validate()


if __name__ == "__main__":
    unittest.main()
