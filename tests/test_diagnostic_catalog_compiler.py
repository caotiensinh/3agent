from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.catalog_compiler import (
    CatalogIssue,
    compile_catalog_files,
    compile_planned_routes,
    domain_for_issue_number,
    parse_catalog_text,
    planned_route_from_issue,
    validate_catalog_issues,
)


class DiagnosticCatalogCompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.paths = (
            root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md",
            root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_2_EXPANSION.md",
            root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_3_EXPANSION.md",
        )

    def test_domain_ranges_cover_canonical_boundaries(self) -> None:
        self.assertEqual(domain_for_issue_number(1), "identity_auth")
        self.assertEqual(domain_for_issue_number(20), "identity_auth")
        self.assertEqual(domain_for_issue_number(21), "windows_endpoint")
        self.assertEqual(domain_for_issue_number(121), "lan_wifi")
        self.assertEqual(domain_for_issue_number(381), "intune_autopilot")
        self.assertEqual(domain_for_issue_number(501), "ad_core")
        self.assertEqual(domain_for_issue_number(576), "cctv_access")
        self.assertEqual(domain_for_issue_number(650), "wan_remote")

    def test_domain_range_rejects_outside_corpus(self) -> None:
        with self.assertRaises(ValueError):
            domain_for_issue_number(0)
        with self.assertRaises(ValueError):
            domain_for_issue_number(651)

    def test_parser_only_accepts_canonical_issue_lines(self) -> None:
        parsed = parse_catalog_text(
            "\n".join(
                (
                    "# title",
                    "- IT-0001 — User cannot sign in.",
                    "not an issue",
                    "- S01 — source reference",
                )
            ),
            source_file="sample.md",
        )
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].issue_id, "IT-0001")
        self.assertEqual(parsed[0].domain_id, "identity_auth")

    def test_catalog_files_compile_exactly_650_unique_contiguous_issues(self) -> None:
        issues = compile_catalog_files(self.paths)
        self.assertEqual(len(issues), 650)
        self.assertEqual(issues[0].issue_id, "IT-0001")
        self.assertEqual(issues[-1].issue_id, "IT-0650")
        self.assertEqual(len({issue.issue_id for issue in issues}), 650)
        self.assertEqual(tuple(issue.number for issue in issues), tuple(range(1, 651)))

    def test_catalog_compiles_into_650_non_executable_planned_routes(self) -> None:
        routes = compile_planned_routes(self.paths)
        self.assertEqual(len(routes), 650)
        self.assertTrue(all(route.status == "planned" for route in routes))
        self.assertTrue(all(route.execution_enabled is False for route in routes))
        self.assertTrue(all(route.evidence_capability_tags for route in routes))
        self.assertEqual(len({route.route_id for route in routes}), 650)

    def test_compiled_routes_cover_all_32_domains(self) -> None:
        routes = compile_planned_routes(self.paths)
        self.assertEqual(len({route.domain_id for route in routes}), 32)

    def test_network_route_has_scope_and_location_questions(self) -> None:
        issue = CatalogIssue(
            issue_id="IT-0121",
            number=121,
            canonical_symptom="Network connectivity complaint",
            domain_id="lan_wifi",
            source_file="sample.md",
        )
        route = planned_route_from_issue(issue)
        self.assertIn("scope.others_affected", route.clarification_question_ids)
        self.assertIn("scope.same_area", route.clarification_question_ids)
        self.assertIn("context.location", route.clarification_question_ids)
        self.assertIn("network.dns", route.evidence_capability_tags)
        self.assertFalse(route.execution_enabled)

    def test_camera_route_preserves_physical_boundary(self) -> None:
        issue = CatalogIssue(
            issue_id="IT-0576",
            number=576,
            canonical_symptom="Camera is unreachable",
            domain_id="cctv_access",
            source_file="sample.md",
        )
        route = planned_route_from_issue(issue)
        self.assertTrue(route.physical_verification_possible)
        self.assertIn("physical.power_link", route.clarification_question_ids)
        self.assertIn("camera.reachability", route.evidence_capability_tags)
        self.assertIn("switch.poe", route.evidence_capability_tags)

    def test_planned_route_does_not_expose_execution_tool_ids(self) -> None:
        route = planned_route_from_issue(
            CatalogIssue(
                issue_id="IT-0101",
                number=101,
                canonical_symptom="Cannot print",
                domain_id="printing",
                source_file="sample.md",
            )
        )
        self.assertFalse(hasattr(route, "evidence_tool_ids"))
        self.assertFalse(hasattr(route, "remediation_tool_ids"))

    def test_validator_rejects_duplicate_issue_ids(self) -> None:
        issues = (
            CatalogIssue("IT-0001", 1, "a", "identity_auth", "a.md"),
            CatalogIssue("IT-0001", 1, "b", "identity_auth", "b.md"),
        )
        with self.assertRaisesRegex(ValueError, "duplicate issue ids"):
            validate_catalog_issues(issues, expected_first=1, expected_last=1)

    def test_validator_rejects_gaps(self) -> None:
        issues = (
            CatalogIssue("IT-0001", 1, "a", "identity_auth", "a.md"),
            CatalogIssue("IT-0003", 3, "c", "identity_auth", "a.md"),
        )
        with self.assertRaisesRegex(ValueError, "catalog is not contiguous"):
            validate_catalog_issues(issues, expected_first=1, expected_last=3)


if __name__ == "__main__":
    unittest.main()
