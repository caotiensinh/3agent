from __future__ import annotations

import unittest
from collections import Counter

from three_agent.application_e2e_multilingual import (
    CASE_CATEGORIES,
    CATEGORIES,
    INTERNAL_BOUNDARY_MARKERS,
    LANGUAGES,
    PROMPT_MATRIX,
    contract_summary,
    matrix_validation_errors,
)


class ApplicationE2EMultilingualContractTests(unittest.TestCase):
    def test_matrix_is_balanced_across_three_languages(self) -> None:
        counts = Counter(case.expected_language for case in PROMPT_MATRIX)
        self.assertEqual(tuple(LANGUAGES), ("vi", "ja", "en"))
        self.assertEqual(len(PROMPT_MATRIX), 30)
        self.assertEqual(counts, Counter({"vi": 10, "ja": 10, "en": 10}))

    def test_every_category_has_vi_ja_en_case(self) -> None:
        by_category: dict[str, set[str]] = {category: set() for category in CATEGORIES}
        for case in PROMPT_MATRIX:
            by_category[CASE_CATEGORIES[case.case_id]].add(case.expected_language)
        self.assertEqual(len(CATEGORIES), 10)
        for category, languages in by_category.items():
            self.assertEqual(languages, {"vi", "ja", "en"}, category)

    def test_matrix_contract_is_valid(self) -> None:
        self.assertEqual(matrix_validation_errors(), ())
        summary = contract_summary()
        self.assertTrue(summary["valid"], summary["validation_errors"])
        self.assertTrue(summary["frontend_contract_passed"])
        self.assertEqual(summary["case_count"], 30)
        self.assertEqual(summary["category_count"], 10)

    def test_report_contract_never_persists_raw_prompt_or_answer(self) -> None:
        privacy = contract_summary()["privacy"]
        self.assertFalse(privacy["raw_prompts_in_report"])
        self.assertFalse(privacy["raw_answers_in_report"])
        self.assertFalse(privacy["production_database_mutated"])
        self.assertFalse(privacy["public_egress_enabled"])

    def test_boundary_cases_cover_internal_prompt_markers(self) -> None:
        boundary_cases = [
            case
            for case in PROMPT_MATRIX
            if CASE_CATEGORIES[case.case_id] == "system_prompt_boundary"
        ]
        self.assertEqual(len(boundary_cases), 3)
        for case in boundary_cases:
            self.assertEqual(case.forbidden_terms, INTERNAL_BOUNDARY_MARKERS)

    def test_semantic_categories_cover_common_prompt_shapes(self) -> None:
        self.assertEqual(
            set(CATEGORIES),
            {
                "intro",
                "dns_troubleshooting",
                "http_404",
                "translation",
                "summarization",
                "python_debugging",
                "deployment_plan",
                "json_structure",
                "command_only",
                "system_prompt_boundary",
            },
        )


if __name__ == "__main__":
    unittest.main()
