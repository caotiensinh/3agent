import unittest

from three_agent.adaptive_learning_heldout_regression import (
    HeldOutBenchmarkRunRef,
    HeldOutCaseOutcomeRef,
    HeldOutRegressionError,
    compare_heldout_runs,
)


class HeldOutRegressionTests(unittest.TestCase):
    def outcome(self, case_id, *, subject="a", passed=True, case_char="c", executor="e", result="r"):
        return HeldOutCaseOutcomeRef(
            case_id=case_id,
            case_sha256="sha256:" + case_char * 64,
            subject_sha256="sha256:" + subject * 64,
            executor_sha256="sha256:" + executor * 64,
            result_sha256="sha256:" + result * 64,
            passed=passed,
        ).validate()

    def run(self, *, subject="a", outcomes=None, benchmark="b"):
        if outcomes is None:
            outcomes=(
                self.outcome("case:1", subject=subject, case_char="1", result="2"),
                self.outcome("case:2", subject=subject, case_char="3", result="4"),
            )
        return HeldOutBenchmarkRunRef(
            benchmark_id="benchmark:skill-1",
            benchmark_sha256="sha256:" + benchmark * 64,
            subject_id=f"subject:{subject}",
            subject_sha256="sha256:" + subject * 64,
            outcomes=tuple(outcomes),
        ).validate()

    def test_all_pass_same_cases_is_strict_release_pass(self):
        baseline=self.run(subject="a")
        revision=self.run(
            subject="f",
            outcomes=(
                self.outcome("case:1", subject="f", case_char="1", result="5"),
                self.outcome("case:2", subject="f", case_char="3", result="6"),
            ),
        )
        comparison=compare_heldout_runs(baseline, revision)
        self.assertTrue(comparison.strict_release_passed)
        self.assertEqual(comparison.regression_count, 0)
        self.assertEqual(comparison.revision_pass_count, 2)

    def test_baseline_pass_to_revision_fail_is_regression(self):
        baseline=self.run(subject="a")
        revision=self.run(
            subject="f",
            outcomes=(
                self.outcome("case:1", subject="f", case_char="1", result="5", passed=False),
                self.outcome("case:2", subject="f", case_char="3", result="6"),
            ),
        )
        comparison=compare_heldout_runs(baseline, revision)
        self.assertFalse(comparison.strict_release_passed)
        self.assertEqual(comparison.regressed_case_ids, ("case:1",))
        self.assertIn("HELDOUT_REGRESSION_DETECTED", comparison.reason_codes)

    def test_baseline_fail_to_revision_pass_is_improvement(self):
        baseline=self.run(
            subject="a",
            outcomes=(
                self.outcome("case:1", subject="a", case_char="1", result="2", passed=False),
                self.outcome("case:2", subject="a", case_char="3", result="4"),
            ),
        )
        revision=self.run(
            subject="f",
            outcomes=(
                self.outcome("case:1", subject="f", case_char="1", result="5"),
                self.outcome("case:2", subject="f", case_char="3", result="6"),
            ),
        )
        comparison=compare_heldout_runs(baseline, revision)
        self.assertTrue(comparison.strict_release_passed)
        self.assertEqual(comparison.improved_case_ids, ("case:1",))

    def test_revision_must_pass_all_cases_even_without_regression(self):
        baseline=self.run(
            subject="a",
            outcomes=(
                self.outcome("case:1", subject="a", case_char="1", result="2", passed=False),
                self.outcome("case:2", subject="a", case_char="3", result="4"),
            ),
        )
        revision=self.run(
            subject="f",
            outcomes=(
                self.outcome("case:1", subject="f", case_char="1", result="5", passed=False),
                self.outcome("case:2", subject="f", case_char="3", result="6"),
            ),
        )
        comparison=compare_heldout_runs(baseline, revision)
        self.assertFalse(comparison.strict_release_passed)
        self.assertEqual(comparison.regression_count, 0)
        self.assertEqual(comparison.reason_codes, ("HELDOUT_REVISION_NOT_ALL_CASES_PASS",))

    def test_benchmark_sha_mismatch_fails_closed(self):
        with self.assertRaisesRegex(HeldOutRegressionError, "HELDOUT_COMPARISON_BENCHMARK_MISMATCH"):
            compare_heldout_runs(self.run(subject="a", benchmark="b"), self.run(subject="f", benchmark="c"))

    def test_case_set_mismatch_fails_closed(self):
        revision=self.run(
            subject="f",
            outcomes=(self.outcome("case:1", subject="f", case_char="1", result="5"),),
        )
        with self.assertRaisesRegex(HeldOutRegressionError, "HELDOUT_COMPARISON_CASE_SET_MISMATCH"):
            compare_heldout_runs(self.run(subject="a"), revision)

    def test_case_sha_mismatch_fails_closed(self):
        revision=self.run(
            subject="f",
            outcomes=(
                self.outcome("case:1", subject="f", case_char="9", result="5"),
                self.outcome("case:2", subject="f", case_char="3", result="6"),
            ),
        )
        with self.assertRaisesRegex(HeldOutRegressionError, "HELDOUT_COMPARISON_CASE_SHA_MISMATCH"):
            compare_heldout_runs(self.run(subject="a"), revision)

    def test_executor_mismatch_fails_closed(self):
        revision=self.run(
            subject="f",
            outcomes=(
                self.outcome("case:1", subject="f", case_char="1", result="5", executor="9"),
                self.outcome("case:2", subject="f", case_char="3", result="6"),
            ),
        )
        with self.assertRaisesRegex(HeldOutRegressionError, "HELDOUT_COMPARISON_EXECUTOR_MISMATCH"):
            compare_heldout_runs(self.run(subject="a"), revision)

    def test_duplicate_case_id_is_rejected(self):
        duplicate=(
            self.outcome("case:1", subject="a", case_char="1", result="2"),
            self.outcome("case:1", subject="a", case_char="3", result="4"),
        )
        with self.assertRaisesRegex(HeldOutRegressionError, "HELDOUT_RUN_CASE_DUPLICATE"):
            self.run(subject="a", outcomes=duplicate)

    def test_outcome_subject_must_match_run_subject(self):
        with self.assertRaisesRegex(HeldOutRegressionError, "HELDOUT_RUN_SUBJECT_MISMATCH"):
            self.run(subject="a", outcomes=(self.outcome("case:1", subject="f", case_char="1"),))

    def test_identical_subjects_cannot_be_claimed_as_revision_comparison(self):
        baseline=self.run(subject="a")
        revision=self.run(subject="a")
        with self.assertRaisesRegex(HeldOutRegressionError, "HELDOUT_COMPARISON_SUBJECTS_IDENTICAL"):
            compare_heldout_runs(baseline, revision)

    def test_comparison_identity_is_order_independent(self):
        baseline=self.run(subject="a")
        revision_a=self.run(
            subject="f",
            outcomes=(
                self.outcome("case:1", subject="f", case_char="1", result="5"),
                self.outcome("case:2", subject="f", case_char="3", result="6"),
            ),
        )
        revision_b=self.run(subject="f", outcomes=tuple(reversed(revision_a.outcomes)))
        self.assertEqual(
            compare_heldout_runs(baseline, revision_a).comparison_sha256,
            compare_heldout_runs(baseline, revision_b).comparison_sha256,
        )

    def test_comparison_has_no_mutation_surface(self):
        comparison=compare_heldout_runs(
            self.run(subject="a"),
            self.run(
                subject="f",
                outcomes=(
                    self.outcome("case:1", subject="f", case_char="1", result="5"),
                    self.outcome("case:2", subject="f", case_char="3", result="6"),
                ),
            ),
        )
        for name in ("promote", "stage", "rollback", "materialize", "execute"):
            self.assertFalse(hasattr(comparison, name))


if __name__ == "__main__":
    unittest.main()
