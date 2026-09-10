import unittest

from three_agent.security_monitoring.release_transport_readiness import ReleaseTransportAssessment, ReleaseTransportSnapshot

REQUIRED = ("harness-ci", "canonical-module-ci")


class ReleaseTransportReadinessTests(unittest.TestCase):
    def test_unprotected_main_is_blocked_external(self):
        snapshot = ReleaseTransportSnapshot(
            branch="main",
            branch_protected=False,
            active_ruleset_count=0,
            required_status_checks=(),
            source_ref="github:branches/main",
        )
        result = ReleaseTransportAssessment.assess(snapshot, required_checks=REQUIRED)
        self.assertFalse(result.ready)
        self.assertEqual(result.status, "blocked_external")
        self.assertIn("branch_protection_disabled", result.blockers)
        self.assertIn("no_active_ruleset", result.blockers)
        self.assertIn("missing_required_check:harness-ci", result.blockers)

    def test_protected_branch_with_required_checks_is_ready(self):
        snapshot = ReleaseTransportSnapshot(
            branch="main",
            branch_protected=True,
            active_ruleset_count=1,
            required_status_checks=REQUIRED,
            source_ref="github:ruleset-snapshot:abc123",
        )
        result = ReleaseTransportAssessment.assess(snapshot, required_checks=REQUIRED)
        self.assertTrue(result.ready)
        self.assertEqual(result.blockers, ())

    def test_missing_single_check_is_explicit(self):
        snapshot = ReleaseTransportSnapshot(
            branch="main",
            branch_protected=True,
            active_ruleset_count=1,
            required_status_checks=("harness-ci",),
            source_ref="github:ruleset-snapshot:abc123",
        )
        result = ReleaseTransportAssessment.assess(snapshot, required_checks=REQUIRED)
        self.assertEqual(result.blockers, ("missing_required_check:canonical-module-ci",))


if __name__ == "__main__":
    unittest.main()
