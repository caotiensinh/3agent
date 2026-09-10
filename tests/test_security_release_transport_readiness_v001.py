import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.release_transport_readiness import (
    ReleaseTransportAssessment,
    ReleaseTransportSnapshot,
)

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
        self.assertEqual(result.validate(), result)

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
        self.assertEqual(result.observed_required_status_checks, tuple(sorted(REQUIRED)))
        self.assertEqual(result.required_checks, tuple(sorted(REQUIRED)))

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
        self.assertFalse(result.ready)

    def test_forged_ready_status_cannot_bypass_unprotected_snapshot(self):
        snapshot = ReleaseTransportSnapshot(
            branch="main",
            branch_protected=False,
            active_ruleset_count=0,
            required_status_checks=(),
            source_ref="github:branches/main",
        )
        valid = ReleaseTransportAssessment.assess(snapshot, required_checks=REQUIRED)
        forged = replace(valid, status="ready", blockers=())
        with self.assertRaisesRegex(MonitoringContractError, "blockers"):
            _ = forged.ready

    def test_forged_authority_is_rejected(self):
        snapshot = ReleaseTransportSnapshot(
            branch="main",
            branch_protected=True,
            active_ruleset_count=1,
            required_status_checks=REQUIRED,
            source_ref="github:ruleset-snapshot:abc123",
        )
        valid = ReleaseTransportAssessment.assess(snapshot, required_checks=REQUIRED)
        with self.assertRaisesRegex(MonitoringContractError, "read_only"):
            replace(valid, authority="mutation").validate()

    def test_forged_assessment_id_is_rejected(self):
        snapshot = ReleaseTransportSnapshot(
            branch="main",
            branch_protected=True,
            active_ruleset_count=1,
            required_status_checks=REQUIRED,
            source_ref="github:ruleset-snapshot:abc123",
        )
        valid = ReleaseTransportAssessment.assess(snapshot, required_checks=REQUIRED)
        with self.assertRaisesRegex(MonitoringContractError, "does not match"):
            replace(valid, assessment_id="release-transport:" + "0" * 24).validate()

    def test_required_check_order_is_canonical(self):
        snapshot = ReleaseTransportSnapshot(
            branch="main",
            branch_protected=True,
            active_ruleset_count=1,
            required_status_checks=("canonical-module-ci", "harness-ci"),
            source_ref="github:ruleset-snapshot:abc123",
        )
        left = ReleaseTransportAssessment.assess(snapshot, required_checks=REQUIRED)
        right = ReleaseTransportAssessment.assess(snapshot, required_checks=tuple(reversed(REQUIRED)))
        self.assertEqual(left.assessment_id, right.assessment_id)


if __name__ == "__main__":
    unittest.main()
