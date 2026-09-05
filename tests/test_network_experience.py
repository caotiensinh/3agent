from __future__ import annotations

import unittest

from three_agent.network_experience import (
    EvidencePattern,
    ExperienceCase,
    NetworkExperienceError,
    SkillCandidate,
)


def evidence(evidence_id: str, role: str = "supporting") -> dict:
    return {
        "evidence_id": evidence_id,
        "role": role,
        "observation": f"observation-{evidence_id}",
        "source_ref": f"events/{evidence_id}",
        "source_sha256": "sha256:" + ("a" * 64),
    }


def base_case() -> dict:
    return {
        "schema_version": "workspace-network-experience-case/v1",
        "case_id": "case-001",
        "dataset_id": "cse-cic-ids2018",
        "incident_class": "service-degradation",
        "symptoms": ["packet loss increased", "service reconnects increased"],
        "evidence": [evidence("e1"), evidence("e2", "discriminator")],
        "candidate_causes": ["physical link degradation", "remote service overload"],
        "confirmed_cause": None,
        "cause_basis": "unknown",
        "remediation": [],
        "outcome": None,
        "confidence": 0.62,
        "provenance_refs": ["prov-001"],
    }


class NetworkExperienceTests(unittest.TestCase):
    def test_case_is_compact_evidence_not_raw_log_storage(self):
        case = ExperienceCase.from_dict(base_case())
        self.assertEqual(len(case.evidence), 2)
        self.assertIsNone(case.confirmed_cause)
        self.assertTrue(case.fingerprint().startswith("sha256:"))

    def test_confirmed_cause_requires_ground_truth_or_operator_verification(self):
        payload = base_case()
        payload["confirmed_cause"] = "physical link degradation"
        payload["cause_basis"] = "unknown"
        with self.assertRaises(NetworkExperienceError):
            ExperienceCase.from_dict(payload)

    def test_unverified_remediation_is_forbidden(self):
        payload = base_case()
        payload["remediation"] = [
            {
                "action": "replace cable",
                "basis": "model_inference",
                "evidence_ids": ["e1"],
            }
        ]
        with self.assertRaises(NetworkExperienceError):
            ExperienceCase.from_dict(payload)

    def test_verified_remediation_must_reference_case_evidence(self):
        payload = base_case()
        payload["remediation"] = [
            {
                "action": "replace cable",
                "basis": "operator_verified",
                "evidence_ids": ["missing"],
            }
        ]
        with self.assertRaises(NetworkExperienceError):
            ExperienceCase.from_dict(payload)

    def test_evidence_pattern_requires_multiple_independent_cases(self):
        payload = {
            "schema_version": "workspace-network-evidence-pattern/v1",
            "pattern_id": "pattern-001",
            "title": "Link degradation pattern",
            "supporting_case_ids": ["case-001"],
            "symptoms": ["packet loss"],
            "evidence_requirements": ["interface errors increase"],
            "discriminators": ["loss remains local to one switch port"],
            "likely_causes": ["physical link degradation"],
            "false_positive_checks": ["verify upstream WAN is healthy"],
        }
        with self.assertRaises(NetworkExperienceError):
            EvidencePattern.from_dict(payload, minimum_independent_cases=2)

    def test_candidate_skill_is_advisory_and_never_auto_promoted(self):
        payload = {
            "schema_version": "workspace-network-skill-candidate/v1",
            "name": "diagnose-link-degradation",
            "description": "Evidence-first procedure for suspected physical-link degradation.",
            "derived_pattern_ids": ["pattern-001"],
            "evidence_requirements": ["interface counters", "packet-loss measurement"],
            "procedure_steps": ["compare local interface errors with end-to-end loss"],
            "stop_conditions": ["insufficient evidence to isolate the failing segment"],
            "authority": "advisory",
            "auto_promotable": False,
        }
        skill = SkillCandidate.from_dict(payload)
        self.assertEqual(skill.authority, "advisory")
        self.assertFalse(skill.auto_promotable)

    def test_candidate_skill_cannot_self_approve(self):
        payload = {
            "schema_version": "workspace-network-skill-candidate/v1",
            "name": "diagnose-link-degradation",
            "description": "Candidate only.",
            "derived_pattern_ids": ["pattern-001"],
            "evidence_requirements": ["interface counters"],
            "procedure_steps": ["inspect evidence"],
            "stop_conditions": ["evidence insufficient"],
            "authority": "advisory",
            "auto_promotable": True,
        }
        with self.assertRaises(NetworkExperienceError):
            SkillCandidate.from_dict(payload)


if __name__ == "__main__":
    unittest.main()
