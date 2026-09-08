import hashlib
import json
import unittest

from three_agent.adaptive_learning_heldout_supersession_gate import (
    HeldOutSupersessionGateError,
    HeldOutSupersessionGateProof,
)


def digest(payload):
    raw=json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class FakePackage:
    result="PASS"
    kind="skill"
    item_id="knowledge:skill-1"
    candidate_id="candidate:revision-1"
    candidate_sha256="sha256:" + "c"*64
    candidate_knowledge_sha256="sha256:" + "d"*64
    base_candidate_id="candidate:base-1"
    base_candidate_sha256="sha256:" + "b"*64
    base_knowledge_sha256="sha256:" + "a"*64
    evaluation_sha256="sha256:" + "e"*64
    domain="general"

    def validate(self):
        return self


class HeldOutSupersessionGateTests(unittest.TestCase):
    def production(self):
        data={
            "skill_name":"base-skill",
            "skill_sha256":"sha256:"+"1"*64,
            "registry_entry_sha256":"sha256:"+"2"*64,
            "source_candidate_id":FakePackage.base_candidate_id,
            "source_candidate_sha256":FakePackage.base_candidate_sha256,
            "source_candidate_bound":True,
            "authority":"evaluation_identity_only_no_runtime_or_learning_mutation",
            "schema_version":"workspace-heldout-production-skill-subject/v1",
        }
        return {**data, "subject_sha256":digest(data)}

    def candidate(self):
        data={
            "candidate_id":FakePackage.candidate_id,
            "candidate_sha256":FakePackage.candidate_sha256,
            "candidate_knowledge_sha256":FakePackage.candidate_knowledge_sha256,
            "item_id":FakePackage.item_id,
            "base_knowledge_sha256":FakePackage.base_knowledge_sha256,
            "domain":FakePackage.domain,
            "skill_name":"revision-skill",
            "skill_sha256":"sha256:"+"3"*64,
            "skill_size_bytes":123,
            "revision_evaluation_sha256":FakePackage.evaluation_sha256,
            "authority":"evaluation_identity_only_no_stage_promotion_or_runtime_mutation",
            "schema_version":"workspace-heldout-candidate-skill-subject/v1",
        }
        return {**data, "subject_sha256":digest(data)}

    def comparison(self, production=None, candidate=None):
        production=production or self.production()
        candidate=candidate or self.candidate()
        data={
            "benchmark_id":"benchmark:skill-1",
            "benchmark_sha256":"sha256:"+"4"*64,
            "baseline_run_sha256":"sha256:"+"5"*64,
            "revision_run_sha256":"sha256:"+"6"*64,
            "baseline_subject_sha256":production["subject_sha256"],
            "revision_subject_sha256":candidate["subject_sha256"],
            "total_cases":2,
            "baseline_pass_count":1,
            "revision_pass_count":2,
            "regression_count":0,
            "improvement_count":1,
            "unchanged_pass_count":1,
            "unchanged_fail_count":0,
            "regressed_case_ids":[],
            "improved_case_ids":["case:1"],
            "strict_release_passed":True,
            "reason_codes":[],
            "authority":"evaluation_decision_only_no_stage_promotion_or_runtime_mutation",
            "schema_version":"workspace-heldout-regression-comparison/v1",
        }
        return {**data, "comparison_sha256":digest(data)}

    def proof(self):
        production=self.production()
        candidate=self.candidate()
        return HeldOutSupersessionGateProof.from_proofs(
            package=FakePackage(),
            production_subject=production,
            candidate_subject=candidate,
            comparison=self.comparison(production, candidate),
        )

    def test_exact_proofs_create_deterministic_strict_gate(self):
        first=self.proof()
        second=self.proof()
        self.assertEqual(first.gate_sha256, second.gate_sha256)
        self.assertTrue(first.strict_release_passed)
        self.assertEqual(first.regression_count, 0)
        self.assertEqual(first.revision_pass_count, first.total_cases)

    def test_tampered_production_subject_hash_is_rejected(self):
        production=self.production()
        production["skill_name"]="forged-skill"
        with self.assertRaisesRegex(HeldOutSupersessionGateError, "HELDOUT_GATE_PRODUCTION_PROOF_INVALID"):
            HeldOutSupersessionGateProof.from_proofs(
                package=FakePackage(),
                production_subject=production,
                candidate_subject=self.candidate(),
                comparison=self.comparison(),
            )

    def test_wrong_base_candidate_binding_is_rejected(self):
        production=self.production()
        production["source_candidate_sha256"]="sha256:"+"9"*64
        data=dict(production)
        data.pop("subject_sha256")
        production["subject_sha256"]=digest(data)
        with self.assertRaisesRegex(HeldOutSupersessionGateError, "HELDOUT_GATE_BASE_BINDING_MISMATCH"):
            HeldOutSupersessionGateProof.from_proofs(
                package=FakePackage(),
                production_subject=production,
                candidate_subject=self.candidate(),
                comparison=self.comparison(production, self.candidate()),
            )

    def test_wrong_revision_candidate_binding_is_rejected(self):
        candidate=self.candidate()
        candidate["candidate_sha256"]="sha256:"+"9"*64
        data=dict(candidate)
        data.pop("subject_sha256")
        candidate["subject_sha256"]=digest(data)
        with self.assertRaisesRegex(HeldOutSupersessionGateError, "HELDOUT_GATE_REVISION_BINDING_MISMATCH"):
            HeldOutSupersessionGateProof.from_proofs(
                package=FakePackage(),
                production_subject=self.production(),
                candidate_subject=candidate,
                comparison=self.comparison(self.production(), candidate),
            )

    def test_comparison_must_bind_exact_subjects(self):
        comparison=self.comparison()
        comparison["baseline_subject_sha256"]="sha256:"+"9"*64
        data=dict(comparison)
        data.pop("comparison_sha256")
        comparison["comparison_sha256"]=digest(data)
        with self.assertRaisesRegex(HeldOutSupersessionGateError, "HELDOUT_GATE_COMPARISON_SUBJECT_MISMATCH"):
            HeldOutSupersessionGateProof.from_proofs(
                package=FakePackage(),
                production_subject=self.production(),
                candidate_subject=self.candidate(),
                comparison=comparison,
            )

    def test_regression_cannot_form_release_gate(self):
        comparison=self.comparison()
        comparison.update(
            regression_count=1,
            revision_pass_count=1,
            strict_release_passed=False,
            regressed_case_ids=["case:2"],
            reason_codes=["HELDOUT_REGRESSION_DETECTED", "HELDOUT_REVISION_NOT_ALL_CASES_PASS"],
        )
        data=dict(comparison)
        data.pop("comparison_sha256")
        comparison["comparison_sha256"]=digest(data)
        with self.assertRaisesRegex(HeldOutSupersessionGateError, "HELDOUT_GATE_STRICT_PASS_REQUIRED"):
            HeldOutSupersessionGateProof.from_proofs(
                package=FakePackage(),
                production_subject=self.production(),
                candidate_subject=self.candidate(),
                comparison=comparison,
            )

    def test_unbound_manual_production_skill_is_rejected_for_revision_supersession(self):
        production=self.production()
        production.update(
            source_candidate_id=None,
            source_candidate_sha256=None,
            source_candidate_bound=False,
        )
        data=dict(production)
        data.pop("subject_sha256")
        production["subject_sha256"]=digest(data)
        with self.assertRaisesRegex(HeldOutSupersessionGateError, "HELDOUT_GATE_BASE_CANDIDATE_REQUIRED"):
            HeldOutSupersessionGateProof.from_proofs(
                package=FakePackage(),
                production_subject=production,
                candidate_subject=self.candidate(),
                comparison=self.comparison(production, self.candidate()),
            )

    def test_gate_is_evidence_only_and_has_no_mutation_surface(self):
        proof=self.proof()
        payload=proof.to_payload()
        self.assertIn("gate_sha256", payload)
        for name in ("promote", "stage", "rollback", "materialize", "supersede", "execute"):
            self.assertFalse(hasattr(proof, name))


if __name__ == "__main__":
    unittest.main()
