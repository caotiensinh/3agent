import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.adaptive_learning_production_subject import (
    ProductionSkillEvaluationSubjectError,
    ProductionSkillEvaluationSubjectResolver,
)


class ProductionSkillEvaluationSubjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "skills"
        self.root.mkdir()
        self.name = "demo-skill"
        skill_dir = self.root / self.name
        skill_dir.mkdir()
        self.raw = b"---\nname: demo-skill\ndescription: Demo.\n---\n\n# Demo\n\nSafe procedure.\n"
        (skill_dir / "SKILL.md").write_bytes(self.raw)
        plain = hashlib.sha256(self.raw).hexdigest()
        self.candidate_sha = "sha256:" + "a" * 64
        self.entry = {
            "enabled": True,
            "agent_ids": ["research"],
            "instruction_only": True,
            "network_access": False,
            "credential_access": False,
            "persistent_self_modify": False,
            "external_code_vendored": False,
            "sha256": plain,
            "review": "skills/demo-skill/review.md",
            "provenance": [f"candidate:base-1:{self.candidate_sha}"],
            "references": {},
        }
        self._write()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self):
        (self.root / "registry.json").write_text(
            json.dumps({"schema_version": 1, "policy": "test", "skills": {self.name: self.entry}}),
            encoding="utf-8",
        )

    def _resolve(self, **kwargs):
        with patch(
            "three_agent.adaptive_learning_production_subject.ApprovedSkillLoader.audit_registry",
            return_value=[self.name],
        ):
            return ProductionSkillEvaluationSubjectResolver(self.root).resolve(self.name, **kwargs)

    def test_exact_identity_is_deterministic_and_candidate_bound(self):
        first = self._resolve(expected_candidate_sha256=self.candidate_sha)
        second = self._resolve(expected_candidate_sha256=self.candidate_sha)
        self.assertEqual(first.subject_sha256, second.subject_sha256)
        self.assertTrue(first.source_candidate_bound)
        self.assertEqual(first.source_candidate_sha256, self.candidate_sha)
        self.assertEqual(first.skill_sha256, "sha256:" + hashlib.sha256(self.raw).hexdigest())

    def test_crlf_and_lf_have_same_canonical_skill_identity(self):
        (self.root / self.name / "SKILL.md").write_bytes(self.raw.replace(b"\n", b"\r\n"))
        subject = self._resolve()
        self.assertEqual(subject.skill_sha256, "sha256:" + hashlib.sha256(self.raw).hexdigest())

    def test_tampered_skill_fails_closed(self):
        (self.root / self.name / "SKILL.md").write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(
            ProductionSkillEvaluationSubjectError, "PRODUCTION_SUBJECT_SKILL_SHA_MISMATCH"
        ):
            self._resolve()

    def test_expected_candidate_mismatch_fails_closed(self):
        with self.assertRaisesRegex(
            ProductionSkillEvaluationSubjectError, "PRODUCTION_SUBJECT_EXPECTED_CANDIDATE_MISMATCH"
        ):
            self._resolve(expected_candidate_sha256="sha256:" + "b" * 64)

    def test_ambiguous_candidate_provenance_fails_closed(self):
        self.entry["provenance"].append("candidate:base-2:sha256:" + "b" * 64)
        self._write()
        with self.assertRaisesRegex(
            ProductionSkillEvaluationSubjectError,
            "PRODUCTION_SUBJECT_CANDIDATE_PROVENANCE_AMBIGUOUS",
        ):
            self._resolve()

    def test_builtin_skill_without_candidate_provenance_remains_exactly_identified(self):
        self.entry["provenance"] = ["reviewed:manual"]
        self._write()
        subject = self._resolve()
        self.assertFalse(subject.source_candidate_bound)
        self.assertIsNone(subject.source_candidate_sha256)

    def test_authority_widening_fails_closed(self):
        self.entry["network_access"] = True
        self._write()
        with self.assertRaisesRegex(
            ProductionSkillEvaluationSubjectError, "PRODUCTION_SUBJECT_AUTHORITY_WIDENED"
        ):
            self._resolve()

    def test_canonical_audit_failure_is_not_bypassed(self):
        with patch(
            "three_agent.adaptive_learning_production_subject.ApprovedSkillLoader.audit_registry",
            side_effect=RuntimeError("bad"),
        ):
            with self.assertRaisesRegex(
                ProductionSkillEvaluationSubjectError, "PRODUCTION_SUBJECT_REGISTRY_AUDIT_FAILED"
            ):
                ProductionSkillEvaluationSubjectResolver(self.root).resolve(self.name)

    def test_result_has_no_mutation_surface(self):
        subject = self._resolve()
        for name in ("promote", "stage", "archive", "rollback", "materialize", "execute"):
            self.assertFalse(hasattr(subject, name))


if __name__ == "__main__":
    unittest.main()
