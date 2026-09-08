import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.skill_applicability_statistics import (
    ApprovedSkillApplicabilityProjector,
    MAX_APPLICABILITY_SKILLS_PER_PROJECTION,
    SkillApplicabilityStatistics,
)
from three_agent.skills import SkillSecurityError


class ApprovedSkillApplicabilityProjectorTests(unittest.TestCase):
    @staticmethod
    def _write_reference(skill_dir: Path, filename: str, content: str) -> tuple[str, int]:
        references = skill_dir / "references"
        references.mkdir(exist_ok=True)
        path = references / filename
        path.write_text(content, encoding="utf-8")
        raw = content.encode("utf-8")
        return hashlib.sha256(raw).hexdigest(), len(raw)

    def _fixture(
        self,
        tmp: str,
        *,
        agent_ids: tuple[str, ...] = ("research",),
        with_references: bool = True,
    ) -> Path:
        project = Path(tmp) / "project"
        root = project / "skills"
        docs = project / "docs"
        docs.mkdir(parents=True)
        root.mkdir(parents=True)
        (docs / "review.md").write_text("# Reviewed\n", encoding="utf-8")

        name = "camera-diagnostics"
        skill_dir = root / name
        skill_dir.mkdir()
        skill_text = (
            "---\n"
            f"name: {name}\n"
            "description: Reviewed camera diagnostics knowledge.\n"
            "license: Project-internal\n"
            "---\n\n"
            "# Camera diagnostics\n\n"
            "Use only reviewed local evidence. SECRET_BODY_MARKER\n"
        )
        (skill_dir / "SKILL.md").write_text(skill_text, encoding="utf-8")

        entry = {
            "enabled": True,
            "agent_ids": list(agent_ids),
            "instruction_only": True,
            "network_access": False,
            "credential_access": False,
            "persistent_self_modify": False,
            "external_code_vendored": False,
            "sha256": hashlib.sha256(skill_text.encode("utf-8")).hexdigest(),
            "review": "docs/review.md",
            "provenance": ["project-owned:test-fixture"],
        }

        if with_references:
            reference_specs = (
                ("generic", "generic.md", "Generic reviewed guidance.\n", None, None),
                ("profile-t", "profile-t.md", "Profile T reviewed guidance.\n", None, "Profile T"),
                ("axis-family", "axis-family.md", "Axis family reviewed guidance.\n", "Axis", None),
                ("axis-v11", "axis-v11.md", "Axis v11 reviewed guidance.\n", "Axis", "11.x"),
            )
            references = {}
            for reference_id, filename, content, vendor, version in reference_specs:
                digest, size = self._write_reference(skill_dir, filename, content)
                meta = {
                    "path": f"references/{filename}",
                    "sha256": digest,
                    "size_bytes": size,
                    "provenance": [f"reviewed:{reference_id}"],
                    "content_class": "vendor-runbook" if vendor else "reviewed-reference",
                }
                if vendor is not None:
                    meta["vendor_family"] = vendor
                if version is not None:
                    meta["version"] = version
                references[reference_id] = meta
            entry["references"] = references

        registry = {
            "schema_version": 1,
            "policy": "approved-local-instruction-only",
            "skills": {name: entry},
        }
        (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        return root

    def test_projects_deterministic_declared_vendor_version_statistics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp)
            projection = ApprovedSkillApplicabilityProjector(root).project_for_agent(
                "research", "camera-diagnostics"
            )

            self.assertEqual(projection.total_references, 4)
            self.assertEqual(projection.vendor_scoped_references, 2)
            self.assertEqual(projection.version_scoped_references, 2)
            self.assertEqual(projection.fully_scoped_references, 1)
            self.assertEqual(projection.unscoped_references, 1)
            self.assertEqual(
                [
                    (row.vendor_family, row.version, row.reference_count)
                    for row in projection.buckets
                ],
                [
                    (None, None, 1),
                    (None, "Profile T", 1),
                    ("Axis", None, 1),
                    ("Axis", "11.x", 1),
                ],
            )
            self.assertTrue(projection.projection_sha256.startswith("sha256:"))
            self.assertEqual(
                projection.to_payload(),
                ApprovedSkillApplicabilityProjector(root)
                .project_for_agent("research", "camera-diagnostics")
                .to_payload(),
            )

    def test_projection_is_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp)
            payload = ApprovedSkillApplicabilityProjector(root).project_for_agent(
                "research", "camera-diagnostics"
            ).to_payload()
            serialized = json.dumps(payload, sort_keys=True)

            self.assertNotIn("SECRET_BODY_MARKER", serialized)
            self.assertNotIn("Generic reviewed guidance", serialized)
            self.assertNotIn("references/", serialized)
            self.assertNotIn("reviewed:axis-v11", serialized)

    def test_wrong_agent_and_tampered_reference_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, agent_ids=("presentation",))
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillApplicabilityProjector(root).project_for_agent(
                    "research", "camera-diagnostics"
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp)
            path = root / "camera-diagnostics" / "references" / "axis-v11.md"
            path.write_text(path.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillApplicabilityProjector(root).project_for_agent(
                    "research", "camera-diagnostics"
                )

    def test_skill_without_references_projects_zero_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, with_references=False)
            projection = ApprovedSkillApplicabilityProjector(root).project_for_agent(
                "research", "camera-diagnostics"
            )
            self.assertEqual(projection.total_references, 0)
            self.assertEqual(projection.buckets, ())
            self.assertEqual(projection.vendor_scoped_references, 0)
            self.assertEqual(projection.version_scoped_references, 0)
            self.assertEqual(projection.fully_scoped_references, 0)
            self.assertEqual(projection.unscoped_references, 0)

    def test_project_many_is_explicit_bounded_deduplicated_and_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp)
            projector = ApprovedSkillApplicabilityProjector(root)
            rows = projector.project_many_for_agent(
                "research", ("camera-diagnostics", "camera-diagnostics")
            )
            self.assertEqual([row.skill_name for row in rows], ["camera-diagnostics"])
            with self.assertRaises(SkillSecurityError):
                projector.project_many_for_agent("research", "camera-diagnostics")
            with self.assertRaises(SkillSecurityError):
                projector.project_many_for_agent(
                    "research",
                    tuple(f"skill-{index}" for index in range(MAX_APPLICABILITY_SKILLS_PER_PROJECTION + 1)),
                )

    def test_projection_validation_rejects_inconsistent_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp)
            projection = ApprovedSkillApplicabilityProjector(root).project_for_agent(
                "research", "camera-diagnostics"
            )
            tampered = SkillApplicabilityStatistics(
                skill_name=projection.skill_name,
                production_sha256=projection.production_sha256,
                total_references=projection.total_references + 1,
                vendor_scoped_references=projection.vendor_scoped_references,
                version_scoped_references=projection.version_scoped_references,
                fully_scoped_references=projection.fully_scoped_references,
                unscoped_references=projection.unscoped_references,
                buckets=projection.buckets,
            )
            with self.assertRaisesRegex(SkillSecurityError, "bucket total mismatch"):
                tampered.validate()

    def test_control_characters_in_applicability_metadata_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp)
            registry_path = root / "registry.json"
            payload = json.loads(registry_path.read_text(encoding="utf-8"))
            payload["skills"]["camera-diagnostics"]["references"]["axis-v11"][
                "vendor_family"
            ] = "Axis\nInjected"
            registry_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(SkillSecurityError, "vendor_family"):
                ApprovedSkillApplicabilityProjector(root).project_for_agent(
                    "research", "camera-diagnostics"
                )


if __name__ == "__main__":
    unittest.main()
