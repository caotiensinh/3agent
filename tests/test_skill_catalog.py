import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.skill_catalog import ApprovedSkillCatalog
from three_agent.skills import SkillSecurityError


class ApprovedSkillCatalogTests(unittest.TestCase):
    @staticmethod
    def _add_skill(
        root: Path,
        registry: dict,
        *,
        name: str,
        agent_ids: tuple[str, ...] = ("research",),
        enabled: bool = True,
        description: str | None = None,
        body: str | None = None,
        enterprise_tier: str | None = "E2",
        risk_class: str | None = "medium",
        category: str | None = None,
        domain: str | None = None,
        tags: list[str] | None = None,
    ) -> Path:
        skill_dir = root / name
        skill_dir.mkdir()
        description = description or f"Reviewed metadata for {name}."
        body = body or f"Reviewed procedure body for {name}."
        content = (
            "---\n"
            f"name: {name}\n"
            f"description: {description}\n"
            "license: Project-internal\n"
            "---\n\n"
            f"# {name}\n\n"
            f"{body}\n"
        )
        path = skill_dir / "SKILL.md"
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        entry = {
            "enabled": enabled,
            "agent_ids": list(agent_ids),
            "instruction_only": True,
            "network_access": False,
            "credential_access": False,
            "persistent_self_modify": False,
            "external_code_vendored": False,
            "sha256": digest,
            "review": "docs/review.md",
            "provenance": [f"project-owned:test-fixture:{name}"],
        }
        if enterprise_tier is not None:
            entry["enterprise_tier"] = enterprise_tier
        if risk_class is not None:
            entry["risk_class"] = risk_class
        if category is not None:
            entry["category"] = category
        if domain is not None:
            entry["domain"] = domain
        if tags is not None:
            entry["tags"] = tags
        registry["skills"][name] = entry
        return path

    def _fixture(
        self,
        tmp: str,
        *,
        agent_ids: tuple[str, ...] = ("research",),
        enabled: bool = True,
    ) -> tuple[Path, Path]:
        project = Path(tmp) / "project"
        root = project / "skills"
        docs = project / "docs"
        docs.mkdir(parents=True)
        root.mkdir(parents=True)
        (docs / "review.md").write_text("# Reviewed\n", encoding="utf-8")
        registry = {
            "schema_version": 1,
            "policy": "approved-local-instruction-only",
            "skills": {},
        }
        path = self._add_skill(
            root,
            registry,
            name="network-diagnosis",
            agent_ids=agent_ids,
            enabled=enabled,
            description="Diagnose network evidence using reviewed read-only procedures.",
            body="Use only verified evidence and stop when evidence is insufficient.",
            category="diagnostics",
            domain="network",
            tags=["camera", "read-only"],
        )
        (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        return root, path

    def _search_fixture(self, tmp: str) -> Path:
        project = Path(tmp) / "project"
        root = project / "skills"
        docs = project / "docs"
        docs.mkdir(parents=True)
        root.mkdir(parents=True)
        (docs / "review.md").write_text("# Reviewed\n", encoding="utf-8")
        registry = {
            "schema_version": 1,
            "policy": "approved-local-instruction-only",
            "skills": {},
        }
        self._add_skill(
            root,
            registry,
            name="camera-network-evidence",
            description="Correlate camera network evidence without changing device state.",
            body="CAMERA_BODY_SECRET_MARKER must never appear in search metadata.",
            category="diagnostics",
            domain="network",
            risk_class="high",
            tags=["camera", "evidence"],
        )
        self._add_skill(
            root,
            registry,
            name="local-data-quality",
            description="Check local analytical data quality before synthesis.",
            category="analysis",
            domain="analyst",
            risk_class="low",
            tags=["data", "quality"],
        )
        self._add_skill(
            root,
            registry,
            name="presentation-evidence",
            agent_ids=("presentation",),
            description="Prepare evidence-bound presentation structure.",
            category="communication",
            domain="general",
            risk_class="low",
            tags=["slides"],
        )
        self._add_skill(
            root,
            registry,
            name="disabled-network-helper",
            enabled=False,
            description="Disabled network helper must never be searchable.",
            category="diagnostics",
            domain="network",
            risk_class="medium",
            tags=["network"],
        )
        (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        return root

    def test_list_returns_compact_metadata_without_skill_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp)
            rows = ApprovedSkillCatalog(root).list_for_agent("research")
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row.name, "network-diagnosis")
            self.assertIn("Diagnose network evidence", row.description)
            self.assertEqual(row.enterprise_tier, "E2")
            self.assertEqual(row.risk_class, "medium")
            self.assertEqual(row.category, "diagnostics")
            self.assertEqual(row.domain, "network")
            self.assertEqual(row.tags, ("camera", "read-only"))
            self.assertEqual(row.provenance_count, 1)
            self.assertNotIn("Use only verified evidence", json.dumps(row.to_dict()))

    def test_list_omits_skill_not_approved_for_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp, agent_ids=("presentation",))
            self.assertEqual(ApprovedSkillCatalog(root).list_for_agent("research"), ())

    def test_list_omits_disabled_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp, enabled=False)
            self.assertEqual(ApprovedSkillCatalog(root).list_for_agent("research"), ())

    def test_list_fails_closed_when_reviewed_bytes_are_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, path = self._fixture(tmp)
            path.write_text(
                path.read_text(encoding="utf-8") + "UNREVIEWED CHANGE\n",
                encoding="utf-8",
            )
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillCatalog(root).list_for_agent("research")

    def test_view_returns_one_approved_skill_on_demand(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp)
            block = ApprovedSkillCatalog(root).view_for_agent("research", "network-diagnosis")
            self.assertIn("## Approved local skill: network-diagnosis", block)
            self.assertIn("Use only verified evidence", block)

    def test_view_cannot_bypass_agent_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp, agent_ids=("presentation",))
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillCatalog(root).view_for_agent("research", "network-diagnosis")

    def test_search_matches_only_compact_name_description_and_reviewed_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._search_fixture(tmp)
            catalog = ApprovedSkillCatalog(root)

            by_query = catalog.search_for_agent("research", query="camera evidence")
            self.assertEqual([row.name for row in by_query], ["camera-network-evidence"])
            serialized = json.dumps([row.to_dict() for row in by_query], sort_keys=True)
            self.assertNotIn("CAMERA_BODY_SECRET_MARKER", serialized)

            # Procedure-body-only text is intentionally not searchable.
            self.assertEqual(catalog.search_for_agent("research", query="SECRET_MARKER"), ())

    def test_search_supports_exact_structured_filters_and_required_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._search_fixture(tmp)
            rows = ApprovedSkillCatalog(root).search_for_agent(
                "research",
                category="diagnostics",
                domain="NETWORK",
                risk_class="HIGH",
                enterprise_tier="e2",
                tags=("camera", "evidence"),
            )
            self.assertEqual([row.name for row in rows], ["camera-network-evidence"])

            self.assertEqual(
                ApprovedSkillCatalog(root).search_for_agent(
                    "research", domain="network", tags=("missing",)
                ),
                (),
            )

    def test_search_preserves_agent_scope_disabled_filter_and_deterministic_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._search_fixture(tmp)
            catalog = ApprovedSkillCatalog(root)
            rows = catalog.search_for_agent("research", limit=1)
            self.assertEqual([row.name for row in rows], ["camera-network-evidence"])
            all_rows = catalog.search_for_agent("research")
            self.assertEqual(
                [row.name for row in all_rows],
                ["camera-network-evidence", "local-data-quality"],
            )
            self.assertNotIn("presentation-evidence", [row.name for row in all_rows])
            self.assertNotIn("disabled-network-helper", [row.name for row in all_rows])

    def test_search_rejects_unbounded_or_malformed_caller_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._search_fixture(tmp)
            catalog = ApprovedSkillCatalog(root)
            with self.assertRaises(SkillSecurityError):
                catalog.search_for_agent("research", limit=0)
            with self.assertRaises(SkillSecurityError):
                catalog.search_for_agent("research", limit=17)
            with self.assertRaises(SkillSecurityError):
                catalog.search_for_agent("research", query="x" * 241)
            with self.assertRaises(SkillSecurityError):
                catalog.search_for_agent("research", tags="camera")
            with self.assertRaises(SkillSecurityError):
                catalog.search_for_agent("research", tags=("camera", "CAMERA"))

    def test_catalog_fails_closed_on_malformed_optional_registry_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp)
            registry_path = root / "registry.json"
            payload = json.loads(registry_path.read_text(encoding="utf-8"))
            payload["skills"]["network-diagnosis"]["tags"] = "camera"
            registry_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(SkillSecurityError, "tags metadata"):
                ApprovedSkillCatalog(root).search_for_agent("research", query="network")


if __name__ == "__main__":
    unittest.main()
