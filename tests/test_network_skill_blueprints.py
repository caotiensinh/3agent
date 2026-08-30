from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.network_skill_blueprints import (
    NetworkSkillBlueprintError,
    NetworkSkillBlueprintRegistry,
    REQUIRED_SKILLS,
)

ROOT = Path(__file__).resolve().parents[1]


def registry() -> NetworkSkillBlueprintRegistry:
    return NetworkSkillBlueprintRegistry.load(
        blueprint_root=ROOT / "network_skills",
        dataset_registry=ROOT / "config/network-datasets.registry.json",
        supplemental_registry=ROOT / "config/network-experience-supplemental-sources.json",
    )


class NetworkSkillBlueprintTests(unittest.TestCase):
    def test_exact_three_independent_core_skills_exist(self):
        loaded = registry()
        self.assertEqual(set(loaded.blueprints), REQUIRED_SKILLS)
        self.assertEqual(
            REQUIRED_SKILLS,
            {"intrusion-trace-hunting", "log-incident-diagnosis", "host-log-forensics"},
        )

    def test_blueprints_are_advisory_candidates_not_runtime_skills(self):
        loaded = registry()
        for blueprint in loaded.blueprints.values():
            self.assertEqual(blueprint.raw["stage"], "candidate_blueprint")
            self.assertEqual(blueprint.raw["authority"], "advisory")
            self.assertIs(blueprint.raw["auto_promotable"], False)
            self.assertTrue(blueprint.raw["promotion_gate"]["requires_held_out_evaluation"])
            self.assertTrue(blueprint.raw["promotion_gate"]["requires_independent_skill_review"])

    def test_intrusion_hunting_uses_multisource_enterprise_corpora(self):
        skill = registry().blueprints["intrusion-trace-hunting"]
        enterprise = set(skill.source_curriculum["enterprise_approved"])
        self.assertTrue({"lanl-comprehensive", "splunk-bots-v2", "cse-cic-ids2018"} <= enterprise)
        self.assertIn("mitre-attack-stix-data", skill.source_curriculum["authoritative_reference"])

    def test_forensics_license_ambiguous_sources_remain_gated(self):
        loaded = registry()
        skill = loaded.blueprints["host-log-forensics"]
        gated = set(skill.source_curriculum["license_gated_high_value"])
        self.assertEqual(gated, {"otrf-security-datasets", "atomic-evtx"})
        for source in gated:
            self.assertEqual(loaded.supplemental_status[source], "review_required")

    def test_loghub_is_research_only_and_cannot_be_enterprise_source(self):
        loaded = registry()
        skill = loaded.blueprints["log-incident-diagnosis"]
        self.assertIn("loghub-2.0", skill.source_curriculum["research_only"])
        self.assertEqual(loaded.supplemental_status["loghub-2.0"], "research_only")

    def test_each_skill_has_separate_output_and_stop_contract(self):
        loaded = registry()
        outputs = []
        for skill_id in sorted(REQUIRED_SKILLS):
            blueprint = loaded.blueprints[skill_id]
            self.assertGreaterEqual(len(blueprint.required_output), 5)
            self.assertGreaterEqual(len(blueprint.stop_conditions), 2)
            outputs.append(blueprint.required_output)
        self.assertEqual(len({tuple(item) for item in outputs}), 3)

    def test_tampered_auto_promotion_fails_closed(self):
        source = ROOT / "network_skills/intrusion-trace-hunting.json"
        payload = json.loads(source.read_text(encoding="utf-8"))
        payload["auto_promotable"] = True
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for skill_id in REQUIRED_SKILLS:
                original = ROOT / "network_skills" / f"{skill_id}.json"
                data = json.loads(original.read_text(encoding="utf-8"))
                if skill_id == "intrusion-trace-hunting":
                    data = payload
                (tmp / f"{skill_id}.json").write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(NetworkSkillBlueprintError):
                NetworkSkillBlueprintRegistry.load(
                    blueprint_root=tmp,
                    dataset_registry=ROOT / "config/network-datasets.registry.json",
                    supplemental_registry=ROOT / "config/network-experience-supplemental-sources.json",
                )


if __name__ == "__main__":
    unittest.main()
